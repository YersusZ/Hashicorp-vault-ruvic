"""Cliente HTTP de HashiCorp Vault.

Las credenciales salen de RUVIC_HASHICORP_VAULT_* (ver config.VaultConfig).
El cliente no guarda secretos en disco ni los escribe en logs.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.request
from typing import Any

from .config import VaultConfig
from .exceptions import VaultAuthError, VaultDataError, VaultNetworkError
from .logging_utils import get_logger
from .paths import join_path, sanitize_mount, sanitize_path

_HEALTH_OK = {200, 429, 472, 473}
_SEALED = {503}
_KV_V2_ONLY = 'Esa operación solo existe en KV v2.'


def _json_body(value: Any) -> Any:
    if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
        return value
    return str(value)


class VaultClient:
    """Cliente de la API HTTP ``/v1`` de Vault.

    Ejemplo:
        >>> client = VaultClient()
        >>> client.authenticate()
        >>> client.kv_read("app/api")
    """

    def __init__(
        self,
        config: VaultConfig | None = None,
        transport: Any | None = None,
    ) -> None:
        self.config = config or VaultConfig.from_env()
        self._token = ''
        self._logger = get_logger()
        self._transport = transport or self._urllib_transport

    def authenticate(self) -> None:
        """Obtiene el token de sesión (token directo o login AppRole)."""
        if self.config.auth_mode == 'token':
            self._token = self.config.token
            return
        mount = sanitize_mount(self.config.approle_mount, 'approle')
        payload = self._raw(
            'POST',
            join_path('auth', mount, 'login'),
            body={'role_id': self.config.role_id, 'secret_id': self.config.secret_id},
            authenticated=False,
        )
        auth = payload.get('auth') if isinstance(payload.get('auth'), dict) else {}
        client_token = auth.get('client_token') if isinstance(auth, dict) else None
        if not isinstance(client_token, str) or not client_token:
            raise VaultAuthError(
                'El login AppRole no devolvió un token. Revisa Role ID, Secret ID y el mount.'
            )
        self._token = client_token
        self._logger.info('Login AppRole correcto en mount %s', mount)

    def health(self) -> dict[str, Any]:
        """Estado del cluster. No exige token."""
        return self._request(
            'GET',
            'sys/health',
            authenticated=False,
            allow_statuses=_HEALTH_OK | _SEALED | {501},
        )

    def lookup_self(self) -> dict[str, Any]:
        """Metadatos del token actual, sin devolver el id del token."""
        self._ensure_token()
        payload = self._request('GET', 'auth/token/lookup-self')
        data = payload.get('data')
        if isinstance(data, dict):
            data.pop('id', None)
            payload['data'] = data
        return payload

    def kv_read(
        self,
        secret_path: str,
        *,
        mount: str | None = None,
        version: int | None = None,
    ) -> dict[str, Any]:
        """Lee un secreto KV. En v2 devuelve ``data`` ya desenvuelto."""
        safe_mount = self._kv_mount(mount)
        path = self._kv_data_path(safe_mount, secret_path)
        query = None
        if self.config.kv_version == 'v2' and version:
            query = {'version': version}
        return self._request('GET', path, query=query, unwrap_kv=True)

    def kv_write(
        self,
        secret_path: str,
        secret_data: dict[str, Any],
        *,
        mount: str | None = None,
        cas: int | None = None,
    ) -> dict[str, Any]:
        """Escribe un secreto. En v2 crea una versión nueva (también sirve para rotar)."""
        safe_mount = self._kv_mount(mount)
        path = self._kv_data_path(safe_mount, secret_path)
        if self.config.kv_version == 'v2':
            body: dict[str, Any] = {'data': secret_data}
            if cas is not None:
                body['options'] = {'cas': cas}
        else:
            body = dict(secret_data)
        return self._request('POST', path, body=body, unwrap_kv=True)

    def kv_list(self, secret_path: str = '', *, mount: str | None = None) -> dict[str, Any]:
        """Lista claves bajo un path (no los valores)."""
        safe_mount = self._kv_mount(mount)
        suffix = sanitize_path(secret_path) if secret_path.strip() else ''
        if self.config.kv_version == 'v2':
            path = join_path(safe_mount, 'metadata', suffix)
        else:
            path = join_path(safe_mount, suffix)
        return self._request('LIST', path)

    def kv_delete(
        self,
        secret_path: str,
        *,
        mount: str | None = None,
        versions: list[int] | None = None,
    ) -> dict[str, Any]:
        """Borra la última versión, o las versiones indicadas en KV v2."""
        safe_mount = self._kv_mount(mount)
        if self.config.kv_version == 'v1' or not versions:
            return self._request('DELETE', self._kv_data_path(safe_mount, secret_path))
        self._require_kv_v2()
        return self._request(
            'POST',
            join_path(safe_mount, 'delete', sanitize_path(secret_path)),
            body={'versions': versions},
        )

    def lease_lookup(self, lease_id: str) -> dict[str, Any]:
        return self._request('PUT', 'sys/leases/lookup', body={'lease_id': lease_id})

    def lease_renew(self, lease_id: str, increment: int | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {'lease_id': lease_id}
        if increment and increment > 0:
            body['increment'] = increment
        return self._request('PUT', 'sys/leases/renew', body=body)

    def lease_revoke(self, lease_id: str) -> dict[str, Any]:
        """Revoca un lease concreto. No usa revoke-force ni revoke-prefix."""
        return self._request(
            'POST',
            'sys/leases/revoke',
            body={'lease_id': lease_id, 'sync': True},
        )

    def generate_dynamic(
        self,
        engine: str,
        api_path: str,
        *,
        method: str = 'GET',
        body: dict[str, Any] | None = None,
        mount: str | None = None,
    ) -> dict[str, Any]:
        """Llama un path relativo de un engine ya montado.

        Ejemplo:
            >>> client.generate_dynamic("database", "creds/readonly")
        """
        mounts = {
            'aws': self.config.aws_mount,
            'azure': self.config.azure_mount,
            'gcp': self.config.gcp_mount,
            'database': self.config.database_mount,
            'ssh': self.config.ssh_mount,
        }
        if engine not in mounts:
            raise VaultDataError(
                f'Engine desconocido: {engine!r}. Usa aws, azure, gcp, database o ssh.'
            )
        safe_mount = sanitize_mount(mount or mounts[engine], mounts[engine])
        path = join_path(safe_mount, sanitize_path(api_path, 'engine path'))
        return self._request(method.upper(), path, body=body)

    def _ensure_token(self) -> None:
        if not self._token:
            self.authenticate()

    def _require_kv_v2(self) -> None:
        if self.config.kv_version != 'v2':
            raise VaultDataError(_KV_V2_ONLY)

    def _kv_mount(self, mount: str | None) -> str:
        return sanitize_mount(mount or self.config.kv_mount, self.config.kv_mount)

    def _kv_data_path(self, mount: str, secret_path: str) -> str:
        safe_path = sanitize_path(secret_path)
        if self.config.kv_version == 'v2':
            return join_path(mount, 'data', safe_path)
        return join_path(mount, safe_path)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        authenticated: bool = True,
        allow_statuses: set[int] | None = None,
        unwrap_kv: bool = False,
    ) -> dict[str, Any]:
        payload = self._raw(
            method,
            path,
            body=body,
            query=query,
            authenticated=authenticated,
            allow_statuses=allow_statuses,
        )
        return self._map(payload, unwrap_kv=unwrap_kv and self.config.kv_version == 'v2')

    def _raw(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
        authenticated: bool = True,
        allow_statuses: set[int] | None = None,
    ) -> dict[str, Any]:
        if authenticated:
            self._ensure_token()
        api_method = 'GET' if method == 'LIST' else method
        params = dict(query or {})
        if method == 'LIST':
            params['list'] = 'true'
        return self._transport(
            api_method,
            path,
            params,
            body,
            authenticated,
            allow_statuses or {200},
        )

    def _map(self, payload: dict[str, Any], *, unwrap_kv: bool) -> dict[str, Any]:
        mapped: dict[str, Any] = {
            'request_id': payload.get('request_id'),
            'lease_id': payload.get('lease_id'),
            'lease_duration': payload.get('lease_duration'),
            'renewable': payload.get('renewable'),
            'warnings': payload.get('warnings'),
        }
        data = payload.get('data')
        if unwrap_kv and isinstance(data, dict) and 'data' in data:
            mapped['data'] = _json_body(data.get('data'))
            mapped['metadata'] = _json_body(data.get('metadata'))
        else:
            mapped['data'] = _json_body(data)
        auth = payload.get('auth')
        if isinstance(auth, dict):
            public = dict(auth)
            public.pop('client_token', None)
            mapped['auth'] = public
        return mapped

    def _urllib_transport(
        self,
        method: str,
        path: str,
        query: dict[str, Any],
        body: dict[str, Any] | None,
        authenticated: bool,
        allow_statuses: set[int],
    ) -> dict[str, Any]:
        from urllib.parse import urlencode

        url = f'{self.config.vault_url}/v1/{path.lstrip("/")}'
        if query:
            url = f'{url}?{urlencode({key: value for key, value in query.items() if value is not None})}'
        headers = {'Accept': 'application/json'}
        data = None
        if body is not None:
            headers['Content-Type'] = 'application/json'
            data = json.dumps(body).encode('utf-8')
        if authenticated and self._token:
            headers['X-Vault-Token'] = self._token
        if self.config.namespace:
            headers['X-Vault-Namespace'] = self.config.namespace
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        context = None
        if self.config.ignore_ssl:
            context = ssl._create_unverified_context()
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.config.connect_timeout,
                context=context,
            ) as response:
                status = response.status
                raw = response.read().decode('utf-8')
        except urllib.error.HTTPError as exc:
            status = exc.code
            raw = exc.read().decode('utf-8', errors='replace')
            if status not in allow_statuses:
                self._raise_http(status, raw)
        except urllib.error.URLError as exc:
            raise VaultNetworkError(
                f'No se pudo alcanzar {self.config.vault_url} '
                f'(timeout {self.config.connect_timeout}s). Revisa URL, puerto y red.'
            ) from exc
        except TimeoutError as exc:
            raise VaultNetworkError(
                f'Vault no respondió en {self.config.connect_timeout}s.'
            ) from exc
        if status in _SEALED:
            raise VaultDataError('Vault está sellado. Hay que hacer unseal antes de usarlo.')
        if status == 501:
            raise VaultDataError('Vault no está inicializado.')
        if not raw:
            return {}
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise VaultDataError('Vault respondió un cuerpo que no es JSON.') from exc
        if not isinstance(parsed, dict):
            return {'data': parsed}
        return parsed

    def _raise_http(self, status: int, raw: str) -> None:
        errors: list[str] = []
        try:
            parsed = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            parsed = {}
        if isinstance(parsed, dict) and isinstance(parsed.get('errors'), list):
            errors = [str(item) for item in parsed['errors'] if item]
        detail = '; '.join(errors) if errors else f'HTTP {status}'
        if status in {401, 403}:
            raise VaultAuthError(
                f'Vault rechazó la autenticación ({status}). Revisa el token o el AppRole. {detail}'
            )
        if status in {400, 404}:
            raise VaultDataError(f'Vault no aceptó la operación ({status}): {detail}')
        raise VaultNetworkError(f'Error de Vault ({status}): {detail}')
