"""Configuración leída de las variables RUVIC_HASHICORP_VAULT_*."""

from __future__ import annotations

import os
from dataclasses import dataclass

ENV_PREFIX = 'RUVIC_HASHICORP_VAULT_'


def _env(name: str, default: str = '') -> str:
    return os.environ.get(f'{ENV_PREFIX}{name}', default).strip()


def _as_bool(value: str) -> bool:
    return value.lower() in {'1', 'true', 'yes', 'on'}


@dataclass(frozen=True)
class VaultConfig:
    """Parámetros de conexión. Los secretos solo viven en estas variables."""

    vault_url: str
    auth_mode: str
    token: str = ''
    role_id: str = ''
    secret_id: str = ''
    approle_mount: str = 'approle'
    namespace: str = ''
    ignore_ssl: bool = False
    kv_mount: str = 'secret'
    kv_version: str = 'v2'
    aws_mount: str = 'aws'
    azure_mount: str = 'azure'
    gcp_mount: str = 'gcp'
    database_mount: str = 'database'
    ssh_mount: str = 'ssh'
    connect_timeout: int = 10

    @classmethod
    def from_env(cls) -> VaultConfig:
        """Construye la config desde el entorno de la instancia activa.

        Raises:
            ValueError: si faltan la URL o las credenciales del modo elegido.
        """
        vault_url = _env('VAULT_URL').rstrip('/')
        auth_mode = _env('AUTH_MODE').lower()
        token = _env('TOKEN')
        role_id = _env('ROLE_ID')
        secret_id = _env('SECRET_ID')
        if not auth_mode:
            if token:
                auth_mode = 'token'
            elif role_id or secret_id:
                auth_mode = 'approle'
        missing: list[str] = []
        if not vault_url:
            missing.append(f'{ENV_PREFIX}VAULT_URL')
        if auth_mode == 'approle':
            if not role_id:
                missing.append(f'{ENV_PREFIX}ROLE_ID')
            if not secret_id:
                missing.append(f'{ENV_PREFIX}SECRET_ID')
        elif auth_mode == 'token':
            if not token:
                missing.append(f'{ENV_PREFIX}TOKEN')
        else:
            missing.append(f'{ENV_PREFIX}AUTH_MODE')
        if missing:
            raise ValueError(
                'Faltan variables de entorno del conector hashicorp_vault: '
                + ', '.join(missing)
                + '. Configura el conector en Settings → Conectores.'
            )
        kv_version = _env('KV_VERSION', 'v2').lower()
        if kv_version not in {'v1', 'v2'}:
            kv_version = 'v2'
        timeout_raw = _env('CONNECT_TIMEOUT', '10') or '10'
        try:
            timeout = max(1, int(timeout_raw))
        except ValueError:
            timeout = 10
        return cls(
            vault_url=vault_url,
            auth_mode=auth_mode,
            token=token,
            role_id=role_id,
            secret_id=secret_id,
            approle_mount=_env('APPROLE_MOUNT', 'approle') or 'approle',
            namespace=_env('NAMESPACE'),
            ignore_ssl=_as_bool(_env('IGNORE_SSL', 'false')),
            kv_mount=_env('KV_MOUNT', 'secret') or 'secret',
            kv_version=kv_version,
            aws_mount=_env('AWS_MOUNT', 'aws') or 'aws',
            azure_mount=_env('AZURE_MOUNT', 'azure') or 'azure',
            gcp_mount=_env('GCP_MOUNT', 'gcp') or 'gcp',
            database_mount=_env('DATABASE_MOUNT', 'database') or 'database',
            ssh_mount=_env('SSH_MOUNT', 'ssh') or 'ssh',
            connect_timeout=timeout,
        )
