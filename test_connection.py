"""Prueba de conexión estándar del conector hashicorp_vault.

Firma Ruvic: def test_connection() -> tuple[bool, str]
Lee solo las variables RUVIC_HASHICORP_VAULT_*. Nunca lanza excepciones.
"""

from __future__ import annotations


def test_connection() -> tuple[bool, str]:
    """Comprueba que Vault responde y que el token o AppRole autentican."""
    try:
        from ruvic_hashicorp_vault_connector import (
            VaultAuthError,
            VaultClient,
            VaultDataError,
            VaultNetworkError,
        )
    except ImportError:
        return (
            False,
            'La librería ruvic-hashicorp-vault-connector no está instalada. '
            'Instala con: pip install git+https://github.com/YersusZ/'
            'Hashicorp-vault-ruvic.git#subdirectory=lib',
        )

    try:
        client = VaultClient()
    except ValueError as exc:
        return False, str(exc)

    try:
        client.health()
        client.authenticate()
        client.lookup_self()
    except VaultAuthError as exc:
        return False, f'Autenticación fallida: {exc}'
    except VaultNetworkError as exc:
        return False, f'Error de red: {exc}'
    except VaultDataError as exc:
        return False, f'Error de datos: {exc}'
    except Exception as exc:
        return False, f'Error inesperado: {exc}'

    return True, f'Conexión exitosa a {client.config.vault_url}'


if __name__ == '__main__':
    ok, message = test_connection()
    print(f"{'OK' if ok else 'FALLO'}: {message}")
    raise SystemExit(0 if ok else 1)
