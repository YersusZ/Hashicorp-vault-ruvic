"""Excepciones del conector HashiCorp Vault."""


class VaultConnectorError(Exception):
    """Error base del conector."""


class VaultAuthError(VaultConnectorError):
    """Token o AppRole inválidos, o permisos insuficientes."""


class VaultNetworkError(VaultConnectorError):
    """No se pudo alcanzar el cluster (URL, TLS o timeout)."""


class VaultDataError(VaultConnectorError):
    """La petición es válida pero el path, el mount o el body no lo son."""
