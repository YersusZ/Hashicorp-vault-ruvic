"""Conector Ruvic para HashiCorp Vault."""

from .client import VaultClient
from .config import ENV_PREFIX, VaultConfig
from .exceptions import (
    VaultAuthError,
    VaultConnectorError,
    VaultDataError,
    VaultNetworkError,
)
from .logging_utils import setup_logging

__all__ = [
    'ENV_PREFIX',
    'VaultAuthError',
    'VaultClient',
    'VaultConfig',
    'VaultConnectorError',
    'VaultDataError',
    'VaultNetworkError',
    'setup_logging',
]

__version__ = '1.0.0'
