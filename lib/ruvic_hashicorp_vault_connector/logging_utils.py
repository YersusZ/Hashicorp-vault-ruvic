"""Logging del conector. Nada de print() ni de secretos."""

from __future__ import annotations

import logging

_LOGGER_NAME = 'ruvic_hashicorp_vault_connector'


def setup_logging(level: str = 'INFO') -> logging.Logger:
    """Configura y retorna el logger del conector."""
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')
        )
        logger.addHandler(handler)
    logger.setLevel(level.upper())
    return logger


def get_logger() -> logging.Logger:
    return logging.getLogger(_LOGGER_NAME)
