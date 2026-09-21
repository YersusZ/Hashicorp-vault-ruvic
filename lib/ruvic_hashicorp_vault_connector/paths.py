"""Normalización de paths de la API de Vault. Rechaza '..' y segmentos vacíos."""

from __future__ import annotations

from .exceptions import VaultDataError


def sanitize_path(path: str, label: str = 'path') -> str:
    if not isinstance(path, str) or not path.strip():
        raise VaultDataError(f'Ruta de Vault inválida ({label}): vacía.')
    normalized = path.replace('\\', '/').strip('/')
    while '//' in normalized:
        normalized = normalized.replace('//', '/')
    segments = normalized.split('/')
    if any(segment in ('', '..') for segment in segments):
        raise VaultDataError(f'Ruta de Vault inválida ({label}).')
    return normalized


def sanitize_mount(mount: str, fallback: str) -> str:
    value = (mount or fallback).strip()
    return sanitize_path(value or fallback, 'mount')


def join_path(*parts: str) -> str:
    cleaned = [part.strip('/') for part in parts if part and part.strip('/')]
    return '/'.join(cleaned)
