export class VaultApiError extends Error {
  constructor(
    message: string,
    public readonly statusCode: number,
    public readonly errors: string[] = [],
  ) {
    super(message);
    this.name = 'VaultApiError';
  }
}

export function sanitizePath(path: string, label = 'path'): string {
  if (typeof path !== 'string' || path.trim() === '') {
    throw new VaultApiError(`Invalid Vault ${label}: empty`, 400);
  }

  const normalized = path
    .replace(/\\/g, '/')
    .replace(/^\/+/, '')
    .replace(/\/+$/, '')
    .replace(/\/{2,}/g, '/');

  const segments = normalized.split('/');
  if (segments.some((segment) => segment === '' || segment === '..')) {
    throw new VaultApiError(`Invalid Vault ${label}`, 400);
  }

  return normalized;
}

export function sanitizeMount(mount: string, fallback: string): string {
  const value = (mount || fallback).trim();
  return sanitizePath(value, 'mount');
}

export function joinPath(...parts: Array<string | undefined>): string {
  return parts
    .filter((part): part is string => Boolean(part && part.length > 0))
    .map((part) => part.replace(/^\/+|\/+$/g, ''))
    .join('/');
}

export function parseVersions(input: string | number[] | undefined): number[] {
  if (Array.isArray(input)) {
    return input.map((value) => Number(value)).filter((value) => Number.isInteger(value) && value > 0);
  }

  if (!input || typeof input !== 'string' || input.trim() === '') {
    return [];
  }

  return input
    .split(',')
    .map((value) => Number(value.trim()))
    .filter((value) => Number.isInteger(value) && value > 0);
}

export function kvDataPath(mount: string, secretPath: string, version: 'v1' | 'v2'): string {
  const safeMount = sanitizeMount(mount, 'secret');
  const safePath = sanitizePath(secretPath);
  if (version === 'v2') {
    return joinPath(safeMount, 'data', safePath);
  }
  return joinPath(safeMount, safePath);
}

export function kvMetadataPath(mount: string, secretPath: string): string {
  return joinPath(sanitizeMount(mount, 'secret'), 'metadata', sanitizePath(secretPath, 'metadata path'));
}

export function kvActionPath(mount: string, action: 'delete' | 'undelete' | 'destroy', secretPath: string): string {
  return joinPath(sanitizeMount(mount, 'secret'), action, sanitizePath(secretPath));
}

export function stripSensitiveAuth(response: Record<string, unknown> | null | undefined): Record<string, unknown> | null {
  if (!response) {
    return null;
  }

  const copy = { ...response };
  delete copy.client_token;
  return copy;
}
