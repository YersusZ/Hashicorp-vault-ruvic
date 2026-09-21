import { VaultApiError, joinPath, kvActionPath, kvDataPath, kvMetadataPath, sanitizeMount, sanitizePath, stripSensitiveAuth } from './paths';
import type { ExecutionJson, HttpAdapter, HttpMethod, HttpRequestOpts, VaultCredentials, VaultResponse } from './types';

function trimBaseUrl(url: string): string {
  return url.replace(/\/+$/, '');
}

function toQuery(qs?: HttpRequestOpts['qs']): string {
  if (!qs) {
    return '';
  }

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(qs)) {
    if (value === undefined || value === '') {
      continue;
    }
    params.set(key, String(value));
  }
  const encoded = params.toString();
  return encoded ? `?${encoded}` : '';
}

export function mapVaultResponse(response: VaultResponse, unwrapKvV2 = false): ExecutionJson {
  const payload: ExecutionJson = {
    request_id: response.request_id,
    lease_id: response.lease_id,
    lease_duration: response.lease_duration,
    renewable: response.renewable,
    warnings: response.warnings ?? null,
  };

  if (unwrapKvV2 && response.data && typeof response.data === 'object' && 'data' in response.data) {
    const kv = response.data as { data?: Record<string, unknown> | null; metadata?: Record<string, unknown> | null };
    payload.data = kv.data ?? null;
    payload.metadata = kv.metadata ?? null;
  } else {
    payload.data = response.data ?? null;
  }

  if (response.auth) {
    payload.auth = stripSensitiveAuth(response.auth as Record<string, unknown>);
  }

  return payload;
}

export class VaultClient {
  private token?: string;

  constructor(
    private readonly creds: VaultCredentials,
    private readonly http: HttpAdapter,
  ) {}

  get kvMount(): string {
    return sanitizeMount(this.creds.kvMount || 'secret', 'secret');
  }

  get kvVersion(): 'v1' | 'v2' {
    return this.creds.kvVersion === 'v1' ? 'v1' : 'v2';
  }

  mount(kind: 'aws' | 'azure' | 'gcp' | 'database' | 'ssh', override?: string): string {
    const defaults = {
      aws: this.creds.awsMount || 'aws',
      azure: this.creds.azureMount || 'azure',
      gcp: this.creds.gcpMount || 'gcp',
      database: this.creds.databaseMount || 'database',
      ssh: this.creds.sshMount || 'ssh',
    };
    return sanitizeMount(override || defaults[kind], defaults[kind]);
  }

  async authenticate(): Promise<void> {
    if (this.creds.authMethod === 'token') {
      if (!this.creds.token) {
        throw new VaultApiError('Vault token is required', 400);
      }
      this.token = this.creds.token;
      return;
    }

    const mount = sanitizeMount(this.creds.appRoleMount || 'approle', 'approle');
    if (!this.creds.roleId || !this.creds.secretId) {
      throw new VaultApiError('AppRole Role ID and Secret ID are required', 400);
    }

    const response = await this.request('POST', joinPath('auth', mount, 'login'), {
      body: {
        role_id: this.creds.roleId,
        secret_id: this.creds.secretId,
      },
      authenticated: false,
    });

    const clientToken = response.auth?.client_token;
    if (!clientToken) {
      throw new VaultApiError('AppRole login did not return a client token', 401);
    }
    this.token = clientToken;
  }

  async health(): Promise<ExecutionJson> {
    const response = await this.request('GET', 'sys/health', {
      authenticated: false,
      allowStatuses: [200, 429, 472, 473, 501, 503],
    });
    return mapVaultResponse(response);
  }

  async lookupSelf(): Promise<ExecutionJson> {
    const response = await this.request('GET', 'auth/token/lookup-self');
    const mapped = mapVaultResponse(response);
    if (mapped.data) {
      const data = { ...mapped.data };
      delete data.id;
      mapped.data = data;
    }
    return mapped;
  }

  async kvRead(secretPath: string, options: { mount?: string; version?: number } = {}): Promise<ExecutionJson> {
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const path = kvDataPath(mount, secretPath, this.kvVersion);
    const qs = this.kvVersion === 'v2' && options.version ? { version: options.version } : undefined;
    const response = await this.request('GET', path, { qs });
    return mapVaultResponse(response, this.kvVersion === 'v2');
  }

  async kvWrite(
    secretPath: string,
    secretData: Record<string, unknown>,
    options: { mount?: string; cas?: number } = {},
  ): Promise<ExecutionJson> {
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const path = kvDataPath(mount, secretPath, this.kvVersion);
    const body =
      this.kvVersion === 'v2'
        ? {
            data: secretData,
            ...(options.cas === undefined ? {} : { options: { cas: options.cas } }),
          }
        : secretData;
    const response = await this.request('POST', path, { body });
    return mapVaultResponse(response, this.kvVersion === 'v2');
  }

  async kvPatch(
    secretPath: string,
    secretData: Record<string, unknown>,
    options: { mount?: string; cas?: number } = {},
  ): Promise<ExecutionJson> {
    if (this.kvVersion !== 'v2') {
      throw new VaultApiError('Patch is only supported on KV v2', 400);
    }
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const path = kvDataPath(mount, secretPath, 'v2');
    const body = {
      data: secretData,
      ...(options.cas === undefined ? {} : { options: { cas: options.cas } }),
    };
    const response = await this.request('PATCH', path, {
      body,
      headers: { 'Content-Type': 'application/merge-patch+json' },
    });
    return mapVaultResponse(response, true);
  }

  getClientToken(): string {
    if (!this.token) {
      throw new VaultApiError('Not authenticated to Vault', 401);
    }
    return this.token;
  }

  async kvList(secretPath: string, options: { mount?: string } = {}): Promise<ExecutionJson> {
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const suffix = secretPath && secretPath.trim() !== '' ? sanitizePath(secretPath) : '';
    const path = this.kvVersion === 'v2' ? joinPath(mount, 'metadata', suffix) : joinPath(mount, suffix);
    const response = await this.request('LIST', path);
    return mapVaultResponse(response);
  }

  async kvDelete(
    secretPath: string,
    options: { mount?: string; versions?: number[] } = {},
  ): Promise<ExecutionJson> {
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    if (this.kvVersion === 'v1' || !options.versions?.length) {
      const path = kvDataPath(mount, secretPath, this.kvVersion);
      const response = await this.request('DELETE', path);
      return mapVaultResponse(response, this.kvVersion === 'v2');
    }
    const response = await this.request('POST', kvActionPath(mount, 'delete', secretPath), {
      body: { versions: options.versions },
    });
    return mapVaultResponse(response);
  }

  async kvUndelete(secretPath: string, versions: number[], options: { mount?: string } = {}): Promise<ExecutionJson> {
    if (this.kvVersion !== 'v2') {
      throw new VaultApiError('Undelete is only supported on KV v2', 400);
    }
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const response = await this.request('POST', kvActionPath(mount, 'undelete', secretPath), {
      body: { versions },
    });
    return mapVaultResponse(response);
  }

  async kvDestroy(secretPath: string, versions: number[], options: { mount?: string } = {}): Promise<ExecutionJson> {
    if (this.kvVersion !== 'v2') {
      throw new VaultApiError('Destroy is only supported on KV v2', 400);
    }
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const response = await this.request('PUT', kvActionPath(mount, 'destroy', secretPath), {
      body: { versions },
    });
    return mapVaultResponse(response);
  }

  async kvGetMetadata(secretPath: string, options: { mount?: string } = {}): Promise<ExecutionJson> {
    if (this.kvVersion !== 'v2') {
      throw new VaultApiError('Metadata is only supported on KV v2', 400);
    }
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const response = await this.request('GET', kvMetadataPath(mount, secretPath));
    return mapVaultResponse(response);
  }

  async kvUpdateMetadata(
    secretPath: string,
    metadata: Record<string, unknown>,
    options: { mount?: string } = {},
  ): Promise<ExecutionJson> {
    if (this.kvVersion !== 'v2') {
      throw new VaultApiError('Metadata is only supported on KV v2', 400);
    }
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const response = await this.request('POST', kvMetadataPath(mount, secretPath), { body: metadata });
    return mapVaultResponse(response);
  }

  async kvDeleteMetadata(secretPath: string, options: { mount?: string } = {}): Promise<ExecutionJson> {
    if (this.kvVersion !== 'v2') {
      throw new VaultApiError('Metadata is only supported on KV v2', 400);
    }
    const mount = sanitizeMount(options.mount || this.kvMount, this.kvMount);
    const response = await this.request('DELETE', kvMetadataPath(mount, secretPath));
    return mapVaultResponse(response);
  }

  async kvRotate(
    secretPath: string,
    secretData: Record<string, unknown>,
    options: { mount?: string; cas?: number } = {},
  ): Promise<ExecutionJson> {
    return this.kvWrite(secretPath, secretData, options);
  }

  async leaseLookup(leaseId: string): Promise<ExecutionJson> {
    const response = await this.request('PUT', 'sys/leases/lookup', { body: { lease_id: leaseId } });
    return mapVaultResponse(response);
  }

  async leaseRenew(leaseId: string, increment?: number): Promise<ExecutionJson> {
    const body: Record<string, unknown> = { lease_id: leaseId };
    if (increment && increment > 0) {
      body.increment = increment;
    }
    const response = await this.request('PUT', 'sys/leases/renew', { body });
    return mapVaultResponse(response);
  }

  async leaseRevoke(leaseId: string): Promise<ExecutionJson> {
    const response = await this.request('POST', 'sys/leases/revoke', {
      body: { lease_id: leaseId, sync: true },
    });
    return mapVaultResponse(response);
  }

  async generateDynamic(
    engine: 'aws' | 'azure' | 'gcp' | 'database' | 'ssh',
    apiPath: string,
    options: {
      mount?: string;
      method?: HttpMethod;
      qs?: HttpRequestOpts['qs'];
      body?: Record<string, unknown>;
    } = {},
  ): Promise<ExecutionJson> {
    const mount = this.mount(engine, options.mount);
    const path = joinPath(mount, sanitizePath(apiPath, 'engine path'));
    const response = await this.request(options.method || 'GET', path, {
      qs: options.qs,
      body: options.body,
    });
    return mapVaultResponse(response);
  }

  async request(
    method: HttpMethod | 'LIST',
    path: string,
    options: {
      body?: unknown;
      qs?: HttpRequestOpts['qs'];
      headers?: Record<string, string>;
      authenticated?: boolean;
      allowStatuses?: number[];
    } = {},
  ): Promise<VaultResponse> {
    const authenticated = options.authenticated !== false;
    if (authenticated && !this.token) {
      throw new VaultApiError('Not authenticated to Vault', 401);
    }

    const apiMethod: HttpMethod = method === 'LIST' ? 'GET' : method;
    const qs = method === 'LIST' ? { ...(options.qs || {}), list: true } : options.qs;
    const url = `${trimBaseUrl(this.creds.vaultUrl)}/v1/${path.replace(/^\/+/, '')}${toQuery(qs)}`;

    const headers: Record<string, string> = {
      Accept: 'application/json',
      ...(options.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(options.headers || {}),
    };

    if (this.token && authenticated) {
      headers['X-Vault-Token'] = this.token;
    }
    if (this.creds.namespace) {
      headers['X-Vault-Namespace'] = this.creds.namespace;
    }

    try {
      const raw = await this.http({
        method: apiMethod,
        url,
        headers,
        body: options.body,
        qs,
        skipSslCertificateValidation: Boolean(this.creds.ignoreSsl),
        allowStatuses: options.allowStatuses,
      });
      return (raw || {}) as VaultResponse;
    } catch (error) {
      throw toVaultApiError(error, url);
    }
  }
}

function isUnreachableError(error: unknown): boolean {
  const err = error as { message?: string; cause?: { code?: string; message?: string } };
  const haystack = `${err.message || ''} ${err.cause?.code || ''} ${err.cause?.message || ''}`.toLowerCase();
  return (
    haystack.includes('fetch failed') ||
    haystack.includes('econnrefused') ||
    haystack.includes('enotfound') ||
    haystack.includes('econnreset') ||
    haystack.includes('network')
  );
}

export function toVaultApiError(error: unknown, url?: string): VaultApiError {
  if (error instanceof VaultApiError) {
    return error;
  }

  if (isUnreachableError(error)) {
    const target = url ? ` at ${url}` : '';
    return new VaultApiError(
      `Vault is unreachable${target}. Start Docker Desktop, then: docker compose -f docker-compose.vault.yml up -d`,
      0,
    );
  }

  const err = error as {
    statusCode?: number;
    status?: number;
    message?: string;
    response?: { status?: number; body?: VaultResponse; data?: VaultResponse };
    body?: VaultResponse;
  };

  const status = err.statusCode || err.status || err.response?.status || 500;
  const payload = err.response?.body || err.response?.data || err.body;
  const errors = Array.isArray(payload?.errors) ? payload.errors : [];
  const safeMessage = errors.length ? `Vault API error (${status})` : `Vault request failed (${status})`;
  return new VaultApiError(safeMessage, status, errors);
}

export function createFetchAdapter(): HttpAdapter {
  return async (opts) => {
    const headers = { ...(opts.headers || {}) };
    const init: RequestInit = {
      method: opts.method,
      headers,
    };

    if (opts.body !== undefined && opts.method !== 'GET') {
      init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
    }

    let response: Response;
    try {
      response = await fetch(opts.url, init);
    } catch (error) {
      throw toVaultApiError(error, opts.url);
    }

    const text = await response.text();
    let parsed: unknown = {};
    if (text) {
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = { data: { raw: text } };
      }
    }

    const allowed = new Set(opts.allowStatuses || []);
    if (!response.ok && !allowed.has(response.status)) {
      const payload = parsed as VaultResponse;
      throw new VaultApiError(
        `Vault request failed (${response.status})`,
        response.status,
        Array.isArray(payload.errors) ? payload.errors : [],
      );
    }

    return parsed;
  };
}
