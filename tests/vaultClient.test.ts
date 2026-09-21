import { asObject, fromN8nCredentials } from '../nodes/HashiCorpVault/transport/credentialsMapper';
import { maskSecrets } from '../nodes/HashiCorpVault/transport/mask';
import {
  kvActionPath,
  kvDataPath,
  kvMetadataPath,
  parseVersions,
  sanitizePath,
  VaultApiError,
} from '../nodes/HashiCorpVault/transport/paths';
import type { HttpAdapter, VaultResponse } from '../nodes/HashiCorpVault/transport/types';
import { mapVaultResponse, toVaultApiError, VaultClient } from '../nodes/HashiCorpVault/transport/vaultClient';

describe('sanitizePath', () => {
  it('strips slashes and rejects traversal', () => {
    expect(sanitizePath('/infra/ssh/bastion/')).toBe('infra/ssh/bastion');
    expect(() => sanitizePath('../secret')).toThrow(VaultApiError);
    expect(() => sanitizePath('')).toThrow(VaultApiError);
  });
});

describe('KV path rewrite', () => {
  it('uses data/ for KV v2 and the raw path for v1', () => {
    expect(kvDataPath('secret', 'infra/db', 'v2')).toBe('secret/data/infra/db');
    expect(kvDataPath('secret', 'infra/db', 'v1')).toBe('secret/infra/db');
    expect(kvMetadataPath('kv', 'apps/api')).toBe('kv/metadata/apps/api');
    expect(kvActionPath('secret', 'undelete', 'infra/db')).toBe('secret/undelete/infra/db');
  });
});

describe('parseVersions', () => {
  it('parses comma-separated versions', () => {
    expect(parseVersions('1, 2, x, 3')).toEqual([1, 2, 3]);
    expect(parseVersions([4, 5])).toEqual([4, 5]);
  });
});

describe('maskSecrets', () => {
  it('masks sensitive keys and keeps non-sensitive values', () => {
    const masked = maskSecrets({
      data: {
        username: 'deploy',
        password: 's3cret',
        nested: { api_token: 'abc', region: 'us-east-1' },
      },
      lease_id: 'aws/creds/deploy/1',
    }) as Record<string, unknown>;

    const data = masked.data as Record<string, unknown>;
    const nested = data.nested as Record<string, unknown>;
    expect(data.username).toBe('deploy');
    expect(data.password).toBe('********');
    expect(nested.api_token).toBe('********');
    expect(nested.region).toBe('us-east-1');
    expect(masked.lease_id).toBe('aws/creds/deploy/1');
  });
});

describe('fromN8nCredentials / asObject', () => {
  it('maps n8n credential fields', () => {
    const mapped = fromN8nCredentials({
      vaultUrl: 'https://vault.example:8200/',
      authMethod: 'appRole',
      roleId: 'role',
      secretId: 'secret',
      kvVersion: 'v2',
    });
    expect(mapped.authMethod).toBe('appRole');
    expect(mapped.kvMount).toBe('secret');
    expect(mapped.awsMount).toBe('aws');
  });

  it('parses JSON objects', () => {
    expect(asObject('{"user":"a"}')).toEqual({ user: 'a' });
    expect(asObject({ user: 'a' })).toEqual({ user: 'a' });
  });
});

function mockAdapter(handler: (opts: Parameters<HttpAdapter>[0]) => unknown | Promise<unknown>): {
  adapter: HttpAdapter;
  calls: Array<Parameters<HttpAdapter>[0]>;
} {
  const calls: Array<Parameters<HttpAdapter>[0]> = [];
  const adapter: HttpAdapter = async (opts) => {
    calls.push(opts);
    return handler(opts);
  };
  return { adapter, calls };
}

describe('VaultClient', () => {
  it('logs in with AppRole and does not persist the client token in mapped output', async () => {
    const { adapter, calls } = mockAdapter(async (opts) => {
      if (opts.url.endsWith('/auth/approle/login')) {
        return {
          auth: { client_token: 'hvs.super-secret', accessor: 'acc', lease_duration: 3600 },
        } satisfies VaultResponse;
      }
      if (opts.url.includes('/auth/token/lookup-self')) {
        return { data: { id: 'hvs.super-secret', policies: ['ruvic'] } } satisfies VaultResponse;
      }
      throw new Error(`unexpected ${opts.url}`);
    });

    const client = new VaultClient(
      {
        vaultUrl: 'https://vault.example:8200',
        authMethod: 'appRole',
        roleId: 'role-id',
        secretId: 'secret-id',
      },
      adapter,
    );

    await client.authenticate();
    const lookup = await client.lookupSelf();
    expect(lookup.data).toEqual({ policies: ['ruvic'] });
    expect(JSON.stringify(lookup)).not.toContain('hvs.super-secret');
    expect(calls[0].body).toEqual({ role_id: 'role-id', secret_id: 'secret-id' });
    expect(calls[1].headers?.['X-Vault-Token']).toBe('hvs.super-secret');
  });

  it('rewrites KV v2 reads and unwraps data.data', async () => {
    const { adapter, calls } = mockAdapter(async () => ({
      lease_id: '',
      data: {
        data: { username: 'deploy', password: 'hidden' },
        metadata: { version: 3 },
      },
    }));

    const client = new VaultClient(
      { vaultUrl: 'http://127.0.0.1:8200', authMethod: 'token', token: 'root', kvVersion: 'v2' },
      adapter,
    );
    await client.authenticate();
    const result = await client.kvRead('infra/db', { version: 3 });
    expect(calls[0].url).toBe('http://127.0.0.1:8200/v1/secret/data/infra/db?version=3');
    expect(result.data).toEqual({ username: 'deploy', password: 'hidden' });
    expect(result.metadata).toEqual({ version: 3 });
  });

  it('sends KV v2 patch as merge-patch+json', async () => {
    const { adapter, calls } = mockAdapter(async () => ({
      data: { data: { password: 'new' }, metadata: { version: 4 } },
    }));
    const client = new VaultClient(
      { vaultUrl: 'http://127.0.0.1:8200', authMethod: 'token', token: 'root', kvVersion: 'v2' },
      adapter,
    );
    await client.authenticate();
    await client.kvPatch('infra/db', { password: 'new' });
    expect(calls[0].method).toBe('PATCH');
    expect(calls[0].url).toBe('http://127.0.0.1:8200/v1/secret/data/infra/db');
    expect(calls[0].headers?.['Content-Type']).toBe('application/merge-patch+json');
    expect(calls[0].body).toEqual({ data: { password: 'new' } });
  });

  it('writes KV v1 without the data wrapper', async () => {
    const { adapter, calls } = mockAdapter(async () => ({ data: null }));
    const client = new VaultClient(
      { vaultUrl: 'http://127.0.0.1:8200', authMethod: 'token', token: 'root', kvVersion: 'v1' },
      adapter,
    );
    await client.authenticate();
    await client.kvWrite('infra/db', { password: 'x' });
    expect(calls[0].url).toBe('http://127.0.0.1:8200/v1/secret/infra/db');
    expect(calls[0].body).toEqual({ password: 'x' });
  });

  it('revokes leases with sync=true', async () => {
    const { adapter, calls } = mockAdapter(async () => ({ data: null }));
    const client = new VaultClient(
      { vaultUrl: 'http://127.0.0.1:8200', authMethod: 'token', token: 'root' },
      adapter,
    );
    await client.authenticate();
    await client.leaseRevoke('aws/creds/deploy/abcd');
    expect(calls[0].method).toBe('POST');
    expect(calls[0].url).toBe('http://127.0.0.1:8200/v1/sys/leases/revoke');
    expect(calls[0].body).toEqual({ lease_id: 'aws/creds/deploy/abcd', sync: true });
  });

  it('builds dynamic engine paths for database, ssh, aws, azure and gcp', async () => {
    const { adapter, calls } = mockAdapter(async () => ({
      lease_id: 'db/creds/app/1',
      lease_duration: 3600,
      renewable: true,
      data: { username: 'v-root', password: 'pw' },
    }));
    const client = new VaultClient(
      { vaultUrl: 'http://127.0.0.1:8200', authMethod: 'token', token: 'root' },
      adapter,
    );
    await client.authenticate();
    await client.generateDynamic('database', 'creds/app');
    await client.generateDynamic('database', 'rotate-root/mysql', { method: 'POST' });
    await client.generateDynamic('ssh', 'sign/bastion', { method: 'POST', body: { public_key: 'ssh-ed25519 AAAA' } });
    await client.generateDynamic('aws', 'sts/deploy', { qs: { ttl: '15m' } });
    await client.generateDynamic('azure', 'rotate-root', { method: 'POST' });
    await client.generateDynamic('gcp', 'roleset/ci/token');

    const urls = calls.map((call) => `${call.method} ${call.url}`);
    expect(urls).toEqual([
      'GET http://127.0.0.1:8200/v1/database/creds/app',
      'POST http://127.0.0.1:8200/v1/database/rotate-root/mysql',
      'POST http://127.0.0.1:8200/v1/ssh/sign/bastion',
      'GET http://127.0.0.1:8200/v1/aws/sts/deploy?ttl=15m',
      'POST http://127.0.0.1:8200/v1/azure/rotate-root',
      'GET http://127.0.0.1:8200/v1/gcp/roleset/ci/token',
    ]);
  });

  it('does not put secret material into VaultApiError messages', async () => {
    const adapter: HttpAdapter = async () => {
      throw new VaultApiError('Vault request failed (403)', 403, ['permission denied']);
    };
    const client = new VaultClient(
      { vaultUrl: 'http://127.0.0.1:8200', authMethod: 'token', token: 'hvs.dont-leak' },
      adapter,
    );
    await client.authenticate();
    await expect(client.kvRead('infra/db')).rejects.toMatchObject({
      message: 'Vault request failed (403)',
      errors: ['permission denied'],
    });
  });

  it('maps connection refused to an unreachable error instead of HTTP 500', () => {
    const err = new TypeError('fetch failed');
    (err as Error & { cause: { code: string } }).cause = { code: 'ECONNREFUSED' };
    const mapped = toVaultApiError(err, 'http://127.0.0.1:8200/v1/sys/health');
    expect(mapped.statusCode).toBe(0);
    expect(mapped.message).toContain('Vault is unreachable');
    expect(mapped.message).toContain('docker compose');
  });

  it('strips client_token from auth payloads', () => {
    const mapped = mapVaultResponse({
      auth: { client_token: 'hvs.hidden', accessor: 'acc' },
      data: { ok: true },
    });
    expect(mapped.auth).toEqual({ accessor: 'acc' });
    expect(JSON.stringify(mapped)).not.toContain('hvs.hidden');
  });
});
