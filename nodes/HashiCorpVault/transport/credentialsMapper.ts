import type { ICredentialDataDecryptedObject } from 'n8n-workflow';
import type { VaultCredentials } from './types';

export function fromN8nCredentials(raw: ICredentialDataDecryptedObject | Record<string, unknown>): VaultCredentials {
  return {
    vaultUrl: String(raw.vaultUrl || '').trim(),
    authMethod: raw.authMethod === 'token' ? 'token' : 'appRole',
    roleId: raw.roleId ? String(raw.roleId) : undefined,
    secretId: raw.secretId ? String(raw.secretId) : undefined,
    token: raw.token ? String(raw.token) : undefined,
    namespace: raw.namespace ? String(raw.namespace) : undefined,
    ignoreSsl: Boolean(raw.ignoreSsl),
    appRoleMount: raw.appRoleMount ? String(raw.appRoleMount) : 'approle',
    kvMount: raw.kvMount ? String(raw.kvMount) : 'secret',
    kvVersion: raw.kvVersion === 'v1' ? 'v1' : 'v2',
    awsMount: raw.awsMount ? String(raw.awsMount) : 'aws',
    azureMount: raw.azureMount ? String(raw.azureMount) : 'azure',
    gcpMount: raw.gcpMount ? String(raw.gcpMount) : 'gcp',
    databaseMount: raw.databaseMount ? String(raw.databaseMount) : 'database',
    sshMount: raw.sshMount ? String(raw.sshMount) : 'ssh',
  };
}

export function asObject(value: unknown): Record<string, unknown> {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  if (typeof value === 'string' && value.trim()) {
    const parsed = JSON.parse(value) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
  }
  throw new Error('Expected a JSON object');
}
