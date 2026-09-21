export type AuthMethod = 'appRole' | 'token';
export type KvVersion = 'v1' | 'v2';
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

export interface VaultCredentials {
  vaultUrl: string;
  authMethod: AuthMethod;
  roleId?: string;
  secretId?: string;
  token?: string;
  namespace?: string;
  ignoreSsl?: boolean;
  appRoleMount?: string;
  kvMount?: string;
  kvVersion?: KvVersion;
  awsMount?: string;
  azureMount?: string;
  gcpMount?: string;
  databaseMount?: string;
  sshMount?: string;
}

export interface HttpRequestOpts {
  method: HttpMethod | 'LIST';
  url: string;
  headers?: Record<string, string>;
  body?: unknown;
  qs?: Record<string, string | number | boolean | undefined>;
  skipSslCertificateValidation?: boolean;
  allowStatuses?: number[];
}

export type HttpAdapter = (opts: HttpRequestOpts) => Promise<unknown>;

export interface VaultAuthPayload {
  client_token?: string;
  accessor?: string;
  lease_duration?: number;
  renewable?: boolean;
  [key: string]: unknown;
}

export interface VaultResponse {
  request_id?: string;
  lease_id?: string;
  renewable?: boolean;
  lease_duration?: number;
  data?: Record<string, unknown> | null;
  wrap_info?: unknown;
  warnings?: string[] | null;
  auth?: VaultAuthPayload | null;
  errors?: string[];
  [key: string]: unknown;
}

export interface ExecutionJson {
  lease_id?: string;
  lease_duration?: number;
  renewable?: boolean;
  request_id?: string;
  data?: Record<string, unknown> | null;
  metadata?: Record<string, unknown> | null;
  auth?: Record<string, unknown> | null;
  warnings?: string[] | null;
  [key: string]: unknown;
}
