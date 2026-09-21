import type {
  ICredentialDataDecryptedObject,
  ICredentialTestRequest,
  ICredentialType,
  IHttpRequestOptions,
  INodeProperties,
} from 'n8n-workflow';
import { fromN8nCredentials } from '../nodes/HashiCorpVault/transport/credentialsMapper';
import { createFetchAdapter, VaultClient } from '../nodes/HashiCorpVault/transport/vaultClient';

export class HashiCorpVaultApi implements ICredentialType {
  name = 'hashiCorpVaultApi';
  displayName = 'HashiCorp Vault API';
  icon = 'file:../nodes/HashiCorpVault/hashicorp.svg' as const;
  documentationUrl = 'https://developer.hashicorp.com/vault/docs/auth/approle';

  properties: INodeProperties[] = [
    {
      displayName: 'Vault URL',
      name: 'vaultUrl',
      type: 'string',
      default: 'https://vault.example.com:8200',
      placeholder: 'https://vault.example.com:8200',
      required: true,
      description: 'Base URL of the Vault cluster, including protocol and port',
    },
    {
      displayName: 'Authentication Method',
      name: 'authMethod',
      type: 'options',
      options: [
        {
          name: 'AppRole',
          value: 'appRole',
          description: 'Machine authentication with Role ID and Secret ID (recommended)',
        },
        {
          name: 'Token',
          value: 'token',
          description: 'Vault token. Prefer periodic/orphan tokens over root tokens',
        },
      ],
      default: 'appRole',
    },
    {
      displayName: 'Role ID',
      name: 'roleId',
      type: 'string',
      default: '',
      required: true,
      displayOptions: { show: { authMethod: ['appRole'] } },
    },
    {
      displayName: 'Secret ID',
      name: 'secretId',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      required: true,
      displayOptions: { show: { authMethod: ['appRole'] } },
    },
    {
      displayName: 'AppRole Mount',
      name: 'appRoleMount',
      type: 'string',
      default: 'approle',
      displayOptions: { show: { authMethod: ['appRole'] } },
      description: 'Auth mount path for AppRole (usually approle)',
    },
    {
      displayName: 'Token',
      name: 'token',
      type: 'string',
      typeOptions: { password: true },
      default: '',
      required: true,
      displayOptions: { show: { authMethod: ['token'] } },
    },
    {
      displayName: 'Namespace',
      name: 'namespace',
      type: 'string',
      default: '',
      description: 'Vault Enterprise namespace. Leave empty for the root namespace',
    },
    {
      displayName: 'KV Mount',
      name: 'kvMount',
      type: 'string',
      default: 'secret',
    },
    {
      displayName: 'KV Version',
      name: 'kvVersion',
      type: 'options',
      options: [
        { name: 'v2', value: 'v2' },
        { name: 'v1', value: 'v1' },
      ],
      default: 'v2',
    },
    {
      displayName: 'AWS Mount',
      name: 'awsMount',
      type: 'string',
      default: 'aws',
    },
    {
      displayName: 'Azure Mount',
      name: 'azureMount',
      type: 'string',
      default: 'azure',
    },
    {
      displayName: 'GCP Mount',
      name: 'gcpMount',
      type: 'string',
      default: 'gcp',
    },
    {
      displayName: 'Database Mount',
      name: 'databaseMount',
      type: 'string',
      default: 'database',
    },
    {
      displayName: 'SSH Mount',
      name: 'sshMount',
      type: 'string',
      default: 'ssh',
    },
    {
      displayName: 'Ignore SSL Issues',
      name: 'ignoreSsl',
      type: 'boolean',
      default: false,
      description: 'Skip TLS certificate validation. Use only in isolated labs',
    },
  ];

  authenticate = async function (
    this: { helpers?: { httpRequest: (opts: IHttpRequestOptions) => Promise<unknown> } },
    credentials: ICredentialDataDecryptedObject,
    requestOptions: IHttpRequestOptions,
  ): Promise<IHttpRequestOptions> {
    const mapped = fromN8nCredentials(credentials);
    const adapter = async (opts: {
      method: string;
      url: string;
      headers?: Record<string, string>;
      body?: unknown;
      skipSslCertificateValidation?: boolean;
    }) => {
      if (this.helpers?.httpRequest) {
        return this.helpers.httpRequest({
          method: opts.method as IHttpRequestOptions['method'],
          url: opts.url,
          headers: opts.headers,
          body: opts.body as IHttpRequestOptions['body'],
          json: true,
          skipSslCertificateValidation: opts.skipSslCertificateValidation,
        });
      }
      return createFetchAdapter()({
        method: opts.method as 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
        url: opts.url,
        headers: opts.headers,
        body: opts.body,
        skipSslCertificateValidation: opts.skipSslCertificateValidation,
      });
    };

    const client = new VaultClient(mapped, adapter);
    await client.authenticate();
    const headers = {
      ...(requestOptions.headers || {}),
      'X-Vault-Token': client.getClientToken(),
    } as Record<string, string>;
    if (mapped.namespace) {
      headers['X-Vault-Namespace'] = mapped.namespace;
    }
    requestOptions.headers = headers;
    return requestOptions;
  };

  test: ICredentialTestRequest = {
    request: {
      method: 'GET',
      url: '={{$credentials.vaultUrl}}/v1/auth/token/lookup-self',
    },
  };
}
