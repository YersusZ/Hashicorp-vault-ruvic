import type {
  ICredentialDataDecryptedObject,
  IDataObject,
  IExecuteFunctions,
  IHttpRequestOptions,
  INodeExecutionData,
  INodeType,
  INodeTypeDescription,
} from 'n8n-workflow';
import { NodeApiError, NodeOperationError } from 'n8n-workflow';
import { nodeProperties } from './descriptions';
import { asObject, fromN8nCredentials } from './transport/credentialsMapper';
import { maskSecrets } from './transport/mask';
import { parseVersions, VaultApiError } from './transport/paths';
import type { ExecutionJson, HttpAdapter } from './transport/types';
import { VaultClient } from './transport/vaultClient';

function optionalString(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed === '' ? undefined : trimmed;
}

function optionalMount(value: unknown): string | undefined {
  return optionalString(value);
}

function casOption(value: unknown): number | undefined {
  if (typeof value !== 'number' || value < 0) {
    return undefined;
  }
  return value;
}

export class HashiCorpVault implements INodeType {
  description: INodeTypeDescription = {
    displayName: 'HashiCorp Vault',
    name: 'hashicorpVault',
    icon: 'file:hashicorp.svg',
    group: ['transform'],
    version: 1,
    subtitle: '={{$parameter["operation"] + ": " + $parameter["resource"]}}',
    description: 'Manage infrastructure credentials in HashiCorp Vault (KV, dynamic secrets, rotation, leases)',
    defaults: {
      name: 'HashiCorp Vault',
    },
    inputs: ['main'],
    outputs: ['main'],
    usableAsTool: true,
    credentials: [
      {
        name: 'hashiCorpVaultApi',
        required: true,
      },
    ],
    properties: nodeProperties,
  };

  async execute(this: IExecuteFunctions): Promise<INodeExecutionData[][]> {
    const items = this.getInputData();
    const returnData: INodeExecutionData[] = [];
    const credentials = (await this.getCredentials('hashiCorpVaultApi')) as ICredentialDataDecryptedObject;
    const adapter = createN8nAdapter(this);
    const client = new VaultClient(fromN8nCredentials(credentials), adapter);
    await client.authenticate();

    for (let i = 0; i < items.length; i++) {
      try {
        const resource = this.getNodeParameter('resource', i) as string;
        const operation = this.getNodeParameter('operation', i) as string;
        const maskEnabled = this.getNodeParameter('maskSecrets', i, true) as boolean;
        const maskRegex = this.getNodeParameter('maskRegex', i, '') as string;
        const json = await runOperation(this, client, resource, operation, i);
        const payload = maskEnabled ? (maskSecrets(json, maskRegex) as IDataObject) : (json as IDataObject);
        returnData.push({ json: payload, pairedItem: { item: i } });
      } catch (error) {
        const vaultError = error instanceof VaultApiError ? error : undefined;
        if (this.continueOnFail()) {
          returnData.push({
            json: {
              error: vaultError ? vaultError.message : 'Vault request failed',
              statusCode: vaultError?.statusCode,
            },
            pairedItem: { item: i },
          });
          continue;
        }
        if (vaultError) {
          throw new NodeApiError(
            this.getNode(),
            { errors: vaultError.errors },
            {
              message: vaultError.message,
              httpCode: String(vaultError.statusCode),
              description: vaultError.errors.join(', '),
            },
          );
        }
        throw new NodeOperationError(this.getNode(), error as Error, { itemIndex: i });
      }
    }

    return [returnData];
  }
}

function createN8nAdapter(ctx: IExecuteFunctions): HttpAdapter {
  return async (opts) => {
    const mergePatch = Boolean(opts.headers?.['Content-Type']?.includes('merge-patch'));
    return ctx.helpers.httpRequest({
      method: opts.method as IHttpRequestOptions['method'],
      url: opts.url,
      headers: opts.headers,
      body: (mergePatch ? JSON.stringify(opts.body) : opts.body) as IHttpRequestOptions['body'],
      json: !mergePatch,
      skipSslCertificateValidation: opts.skipSslCertificateValidation,
    });
  };
}

async function runOperation(
  ctx: IExecuteFunctions,
  client: VaultClient,
  resource: string,
  operation: string,
  itemIndex: number,
): Promise<ExecutionJson> {
  const mount = optionalMount(ctx.getNodeParameter('mount', itemIndex, ''));

  if (resource === 'system') {
    if (operation === 'health') {
      return client.health();
    }
    if (operation === 'lookupSelf') {
      return client.lookupSelf();
    }
  }

  if (resource === 'kv') {
    const secretPath = (ctx.getNodeParameter('secretPath', itemIndex, '') as string) || '';
    if (operation === 'read') {
      const version = ctx.getNodeParameter('secretVersion', itemIndex, 0) as number;
      return client.kvRead(secretPath, { mount, version: version > 0 ? version : undefined });
    }
    if (operation === 'write' || operation === 'rotate') {
      const secretData = asObject(ctx.getNodeParameter('secretData', itemIndex));
      const cas = casOption(ctx.getNodeParameter('cas', itemIndex, -1));
      return operation === 'rotate'
        ? client.kvRotate(secretPath, secretData, { mount, cas })
        : client.kvWrite(secretPath, secretData, { mount, cas });
    }
    if (operation === 'patch') {
      const secretData = asObject(ctx.getNodeParameter('secretData', itemIndex));
      const cas = casOption(ctx.getNodeParameter('cas', itemIndex, -1));
      return client.kvPatch(secretPath, secretData, { mount, cas });
    }
    if (operation === 'list') {
      return client.kvList(secretPath, { mount });
    }
    if (operation === 'delete') {
      const versions = parseVersions(ctx.getNodeParameter('versions', itemIndex, '') as string);
      return client.kvDelete(secretPath, { mount, versions: versions.length ? versions : undefined });
    }
    if (operation === 'undelete') {
      return client.kvUndelete(secretPath, parseVersions(ctx.getNodeParameter('versions', itemIndex, '') as string), {
        mount,
      });
    }
    if (operation === 'destroy') {
      return client.kvDestroy(secretPath, parseVersions(ctx.getNodeParameter('versions', itemIndex, '') as string), {
        mount,
      });
    }
    if (operation === 'getMetadata') {
      return client.kvGetMetadata(secretPath, { mount });
    }
    if (operation === 'updateMetadata') {
      return client.kvUpdateMetadata(secretPath, asObject(ctx.getNodeParameter('metadataBody', itemIndex)), { mount });
    }
    if (operation === 'deleteMetadata') {
      return client.kvDeleteMetadata(secretPath, { mount });
    }
  }

  if (resource === 'lease') {
    const leaseId = ctx.getNodeParameter('leaseId', itemIndex) as string;
    if (operation === 'lookup') {
      return client.leaseLookup(leaseId);
    }
    if (operation === 'renew') {
      const increment = ctx.getNodeParameter('increment', itemIndex, 0) as number;
      return client.leaseRenew(leaseId, increment > 0 ? increment : undefined);
    }
    if (operation === 'revoke') {
      return client.leaseRevoke(leaseId);
    }
  }

  if (resource === 'database') {
    const roleName = ctx.getNodeParameter('roleName', itemIndex) as string;
    if (operation === 'generateCredentials') {
      return client.generateDynamic('database', `creds/${roleName}`, { mount });
    }
    if (operation === 'generateStaticCredentials') {
      return client.generateDynamic('database', `static-creds/${roleName}`, { mount });
    }
    if (operation === 'rotateRole') {
      return client.generateDynamic('database', `rotate-role/${roleName}`, { mount, method: 'POST' });
    }
    if (operation === 'rotateRoot') {
      return client.generateDynamic('database', `rotate-root/${roleName}`, { mount, method: 'POST' });
    }
  }

  if (resource === 'ssh') {
    const roleName = ctx.getNodeParameter('roleName', itemIndex) as string;
    if (operation === 'generateOtp') {
      const body: Record<string, unknown> = {};
      const ip = optionalString(ctx.getNodeParameter('ipAddress', itemIndex, ''));
      const username = optionalString(ctx.getNodeParameter('username', itemIndex, ''));
      if (ip) body.ip = ip;
      if (username) body.username = username;
      return client.generateDynamic('ssh', `creds/${roleName}`, { mount, method: 'POST', body });
    }
    if (operation === 'sign') {
      const body: Record<string, unknown> = {
        public_key: ctx.getNodeParameter('publicKey', itemIndex) as string,
        cert_type: ctx.getNodeParameter('certType', itemIndex, 'user') as string,
      };
      const username = optionalString(ctx.getNodeParameter('username', itemIndex, ''));
      const principals = optionalString(ctx.getNodeParameter('validPrincipals', itemIndex, ''));
      const ttl = optionalString(ctx.getNodeParameter('ttl', itemIndex, ''));
      if (username) body.valid_principals = username;
      if (principals) body.valid_principals = principals;
      if (ttl) body.ttl = ttl;
      return client.generateDynamic('ssh', `sign/${roleName}`, { mount, method: 'POST', body });
    }
    if (operation === 'issue') {
      const body: Record<string, unknown> = {
        cert_type: ctx.getNodeParameter('certType', itemIndex, 'user') as string,
        key_type: ctx.getNodeParameter('keyType', itemIndex, 'ed25519') as string,
      };
      const principals = optionalString(ctx.getNodeParameter('validPrincipals', itemIndex, ''));
      const ttl = optionalString(ctx.getNodeParameter('ttl', itemIndex, ''));
      const keyBits = ctx.getNodeParameter('keyBits', itemIndex, 0) as number;
      if (principals) body.valid_principals = principals;
      if (ttl) body.ttl = ttl;
      if (keyBits > 0) body.key_bits = keyBits;
      return client.generateDynamic('ssh', `issue/${roleName}`, { mount, method: 'POST', body });
    }
  }

  if (resource === 'aws') {
    if (operation === 'rotateRoot') {
      return client.generateDynamic('aws', 'config/rotate-root', { mount, method: 'POST' });
    }
    const roleName = ctx.getNodeParameter('roleName', itemIndex) as string;
    const ttl = optionalString(ctx.getNodeParameter('ttl', itemIndex, ''));
    if (operation === 'generateIam') {
      return client.generateDynamic('aws', `creds/${roleName}`, { mount, qs: { ttl } });
    }
    if (operation === 'generateSts') {
      const roleArn = optionalString(ctx.getNodeParameter('roleArn', itemIndex, ''));
      const roleSessionName = optionalString(ctx.getNodeParameter('roleSessionName', itemIndex, ''));
      return client.generateDynamic('aws', `sts/${roleName}`, {
        mount,
        qs: { ttl, role_arn: roleArn, role_session_name: roleSessionName },
      });
    }
  }

  if (resource === 'azure') {
    if (operation === 'rotateRoot') {
      return client.generateDynamic('azure', 'rotate-root', { mount, method: 'POST' });
    }
    const roleName = ctx.getNodeParameter('roleName', itemIndex) as string;
    if (operation === 'generateCredentials') {
      return client.generateDynamic('azure', `creds/${roleName}`, { mount });
    }
    if (operation === 'generateStaticCredentials') {
      return client.generateDynamic('azure', `static-creds/${roleName}`, { mount });
    }
    if (operation === 'rotateRole') {
      return client.generateDynamic('azure', `rotate-role/${roleName}`, { mount, method: 'POST' });
    }
  }

  if (resource === 'gcp') {
    if (operation === 'rotateRoot') {
      return client.generateDynamic('gcp', 'config/rotate-root', { mount, method: 'POST' });
    }
    const roleName = ctx.getNodeParameter('roleName', itemIndex) as string;
    if (operation === 'rotateRoleset') {
      return client.generateDynamic('gcp', `roleset/${roleName}/rotate`, { mount, method: 'POST' });
    }
    if (operation === 'rotateRolesetKey') {
      return client.generateDynamic('gcp', `roleset/${roleName}/rotate-key`, { mount, method: 'POST' });
    }
    const accountType = (ctx.getNodeParameter('gcpAccountType', itemIndex, 'roleset') as string) || 'roleset';
    if (operation === 'generateAccessToken') {
      if (accountType === 'impersonated-account') {
        return client.generateDynamic('gcp', `impersonated-account/${roleName}/token`, { mount });
      }
      if (accountType === 'static-account') {
        return client.generateDynamic('gcp', `static-account/${roleName}/token`, { mount });
      }
      return client.generateDynamic('gcp', `roleset/${roleName}/token`, { mount });
    }
    if (operation === 'generateServiceAccountKey') {
      const body = {
        key_algorithm: ctx.getNodeParameter('keyAlgorithm', itemIndex, 'KEY_ALG_RSA_2048') as string,
        key_type: ctx.getNodeParameter('gcpKeyType', itemIndex, 'TYPE_JSON') as string,
      };
      const prefix = accountType === 'static-account' ? 'static-account' : 'roleset';
      return client.generateDynamic('gcp', `${prefix}/${roleName}/key`, { mount, method: 'POST', body });
    }
  }

  throw new NodeOperationError(ctx.getNode(), `Unsupported operation ${resource}.${operation}`, { itemIndex });
}
