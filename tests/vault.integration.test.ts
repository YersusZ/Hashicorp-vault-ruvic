import './loadEnv';
import { createFetchAdapter, VaultClient } from '../nodes/HashiCorpVault/transport/vaultClient';

const vaultAddr = process.env.VAULT_ADDR;
const vaultToken = process.env.VAULT_TOKEN;
const runIntegration = process.env.VAULT_INTEGRATION === 'true';

const describeIntegration = runIntegration && vaultAddr && vaultToken ? describe : describe.skip;

describeIntegration('Vault integration (docker-compose.vault.yml)', () => {
  const client = new VaultClient(
    {
      vaultUrl: vaultAddr as string,
      authMethod: 'token',
      token: vaultToken,
      kvMount: process.env.VAULT_KV_MOUNT || 'secret',
      kvVersion: process.env.VAULT_KV_VERSION === 'v1' ? 'v1' : 'v2',
    },
    createFetchAdapter(),
  );

  beforeAll(async () => {
    try {
      await client.authenticate();
      await client.health();
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(
        `Vault is not running at ${vaultAddr}. Start Docker Desktop (systemctl --user start docker-desktop), then: docker compose -f docker-compose.vault.yml up -d\n${message}`,
      );
    }
  });

  it('writes, reads, lists and deletes a KV v2 secret', async () => {
    const path = `ruvic-tests/${Date.now()}`;
    await client.kvWrite(path, { username: 'deploy', password: 'temporary' });
    const read = await client.kvRead(path);
    expect(read.data).toMatchObject({ username: 'deploy', password: 'temporary' });

    const listed = await client.kvList('ruvic-tests');
    const keys = (listed.data?.keys as string[]) || [];
    expect(keys.some((key) => path.endsWith(key.replace(/\/$/, '')) || key.includes(path.split('/')[1]))).toBe(true);

    await client.kvDelete(path);
    await expect(client.kvRead(path)).rejects.toBeDefined();
  });

  it('looks up health', async () => {
    const health = await client.health();
    expect(health).toBeDefined();
  });
});
