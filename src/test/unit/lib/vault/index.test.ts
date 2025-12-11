/*****
 License
 --------------
 Copyright © 2020-2025 Mojaloop Foundation
 The Mojaloop files are made available by the Mojaloop Foundation under the Apache License, Version 2.0 (the "License") and you may not use these files except in compliance with the License. You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, the Mojaloop files are distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

 Contributors
 --------------
 This is the official list of the Mojaloop project contributors for this file.
 Names of the original copyright holders (individuals or organizations)
 should be listed with a '*' in the first column. People who have
 contributed from an organization can be listed under the organization
 that actually holds the copyright for their contributions (see the
 Mojaloop Foundation for an example). Those individuals should have
 their names indented and be marked with a '-'. Email address can be added
 optionally within square brackets <email>.

 * Mojaloop Foundation
 * Eugen Klymniuk <eugen.klymniuk@infitx.com>

 --------------
 ******/

import { Logger } from '@mojaloop/sdk-standard-components';
import Vault, { VaultOpts } from '../../../../lib/vault';

// Mock node-vault
jest.mock('node-vault', () => jest.fn());

interface MockVaultClient {
  approleLogin: jest.Mock;
  kubernetesLogin: jest.Mock;
}

describe('Vault HTTP Keep-Alive Tests', () => {
  let vaultOpts: VaultOpts;
  let mockVaultClient: MockVaultClient;
  let originalEnv: string | undefined;
  let NodeVault: jest.Mock;

  beforeEach(() => {
    originalEnv = process.env.VAULT_HTTP_KEEP_ALIVE;

    NodeVault = require('node-vault') as jest.Mock;
    jest.clearAllMocks();

    // Create mock vault client with required methods
    mockVaultClient = {
      approleLogin: jest.fn().mockResolvedValue({
        auth: {
          client_token: 'test-token',
          lease_duration: 3600,
        },
      }),
      kubernetesLogin: jest.fn().mockResolvedValue({
        auth: {
          client_token: 'test-token',
          lease_duration: 3600,
        },
      }),
    };

    // Mock NodeVault to return our mock client
    NodeVault.mockReturnValue(mockVaultClient);

    // Create vault options for testing
    vaultOpts = {
      endpoint: 'http://vault.example.com:8200',
      mounts: {
        pki: 'pki',
        kv: 'secret',
      },
      pkiServerRole: 'server-role',
      pkiClientRole: 'client-role',
      auth: {
        appRole: {
          roleId: 'test-role-id',
          roleSecretId: 'test-secret-id',
        },
      },
      signExpiryHours: '8760',
      keyLength: 4096,
      keyAlgorithm: 'rsa',
      logger: new Logger.SdkLogger(),
      commonName: 'test-common-name',
    };
  });

  afterEach(() => {
    // Restore original env
    if (originalEnv !== undefined) {
      process.env.VAULT_HTTP_KEEP_ALIVE = originalEnv;
    } else {
      delete process.env.VAULT_HTTP_KEEP_ALIVE;
    }
  });

  describe('Keep-Alive Configuration', () => {
    describe('via keepAlive config option', () => {
      test('should enable keep-alive when keepAlive is true', async () => {
        const optsWithKeepAlive: VaultOpts = {
          ...vaultOpts,
          keepAlive: true,
        };

        const vault = new Vault(optsWithKeepAlive);
        await vault.connect();

        expect(NodeVault).toHaveBeenCalledTimes(2);
        expect(NodeVault).toHaveBeenNthCalledWith(1, {
          endpoint: optsWithKeepAlive.endpoint,
          rpDefaults: { forever: true },
        });
        expect(NodeVault).toHaveBeenNthCalledWith(2, {
          endpoint: optsWithKeepAlive.endpoint,
          token: 'test-token',
          rpDefaults: { forever: true },
        });
      });

      test('should disable keep-alive when keepAlive is false', async () => {
        const optsWithoutKeepAlive: VaultOpts = {
          ...vaultOpts,
          keepAlive: false,
        };

        const vault = new Vault(optsWithoutKeepAlive);
        await vault.connect();

        expect(NodeVault).toHaveBeenCalledTimes(2);
        expect(NodeVault).toHaveBeenNthCalledWith(1, {
          endpoint: optsWithoutKeepAlive.endpoint,
          rpDefaults: { forever: false },
        });
        expect(NodeVault).toHaveBeenNthCalledWith(2, {
          endpoint: optsWithoutKeepAlive.endpoint,
          token: 'test-token',
          rpDefaults: { forever: false },
        });
      });

      test('should use default (true) when keepAlive is undefined', async () => {
        // keepAlive is not set, should fall back to module-level KEEP_ALIVE constant
        const vault = new Vault(vaultOpts);
        await vault.connect();

        expect(NodeVault).toHaveBeenCalledTimes(2);
        // Should default to true based on KEEP_ALIVE constant
        expect(NodeVault).toHaveBeenNthCalledWith(1, {
          endpoint: vaultOpts.endpoint,
          rpDefaults: { forever: true },
        });
      });

      test('config option should override environment variable', async () => {
        // Even if env var says false, config option should win
        process.env.VAULT_HTTP_KEEP_ALIVE = 'false';

        const optsOverride: VaultOpts = {
          ...vaultOpts,
          keepAlive: true, // Override env var
        };

        const vault = new Vault(optsOverride);
        await vault.connect();

        expect(NodeVault).toHaveBeenNthCalledWith(1, {
          endpoint: optsOverride.endpoint,
          rpDefaults: { forever: true }, // Config wins over env
        });
      });
    });

    describe('with different auth methods', () => {
      test('should work with Kubernetes auth', async () => {
        const k8sVaultOpts: VaultOpts = {
          ...vaultOpts,
          keepAlive: true,
          auth: {
            k8s: {
              token: 'k8s-token',
              role: 'k8s-role',
            },
          },
        };

        const vault = new Vault(k8sVaultOpts);
        await vault.connect();

        expect(NodeVault).toHaveBeenCalledTimes(2);
        expect(mockVaultClient.kubernetesLogin).toHaveBeenCalledWith({
          role: 'k8s-role',
          jwt: 'k8s-token',
          kubernetesPath: 'kubernetes',
        });

        expect(NodeVault).toHaveBeenNthCalledWith(1, {
          endpoint: k8sVaultOpts.endpoint,
          rpDefaults: { forever: true },
        });
      });

      test('should work with AppRole auth', async () => {
        const vault = new Vault({
          ...vaultOpts,
          keepAlive: false,
        });
        await vault.connect();

        expect(mockVaultClient.approleLogin).toHaveBeenCalledWith({
          role_id: 'test-role-id',
          secret_id: 'test-secret-id',
        });

        expect(NodeVault).toHaveBeenNthCalledWith(1, {
          endpoint: vaultOpts.endpoint,
          rpDefaults: { forever: false },
        });
      });
    });

    describe('error handling', () => {
      test('should handle connection errors properly', async () => {
        mockVaultClient.approleLogin.mockRejectedValueOnce(new Error('Connection failed'));

        const vault = new Vault({ ...vaultOpts, keepAlive: true });

        await expect(vault.connect()).rejects.toThrow('Connection failed');
        expect(NodeVault).toHaveBeenCalledWith({
          endpoint: vaultOpts.endpoint,
          rpDefaults: { forever: true },
        });
      });
    });
  });
});
