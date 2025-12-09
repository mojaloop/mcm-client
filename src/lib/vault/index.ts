/**************************************************************************
 *  (C) Copyright ModusBox Inc. 2020 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha - yevhen.kyriukha@modusbox.com                   *
 **************************************************************************/
import NodeVault from 'node-vault';
import { strict as assert } from 'assert';
import SDK from '@mojaloop/sdk-standard-components';
import forge from 'node-forge';

// TODO: Use hashi-vault-js package
// TODO: find and link document containing rules on allowable paths
enum VaultPaths {
  STATE_MACHINE_STATE = 'state-machine-state',
}

enum SubjectAltNameType {
  DNS = 2,
  IP = 7,
}

export interface Subject {
  CN: string;
  OU?: string;
  O?: string;
  L?: string;
  C?: string;
  ST?: string;
}

export interface CsrParams {
  subject: Subject;
  extensions?: {
    subjectAltName?: {
      dns?: string[];
      ips?: string[];
    };
  };
}

export interface VaultAuthK8s {
  k8s?: {
    token: string;
    role: string;
  };
}

export interface VaultAuthAppRole {
  appRole?: {
    roleId: string;
    roleSecretId: string;
  };
}

export interface VaultOpts {
  endpoint: string;
  mounts: {
    pki: string;
    kv: string;
  };
  pkiServerRole: string;
  pkiClientRole: string;
  auth: VaultAuthK8s & VaultAuthAppRole;
  signExpiryHours: string;
  keyLength: number;
  keyAlgorithm: string;
  logger: SDK.Logger.SdkLogger;
  commonName: string;
  retryDelayMs?: number;
  keepAlive?: boolean;
}

type VaultLoginResult = { // https://developer.hashicorp.com/vault/api-docs/auth/token#sample-response-1
  auth: {
    client_token: string,
    lease_duration: number;
    [key: string]: unknown;
  }
}

const MAX_TIMEOUT = Math.pow(2, 31) / 2 - 1; // https://developer.mozilla.org/en-US/docs/Web/API/setTimeout#maximum_delay_value

// Enable HTTP keep-alive by default for connection pooling (reduces TCP overhead)
// Can be disabled by setting VAULT_HTTP_KEEP_ALIVE=false
const KEEP_ALIVE = (process.env.VAULT_HTTP_KEEP_ALIVE ?? 'true') === 'true';

export default class Vault {
  private cfg: VaultOpts;
  private reconnectTimer?: NodeJS.Timeout;
  private client?: NodeVault.client;
  private logger: SDK.Logger.SdkLogger;

  constructor(private opts: VaultOpts) {
    this.cfg = opts;
    this.logger = opts.logger.child({ component: 'VaultClient' });
  }

  private _isTokenError(e: any): boolean {
    return e?.response?.statusCode === 403 &&
      (e?.response?.body?.errors?.some?.((msg: string) =>
        msg.toLowerCase().includes('token') && msg.toLowerCase().includes('expired')
      ) ||
      e?.response?.body?.errors?.some?.((msg: string) =>
        msg.toLowerCase().includes('permission denied')
      ));
  }

  private async _withTokenRefresh<T>(fn: () => Promise<T>, retry = true, retryDelayMs=1000): Promise<T> {
    try {
      return await fn();
    } catch (e: any) {
      this.logger.warn('Error in _withTokenRefresh:', e);

      // Vault returns 403 for expired/invalid tokens
      const isTokenError = this._isTokenError(e);

      if (isTokenError && retry) {
        this.logger.warn('Vault token expired or invalid, reconnecting...');
        // put a delay here
        const delayMs = this.cfg.retryDelayMs || retryDelayMs;
        this.logger.info(`Waiting for ${delayMs} ms before retrying...`);
        await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
        await this.connect();
        return this._withTokenRefresh(fn, false); // Only retry once
      }
      throw e;
    }
  }

  async connect() {
    const { auth, endpoint } = this.cfg;
    const rpDefaults = { forever: this.cfg.keepAlive ?? KEEP_ALIVE };
    this.logger.info('Connecting to Vault...', { endpoint, rpDefaults });

    let creds: VaultLoginResult;

    try {
      const vault = NodeVault({ endpoint, rpDefaults } as any);
      if (auth.appRole) {
        creds = await vault.approleLogin({
          role_id: auth.appRole.roleId,
          secret_id: auth.appRole.roleSecretId,
        });
      } else if (auth.k8s) {
        creds = await vault.kubernetesLogin({
          role: auth.k8s.role,
          jwt: auth.k8s.token,
        });
      } else {
        const errMessage = 'Unsupported auth method';
        this.logger.warn(errMessage);
        throw new Error(errMessage);
      }

      this.client = NodeVault({
        endpoint,
        token: creds.auth.client_token,
        rpDefaults,
      } as NodeVault.VaultOptions);

      // Only clear the timer if vault has been connected successfully
      if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

      const tokenRefreshMs = Math.min((creds.auth.lease_duration - 30) * 1000, MAX_TIMEOUT);
      this.reconnectTimer = setTimeout(this.connect.bind(this), tokenRefreshMs);

      this.logger.info(
        `Connected to Vault  [reconnect after: ${tokenRefreshMs} ms]`, { endpoint }
      );
    } catch (err) {
      this.logger.child({ endpoint, rpDefaults }).error(`error in vault.connect(): `, err);
      throw err;
    }
  }

  disconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.logger.info('disconnected from Vault');
  }

  mountAll() {
    assert(this.client);
    return Promise.all([
      this.client.mount({ type: 'pki', prefix: `${this.cfg.mounts.pki}` }),
      this.client.mount({ type: 'kv', prefix: `${this.cfg.mounts.kv}` }),
    ]);
  }

  async createPkiRoles() {
    // return this._client.request({
    //     path: `${this.cfg.mounts.pki}/roles/${this._pkiBaseDomain}`,
    //     method: 'POST',
    //     json: {
    //         allow_any_name: true,
    //     }
    // });
  }

  _setSecret(key: string, value: any) {
    assert(this.client);
    assert(key !== null && key !== undefined, `Cannot set key: [${key}]`);
    const path = `${this.cfg.mounts.kv}/${key}`;
    return this.client.write(path, value);
  }

  async _getSecret(key: string) {
    assert(this.client);
    const path = `${this.cfg.mounts.kv}/${key}`;
    try {
      const { data } = await this.client.read(path);
      return data;
    } catch (e: any) {
      this.logger.warn(`error in _getSecret: `, e);
      if (e?.response?.statusCode === 404) {
        return;
      }
      throw e;
    }
  }

  async _deleteSecret(key: string) {
    assert(this.client);
    const path = `${this.cfg.mounts.kv}/${key}`;
    await this.client.delete(path);
  }

  async setStateMachineState(value: any) {
    return this._withTokenRefresh(() => this._setSecret(VaultPaths.STATE_MACHINE_STATE, value));
  }

  async getStateMachineState() {
    return this._withTokenRefresh(() => this._getSecret(VaultPaths.STATE_MACHINE_STATE));
  }

  async deleteStateMachineState() {
    return this._deleteSecret(VaultPaths.STATE_MACHINE_STATE);
  }

  /**
   * Delete root CA
   * @returns {Promise<void>}
   */
  async deleteCA() {
    return this._withTokenRefresh(async () => {
      try {
        assert(this.client);
        await this.client.request({
          path: `/${this.cfg.mounts.pki}/root`,
          method: 'DELETE',
        });
      } catch (err) {
        this.logger.warn(`error in deleteCA: `, err);
        throw err;
      }
    });
  }

  /**
   * Create root CA
   */
  async createCA(subject: Subject) {
    return this._withTokenRefresh(async () => {
      await this.deleteCA();

      assert(this.client);
      const { data } = await this.client.request({
        path: `/${this.cfg.mounts.pki}/root/generate/exported`,
        method: 'POST',
        json: {
          common_name: subject.CN,
          ou: subject.OU,
          organization: subject.O,
          locality: subject.L,
          country: subject.C,
          province: subject.ST,
          key_type: this.cfg.keyAlgorithm,
          key_bits: this.cfg.keyLength,
        },
      });

      return {
        cert: data.certificate,
        key: data.private_key,
      };
    });
  }

  async getCA() {
    return this._withTokenRefresh(() => {
      assert(this.client);
      return this.client.request({
        path: `/${this.cfg.mounts.pki}/ca/pem`,
        method: 'GET',
      });
    });
  }

  /**
   * Issues a new DFSP server certificate using the provided CSR parameters.
   *
   * A server certificate is a digital certificate used to authenticate a server to clients,
   * enabling secure encrypted communications (typically via TLS/SSL). It contains information
   * about the server's identity and is signed by a trusted Certificate Authority (CA).
   *
   * This function sends a request to the Vault PKI backend to generate a server certificate,
   * including support for Subject Alternative Names (SANs) such as DNS names and IP addresses.
   * The function automatically handles token refresh before making the request.
   *
   * @param csrParameters - The parameters for the certificate signing request, including subject details and extensions.
   * @returns An object containing the intermediate CA chain, root certificate, server certificate, private key, and expiration date.
   *
   * @throws Will throw an error if the Vault client is not initialized or if the request fails.
   */
  async createDFSPServerCert(csrParameters: CsrParams) {
    return this._withTokenRefresh(async () => {
      const reqJson: Record<string, any> = {
        common_name: csrParameters.subject.CN,
      };
      if (csrParameters?.extensions?.subjectAltName) {
        const { dns, ips } = csrParameters.extensions.subjectAltName;
        if (dns) {
          reqJson.alt_names = dns.join(',');
        }
        if (ips) {
          reqJson.ip_sans = ips.join(',');
        }
      }
      assert(this.client);

      const options = {
        path: `/${this.cfg.mounts.pki}/issue/${this.cfg.pkiServerRole}`,
        method: 'POST',
        json: reqJson,
      };

      const { data } = await this.client.request(options);
      this.logger.verbose('createDFSPServerCert is done: ', { options });

      return {
        intermediateChain: Array.isArray(data.ca_chain) ? data.ca_chain.join('\n') : data.ca_chain,
        rootCertificate: data.issuing_ca,
        serverCertificate: data.certificate,
        privateKey: data.private_key,
        expiration: data.expiration,
      };
    });
  }

  /**
   * Signs a Certificate Signing Request (CSR) for the hub using the configured PKI role.
   *
   * This method sends a POST request to the Vault PKI endpoint to sign the provided CSR.
   * The signed certificate is returned in the response data.
   *
   * @param csr - The PEM-encoded certificate signing request to be signed.
   * @returns A promise that resolves with the signed certificate data from Vault.
   * @throws If the Vault client is not initialized or if the signing request fails.
   */
  async signHubCSR(csr: string) {
    return this._withTokenRefresh(async () => {
      assert(this.client);

      const options = {
        path: `/${this.cfg.mounts.pki}/sign/${this.cfg.pkiClientRole}`,
        method: 'POST',
        json: {
          common_name: this.cfg.commonName,
          // ttl: `${this._signExpiryHours}h`,
        },
      };
      this.logger.verbose(`sending signHubCSR request...`, { options });
      options.json['csr'] = csr;

      const { data } = await this.client.request(options);
      this.logger.verbose(`sending signHubCSR request is done`);

      return data;
    });
  }

  /**
   * Sets the DFSP CA certificate chain and private key in Vault.
   *
   * A CA certificate chain is a sequence of certificates, where each certificate in the chain is signed by the subsequent certificate,
   * up to a trusted root certificate authority (CA). This chain allows clients to verify the authenticity of a
   * certificate by tracing it back to a trusted root CA.
   *
   * This method posts the provided certificate chain and private key to the Vault PKI mount's CA configuration endpoint.
   * The `pem_bundle` is constructed by concatenating the private key and certificate chain in PEM format.
   *
   * @param certChainPem - The PEM-encoded certificate chain to be stored.
   * @param privateKeyPem - The PEM-encoded private key to be stored.
   * @returns A promise that resolves when the request completes.
   *
   * @remarks
   * - Requires a valid Vault client and configuration.
   * - The Vault secret object documentation can be found at:
   *   - {@link https://github.com/modusintegration/mojaloop-k3s-bootstrap/blob/e3578fc57a024a41023c61cd365f382027b922bd/docs/README-vault.md#vault-crd-secrets-integration}
   *   - {@link https://vault.koudingspawn.de/supported-secret-types/secret-type-cert}
   */
  async setDFSPCaCertChain(certChainPem: string, privateKeyPem: string) {
    return this._withTokenRefresh(async () => {
      assert(this.client);
      await this.client.request({
        path: `/${this.cfg.mounts.pki}/config/ca`,
        method: 'POST',
        json: {
          pem_bundle: `${privateKeyPem}\n${certChainPem}`,
        },
      });
      // Secret object documentation:
      // https://github.com/modusintegration/mojaloop-k3s-bootstrap/blob/e3578fc57a024a41023c61cd365f382027b922bd/docs/README-vault.md#vault-crd-secrets-integration
      // https://vault.koudingspawn.de/supported-secret-types/secret-type-cert
    });
  }

  async getDFSPCaCertChain() {
    return this._withTokenRefresh(() => {
      assert(this.client);
      return this.client.request({
        path: `/${this.cfg.mounts.pki}/ca_chain`,
        method: 'GET',
      });
    });
  }

  certIsValid(certPem, date = Date.now()) {
    const cert = forge.pki.certificateFromPem(certPem);
    return (
      cert.validity.notBefore.getTime() > date &&
      date < cert.validity.notAfter.getTime()
    );
  }

  createCSR(csrParameters?: CsrParams) {
    const keys = forge.pki.rsa.generateKeyPair(this.cfg.keyLength);
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;

    if (csrParameters?.subject) {
      csr.setSubject(
        Object.entries(csrParameters.subject).map(([shortName, value]) => ({
          shortName,
          value,
        })),
      );
    }

    if (csrParameters?.extensions?.subjectAltName) {
      const { dns, ips } = csrParameters.extensions.subjectAltName;
      csr.setExtensions([
        {
          name: 'subjectAltName',
          altNames: [
            ...(dns?.map?.((value) => ({
              type: SubjectAltNameType.DNS,
              value,
            })) || []),
            ...(ips?.map?.((value) => ({
              type: SubjectAltNameType.IP,
              value,
            })) || []),
          ],
        },
      ]);
    }

    csr.sign(keys.privateKey, forge.md.sha256.create());
    this.logger.verbose('createCSR is done')

    return {
      csr: forge.pki.certificationRequestToPem(csr),
      privateKey: forge.pki.privateKeyToPem(keys.privateKey, 72),
    };
  }

  /**
   * Generates a new RSA key pair and returns the public and private keys in PEM format,
   * along with the creation timestamp.
   *
   * @returns An object containing:
   * - `publicKey`: The RSA public key in PEM format.
   * - `privateKey`: The RSA private key in PEM format.
   * - `createdAt`: The timestamp in seconds since Unix epoch (January 1, 1970 UTC) when the key pair was created.
   *
   * @remarks
   * The key length is determined by the `keyLength` property in the configuration (`this.cfg.keyLength`).
   */
  createJWS() {
    const keypair = forge.pki.rsa.generateKeyPair({ bits: this.cfg.keyLength });
    return {
      publicKey: forge.pki.publicKeyToPem(keypair.publicKey, 72),
      privateKey: forge.pki.privateKeyToPem(keypair.privateKey, 72),
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Performs a health check on the Vault server by sending a GET request to the `/sys/health` endpoint.
   *
   * @returns {Promise<any>} A promise that resolves with the response from the Vault health endpoint if successful, or an object with status 'DOWN' if the request fails. A warning will be logged if the health check fails.
   */
  async healthCheck() {
    assert(this.client);
    try {
      const response = await this.client.request({
        path: '/sys/health',
        method: 'GET',
      });
      return response;
    } catch (err: unknown) {
      this.logger.warn('Vault health check failed: ', err);
      return { status: 'DOWN' };
    }
  }
}
