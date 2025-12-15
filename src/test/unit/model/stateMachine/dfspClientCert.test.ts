/**************************************************************************
 *  (C) Copyright Mojaloop Foundation 2022                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 **************************************************************************/

import { DfspClientCert } from '../../../../lib/stateMachine/states';
import { createMachine, interpret } from 'xstate';
import { createMachineOpts, createTestConfigState } from './commonMocks';
import { waitFor } from 'xstate/lib/waitFor';

type Context = DfspClientCert.Context;
type Event = DfspClientCert.Event;

const startMachine = (opts: ReturnType<typeof createMachineOpts>, onConfigChange: typeof jest.fn) => {
  const machine = createMachine<Context, Event>(
    {
      id: 'testMachine',
      context: {},
      type: 'parallel',
      states: {
        creatingDfspClientCert: DfspClientCert.createState<Context>(opts),
        connectorConfig: createTestConfigState(onConfigChange),
      },
    },
    {
      guards: {
        ...DfspClientCert.createGuards<Context>(opts),
      },
      actions: {},
    }
  );

  const service = interpret(machine); // .onTransition((state) => console.log(state.changed, state.value));
  service.start();

  return service;
};

describe('DfspClientCert', () => {
  let opts: ReturnType<typeof createMachineOpts>;

  beforeEach(() => {
    opts = createMachineOpts();
  });

  test('should create client cert and handle cert changes', async () => {
    opts.vault.createCSR.mockImplementation(() => ({ csr: 'DFSP CSR', privateKey: 'PKEY' }));
    opts.dfspCertificateModel.uploadCSR.mockImplementation(async () => ({ id: 123 }));
    opts.dfspCertificateModel.getClientCertificate.mockImplementation(async () => ({
      certificate: 'DFSP CERT',
      state: 'CERT_SIGNED',
    }));
    const configUpdate = jest.fn();
    opts.refreshIntervalSeconds = 1;
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingDfspClientCert.retry'));

    expect(opts.dfspCertificateModel.uploadCSR).toHaveBeenCalledWith({
      csr: 'DFSP CSR',
    });
    expect(opts.dfspCertificateModel.getClientCertificate).toHaveBeenCalledWith({
      inboundEnrollmentId: 123,
    });
    expect(configUpdate).toHaveBeenCalledWith({
      outbound: {
        tls: {
          creds: {
            cert: 'DFSP CERT',
            key: 'PKEY',
          },
        },
      },
    });

    await waitFor(service, (state) => state.matches('creatingDfspClientCert.gettingDfspClientCert'));
    await waitFor(service, (state) => state.matches('creatingDfspClientCert.retry'));

    expect(opts.dfspCertificateModel.getClientCertificate).toHaveBeenNthCalledWith(2, {
      inboundEnrollmentId: 123,
    });
    // cert is the same therefore no changes to config
    expect(configUpdate).toHaveBeenCalledTimes(1);

    // now change cert response
    opts.dfspCertificateModel.getClientCertificate.mockImplementation(async () => ({
      certificate: 'DFSP CERT NEW',
      state: 'CERT_SIGNED',
    }));

    await waitFor(service, (state) => state.matches('creatingDfspClientCert.gettingDfspClientCert'));
    await waitFor(service, (state) => state.matches('creatingDfspClientCert.retry'));

    expect(opts.dfspCertificateModel.getClientCertificate).toHaveBeenCalledTimes(3);
    expect(configUpdate).toHaveBeenNthCalledWith(2, {
      outbound: {
        tls: {
          creds: {
            cert: 'DFSP CERT NEW',
            key: 'PKEY',
          },
        },
      },
    });

    service.stop();
  });

  test('should detect expiring certificate with default threshold', () => {
    const guards = DfspClientCert.createGuards<Context>(opts);
    const ctx: Context = {
      dfspClientCert: {
        cert: 'DFSP CERT',
        privateKey: 'PKEY',
      },
    };

    // Certificate expiring in 5 days (within default 7 day threshold)
    const expiringDate = new Date();
    expiringDate.setDate(expiringDate.getDate() + 5);

    const event = {
      type: 'done.invoke.getDfspClientCert',
      data: {
        state: 'CERT_SIGNED',
        certificate: 'DFSP CERT',
        certInfo: {
          notAfter: expiringDate.toISOString(),
        },
      },
    };

    expect(guards.isDfspClientCertExpiring(ctx, event)).toBe(true);
  });

  test('should detect expiring certificate with custom threshold', () => {
    opts.certExpiryThresholdDays = 14;
    const guards = DfspClientCert.createGuards<Context>(opts);
    const ctx: Context = {
      dfspClientCert: {
        cert: 'DFSP CERT',
        privateKey: 'PKEY',
      },
    };

    // Certificate expiring in 10 days (within custom 14 day threshold)
    const expiringDate = new Date();
    expiringDate.setDate(expiringDate.getDate() + 10);

    const event = {
      type: 'done.invoke.getDfspClientCert',
      data: {
        state: 'CERT_SIGNED',
        certificate: 'DFSP CERT',
        certInfo: {
          notAfter: expiringDate.toISOString(),
        },
      },
    };

    expect(guards.isDfspClientCertExpiring(ctx, event)).toBe(true);
  });

  test('should not detect non-expiring certificate', () => {
    const guards = DfspClientCert.createGuards<Context>(opts);
    const ctx: Context = {
      dfspClientCert: {
        cert: 'DFSP CERT',
        privateKey: 'PKEY',
      },
    };

    // Certificate expiring in 30 days (outside 7 day threshold)
    const futureDate = new Date();
    futureDate.setDate(futureDate.getDate() + 30);

    const event = {
      type: 'done.invoke.getDfspClientCert',
      data: {
        state: 'CERT_SIGNED',
        certificate: 'DFSP CERT',
        certInfo: {
          notAfter: futureDate.toISOString(),
        },
      },
    };

    expect(guards.isDfspClientCertExpiring(ctx, event)).toBe(false);
  });

  test('should assign notBefore and expireTime when certInfo contains both fields', async () => {
    opts.vault.createCSR.mockImplementation(() => ({ csr: 'DFSP CSR', privateKey: 'PKEY' }));
    opts.dfspCertificateModel.uploadCSR.mockImplementation(async () => ({ id: 321 }));
    const notBefore = new Date(Date.now() - 1000 * 60 * 60 * 24).toISOString(); // 1 day ago
    const notAfter = new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(); // 30 days from now
    opts.dfspCertificateModel.getClientCertificate.mockImplementation(async () => ({
      certificate: 'DFSP CERT 4',
      state: 'CERT_SIGNED',
      certInfo: {
        notBefore,
        notAfter,
      },
    }));
    const configUpdate = jest.fn();
    opts.refreshIntervalSeconds = 1;
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingDfspClientCert.retry'));

    const state = service.getSnapshot();
    // @ts-ignore
    const cert = state.context.dfspClientCert;
    expect(cert?.notBefore).toBe(notBefore);
    expect(cert?.notAfter).toBe(notAfter);

    service.stop();
  });
});
