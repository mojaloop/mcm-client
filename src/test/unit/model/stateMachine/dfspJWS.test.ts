/**************************************************************************
 *  (C) Copyright Mojaloop Foundation 2022                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 **************************************************************************/

import { DfspJWS } from '../../../../lib/stateMachine/states';
import { createMachine, interpret } from 'xstate';
import { createMachineOpts, createTestConfigState } from './commonMocks';
import { waitFor } from 'xstate/lib/waitFor';

type Context = DfspJWS.Context;
type Event = DfspJWS.Event;

const startMachine = (opts: ReturnType<typeof createMachineOpts>, onConfigChange: typeof jest.fn) => {
  const machine = createMachine<Context, Event>(
    {
      id: 'testMachine',
      context: {},
      type: 'parallel',
      states: {
        creatingJWS: DfspJWS.createState<Context>(opts),
        connectorConfig: createTestConfigState(onConfigChange),
      },
    },
    {
      guards: {},
      actions: {},
    }
  );

  const service = interpret(machine); // .onTransition((state) => console.log(state.changed, state.value));
  service.start();

  return service;
};

describe('DfspJWS', () => {
  let opts: ReturnType<typeof createMachineOpts>;

  beforeEach(() => {
    opts = createMachineOpts();
  });

  test('should create JWS and upload it', async () => {
    let createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY',
      privateKey: 'JWS PRIVKEY',
      createdAt,
    }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    expect(opts.vault.createJWS).toHaveBeenCalled();
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({
      publicKey: 'JWS PUBKEY',
      createdAt,
    });
    expect(configUpdate).toHaveBeenCalledWith({ jwsSigningKey: 'JWS PRIVKEY' });

    // recreate JWS
    createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY NEW',
      privateKey: 'JWS PRIVKEY NEW',
      createdAt,
    }));
    service.send({ type: 'CREATE_JWS' });
    await waitFor(service, (state) => state.matches('creatingJWS.idle'));
    expect(opts.vault.createJWS).toHaveBeenCalledTimes(2);
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({
      publicKey: 'JWS PUBKEY NEW',
      createdAt,
    });
    expect(configUpdate).toHaveBeenCalledWith({ jwsSigningKey: 'JWS PRIVKEY NEW' });

    service.stop();
  });

  test('should rotate JWS on ROTATE_JWS event', async () => {
    let createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY',
      privateKey: 'JWS PRIVKEY',
      createdAt,
    }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    // Trigger rotation
    createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY ROTATED',
      privateKey: 'JWS PRIVKEY ROTATED',
      createdAt,
    }));

    service.send({ type: 'ROTATE_JWS' });

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    expect(opts.vault.createJWS).toHaveBeenCalledTimes(2);
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({
      publicKey: 'JWS PUBKEY ROTATED',
      createdAt,
    });
    expect(configUpdate).toHaveBeenLastCalledWith({ jwsSigningKey: 'JWS PRIVKEY ROTATED' });

    service.stop();
  });

  test('should automatically rotate JWS after interval', async () => {
    // Set a longer rotation interval for more reliable testing
    opts.jwsRotationIntervalMs = 200;
    opts.ignoreJwsRotationIntervalMin = true;

    let createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY',
      privateKey: 'JWS PRIVKEY',
      createdAt,
    }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    // Wait for automatic rotation
    createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY AUTO',
      privateKey: 'JWS PRIVKEY AUTO',
      createdAt,
    }));

    await waitFor(service, (state) => state.matches('creatingJWS.creating'), { timeout: 500 });
    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    expect(opts.vault.createJWS).toHaveBeenCalledTimes(2);
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({
      publicKey: 'JWS PUBKEY AUTO',
      createdAt,
    });
    expect(configUpdate).toHaveBeenLastCalledWith({ jwsSigningKey: 'JWS PRIVKEY AUTO' });

    service.stop();
  });

  test('should enforce minimum JWS rotation interval', async () => {
    // Set rotation interval below the minimum
    opts.jwsRotationIntervalMs = 1000; // 1 second, below 30 minutes
    const warnSpy = jest.fn();
    opts.logger = { warn: warnSpy } as any;

    const createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({
      publicKey: 'JWS PUBKEY',
      privateKey: 'JWS PRIVKEY',
      createdAt,
    }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    // Check that logger.warn was called with the minimum interval warning
    expect(warnSpy).toHaveBeenCalledWith(
      expect.stringContaining('jwsRotationIntervalMs (1000) too low, using minimum (1800000)')
    );

    // Check that rotatesAt is set to createdAt + MIN_JWS_ROTATION_INTERVAL_MS
    const state = service.getSnapshot();
    const dfspJWS = state.context.dfspJWS;
    expect(dfspJWS).toBeDefined();
    expect(dfspJWS!.rotatesAt).toBe((createdAt * 1000) + 1800000);

    service.stop();
  });
});
