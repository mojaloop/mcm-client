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
    opts.vault.createJWS.mockImplementation(() => ({ publicKey: 'JWS PUBKEY', privateKey: 'JWS PRIVKEY', createdAt }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    expect(opts.vault.createJWS).toHaveBeenCalled();
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({ publicKey: 'JWS PUBKEY', createdAt });
    expect(configUpdate).toHaveBeenCalledWith({ jwsSigningKey: 'JWS PRIVKEY' });

    // recreate JWS
    createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({ publicKey: 'JWS PUBKEY NEW', privateKey: 'JWS PRIVKEY NEW', createdAt }));
    service.send({ type: 'CREATE_JWS' });
    await waitFor(service, (state) => state.matches('creatingJWS.idle'));
    expect(opts.vault.createJWS).toHaveBeenCalledTimes(2);
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({ publicKey: 'JWS PUBKEY NEW', createdAt });
    expect(configUpdate).toHaveBeenCalledWith({ jwsSigningKey: 'JWS PRIVKEY NEW' });

    service.stop();
  });

  test('should rotate JWS on ROTATE_JWS event', async () => {
    let createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({ publicKey: 'JWS PUBKEY', privateKey: 'JWS PRIVKEY', createdAt }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    // Trigger rotation
    createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({ publicKey: 'JWS PUBKEY ROTATED', privateKey: 'JWS PRIVKEY ROTATED', createdAt }));

    const beforeRotation = Date.now();
    service.send({ type: 'ROTATE_JWS' });

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));
    const afterRotation = Date.now();

    expect(opts.vault.createJWS).toHaveBeenCalledTimes(2);
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({ publicKey: 'JWS PUBKEY ROTATED', createdAt });
    expect(configUpdate).toHaveBeenLastCalledWith({ jwsSigningKey: 'JWS PRIVKEY ROTATED' });

    // Assert rotatesAt is set correctly
    const currentState = service.getSnapshot();
    const rotatesAt = currentState.context.dfspJWS?.rotatesAt;
    expect(rotatesAt).toBeDefined();
    expect(rotatesAt).toBeGreaterThanOrEqual(beforeRotation + (opts.jwsRotationIntervalMs || 24 * 60 * 60 * 1000));
    expect(rotatesAt).toBeLessThanOrEqual(afterRotation + (opts.jwsRotationIntervalMs || 24 * 60 * 60 * 1000));

    service.stop();
  });

  test('should automatically rotate JWS after interval', async () => {
    // Set a short rotation interval for testing
    opts.jwsRotationIntervalMs = 100;

    let createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({ publicKey: 'JWS PUBKEY', privateKey: 'JWS PRIVKEY', createdAt }));

    const configUpdate = jest.fn();
    const service = startMachine(opts, configUpdate);

    await waitFor(service, (state) => state.matches('creatingJWS.idle'));

    // Check initial rotatesAt
    let currentState = service.getSnapshot();
    let rotatesAt = currentState.context.dfspJWS?.rotatesAt;
    expect(rotatesAt).toBeDefined();

    // Wait for automatic rotation
    createdAt = Math.floor(Date.now() / 1000);
    opts.vault.createJWS.mockImplementation(() => ({ publicKey: 'JWS PUBKEY AUTO', privateKey: 'JWS PRIVKEY AUTO', createdAt }));

    const beforeAutoRotation = Date.now();
    await waitFor(service, (state) => state.matches('creatingJWS.creating'), { timeout: 200 });
    await waitFor(service, (state) => state.matches('creatingJWS.idle'));
    const afterAutoRotation = Date.now();

    expect(opts.vault.createJWS).toHaveBeenCalledTimes(2);
    expect(opts.dfspCertificateModel.uploadJWS).toHaveBeenLastCalledWith({ publicKey: 'JWS PUBKEY AUTO', createdAt });
    expect(configUpdate).toHaveBeenLastCalledWith({ jwsSigningKey: 'JWS PRIVKEY AUTO' });

    // Assert rotatesAt is updated correctly after auto rotation
    currentState = service.getSnapshot();
    const newRotatesAt = currentState.context.dfspJWS?.rotatesAt;
    expect(newRotatesAt).toBeDefined();
    expect(newRotatesAt).toBeGreaterThan(rotatesAt!);
    expect(newRotatesAt).toBeGreaterThanOrEqual(beforeAutoRotation + opts.jwsRotationIntervalMs);
    expect(newRotatesAt).toBeLessThanOrEqual(afterAutoRotation + opts.jwsRotationIntervalMs);

    service.stop();
  });
});
