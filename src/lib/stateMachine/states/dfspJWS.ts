/** ************************************************************************
 *  (C) Copyright Mojaloop Foundation 2022                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 ************************************************************************* */

import { assign, send, MachineConfig, DoneEventObject } from 'xstate';
import { MachineOpts } from './MachineOpts';
import { invokeRetry } from './invokeRetry';

export namespace DfspJWS {
  export type Context = {
    dfspJWS?: {
      publicKey: string;
      privateKey: string;
      createdAt: number;
      jwsRotationIntervalMs: number;
    };
  };

  export type Event =
    | DoneEventObject
    | { type: 'CREATE_JWS' | 'DFSP_JWS_PROPAGATED' }
    | { type: 'CREATING_DFSP_JWS' }
    | { type: 'UPLOADING_DFSP_JWS_TO_HUB' }
    | { type: 'ROTATE_JWS' };

  export const createState = <TContext extends Context>(opts: MachineOpts): MachineConfig<TContext, any, Event> => ({
    id: 'createJWS',
    initial: 'creating',
    on: {
      CREATE_JWS: { target: '.creating', internal: false },
      ROTATE_JWS: { target: '.creating', internal: false },
    },
    states: {
      idle: {
        after: {
          [opts.jwsRotationIntervalMs || 24 * 60 * 60 * 1000]: { target: 'creating' }
        },
      },
      creating: {
        entry: send('CREATING_DFSP_JWS'),
        invoke: {
          id: 'dfspJWSCreate',
          src: () =>
            invokeRetry({
              id: 'dfspJWSCreate',
              logger: opts.logger,
              retryInterval: opts.refreshIntervalSeconds * 1000,
              machine: 'DFSP_JWS',
              state: 'creating',
              service: async () => opts.vault.createJWS(),
            }),
          onDone: {
            target: 'uploadingToHub',
            actions: [
              assign({
                dfspJWS: (context, event) => ({
                  ...event.data,
                  jwsRotationIntervalMs: opts.jwsRotationIntervalMs || 24 * 60 * 60 * 1000,
                })
              }),
              send((ctx) => ({
                type: 'UPDATE_CONNECTOR_CONFIG',
                config: { jwsSigningKey: ctx.dfspJWS!.privateKey },
              })),
            ],
          },
        },
      },
      uploadingToHub: {
        entry: send('UPLOADING_DFSP_JWS_TO_HUB'),
        invoke: {
          id: 'dfspJWSUpload',
          src: (ctx) =>
            invokeRetry({
              id: 'dfspJWSUpload',
              logger: opts.logger,
              retryInterval: opts.refreshIntervalSeconds * 1000,
              machine: 'DFSP_JWS',
              state: 'uploadingToHub',
              service: async () =>
                opts.dfspCertificateModel.uploadJWS({
                  publicKey: ctx.dfspJWS!.publicKey,
                  createdAt: ctx.dfspJWS!.createdAt,
                }),
            }),
          onDone: {
            target: 'idle',
            actions: send('DFSP_JWS_PROPAGATED'),
          },
        },
      },
    },
  });
}
