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

/**
 * Namespace for DFSP JWS state machine logic.
 *
 * @remarks
 * This namespace defines types and a state machine configuration for managing
 * the lifecycle of DFSP JWS (JSON Web Signature) keys, including creation,
 * rotation, and propagation to the hub.
 *
 * The state machine consists of the following states:
 * - `idle`: Waits for the rotation interval before transitioning to `creating`.
 * - `creating`: Handles JWS key creation and updates the context with new key data.
 * - `uploadingToHub`: Uploads the public key to the hub and signals propagation.
 *
 * @param opts - Options for configuring the state machine, including rotation interval,
 * logger, vault service, and certificate model.
 *
 * @type Context - The context object containing the current DFSP JWS key data.
 * @type Event - The union of possible events handled by the state machine.
 * @function createState - Returns the state machine configuration.
 *
 */
export namespace DfspJWS {
  export type Context = {
    dfspJWS?: {
      publicKey: string;
      privateKey: string;
      createdAt: number;
      rotatesAt: number;
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
        after: [
          {
            // Wait until rotatesAt, then transition to creating
            delay: (ctx: TContext) => {
              // ctx.dfspJWS is always defined in 'idle' state
              const now = Date.now();
              const delayMs = ctx.dfspJWS!.rotatesAt - now;
              // If rotatesAt is in the past, rotate immediately
              return Math.max(delayMs, 0);
            },
            target: 'creating'
          }
        ]
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
                dfspJWS: (context, event) => {
                  const jwsRotationIntervalMs = opts.jwsRotationIntervalMs || 24 * 60 * 60 * 1000;
                  const createdAt = event.data.createdAt;
                  return {
                    ...event.data,
                    rotatesAt: (createdAt * 1000) + jwsRotationIntervalMs,
                  };
                }
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
