/** ************************************************************************
 *  (C) Copyright Mojaloop Foundation 2022                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 ************************************************************************* */

import { AnyEventObject, assign, DoneEventObject, MachineConfig, send } from 'xstate';
import { MachineOpts } from './MachineOpts';
import { invokeRetry } from './invokeRetry';

export namespace DfspClientCert {
  export interface Context {
    dfspClientCert?: {
      id?: number;
      csr?: string;
      cert?: string;
      privateKey?: string;
      expireTime?: string;
      notBefore?: string;
      notAfter?: string;
    };
  }

  export type Event =
    | DoneEventObject
    | { type: 'DFSP_CLIENT_CERT_CONFIGURED' }
    | { type: 'RECREATE_DFSP_CLIENT_CERT' }
    | { type: 'CREATING_DFSP_CSR' }
    | { type: 'UPLOADING_DFSP_CSR' }
    | { type: 'FETCHING_DFSP_CLIENT_CERT' }
    | { type: 'COMPLETING_DFSP_CLIENT_CERT' };

  enum CertState {
    CERT_SIGNED = 'CERT_SIGNED',
  }

  export const createState = <TContext extends Context>(opts: MachineOpts): MachineConfig<TContext, any, Event> => ({
    id: 'dfspClientCert',
    initial: 'creatingDfspCsr',
    on: {
      CREATE_DFSP_CLIENT_CERT: { target: '.creatingDfspCsr', internal: false },
    },
    states: {
      creatingDfspCsr: {
        entry: send('CREATING_DFSP_CSR'),
        invoke: {
          id: 'createCsr',
          src: () =>
            invokeRetry({
              id: 'createCsr',
              logger: opts.logger,
              retryInterval: opts.refreshIntervalSeconds * 1000,
              machine: 'DFSP_CLIENT_CERT',
              state: 'creatingDfspCsr',
              service: async () => opts.vault.createCSR(),
            }),
          onDone: {
            actions: assign({
              dfspClientCert: (ctx, { data }) => data,
            }),
            target: 'uploadingDfspCsr',
          },
        },
      },
      uploadingDfspCsr: {
        entry: send('UPLOADING_DFSP_CSR'),
        invoke: {
          id: 'uploadCsr',
          src: (ctx) =>
            invokeRetry({
              id: 'uploadCsr',
              logger: opts.logger,
              retryInterval: opts.refreshIntervalSeconds * 1000,
              machine: 'DFSP_CLIENT_CERT',
              state: 'uploadingDfspCsr',
              service: () => opts.dfspCertificateModel.uploadCSR({ csr: ctx.dfspClientCert!.csr! }),
            }),
          onDone: {
            actions: assign({
              dfspClientCert: (ctx, { data }): any => ({
                ...ctx.dfspClientCert,
                id: data.id,
              }),
            }),
            target: 'gettingDfspClientCert',
          },
        },
      },
      gettingDfspClientCert: {
        entry: send('FETCHING_DFSP_CLIENT_CERT'),
        invoke: {
          id: 'getDfspClientCert',
          src: (ctx) =>
            invokeRetry({
              id: 'getDfspClientCert',
              logger: opts.logger,
              retryInterval: opts.refreshIntervalSeconds * 1000,
              machine: 'DFSP_CLIENT_CERT',
              state: 'gettingDfspClientCert',
              service: () =>
                opts.dfspCertificateModel.getClientCertificate({ inboundEnrollmentId: ctx.dfspClientCert!.id! }),
            }),
          onDone: [
            {
              target: 'completed',
              cond: 'hasNewDfspClientCert',
              actions: [
                assign({
                  dfspClientCert: (context, { data }): any => ({
                    ...context.dfspClientCert,
                    cert: data.certificate,
                    notAfter: data.certInfo?.notAfter,
                    notBefore: data.certInfo?.notBefore,
                  }),
                }),
                send((ctx) => ({
                  type: 'UPDATE_CONNECTOR_CONFIG',
                  config: {
                    outbound: {
                      tls: {
                        creds: {
                          cert: ctx.dfspClientCert!.cert,
                          key: ctx.dfspClientCert!.privateKey,
                        },
                      },
                    },
                  },
                })),
              ],
            },
            {
              target: 'creatingDfspCsr',
              cond: 'isDfspClientCertExpiring',
            },
            { target: 'completed' },
          ],
        },
      },
      completed: {
        entry: send('COMPLETING_DFSP_CLIENT_CERT'),
        always:  [
          {
            target: 'retry',
            cond:'hasCert',
            actions: send('DFSP_CLIENT_CERT_CONFIGURED'),
          },
          { target: 'retry' },
        ]
      },
      retry: {
        after: {
          [opts.refreshIntervalSeconds * 1000]: { target: 'gettingDfspClientCert' },
        },
      },
    },
  });

  export const createGuards = <TContext extends Context>(opts: MachineOpts) => ({
    hasNewDfspClientCert: (ctx: TContext, event: AnyEventObject) =>
      event.data?.state === CertState.CERT_SIGNED && event.data.certificate !== ctx.dfspClientCert!.cert,
    isDfspClientCertExpiring: (ctx: TContext, event: AnyEventObject) => {
        if (
            event.data?.state === CertState.CERT_SIGNED &&
            event.data.certificate === ctx.dfspClientCert!.cert &&
            event.data.certInfo?.notAfter
        ) {
            const expiryDate = new Date(event.data.certInfo.notAfter);
            const now = new Date();
            const thresholdDays = opts.certExpiryThresholdDays ?? 7;
            const thresholdDate = new Date(now.getTime() + thresholdDays * 24 * 60 * 60 * 1000);
            return expiryDate <= thresholdDate;
        }
        return false;
    },
    hasCert: (ctx: TContext) => !!ctx.dfspClientCert?.cert && !!ctx.dfspClientCert?.privateKey,
  });
}
