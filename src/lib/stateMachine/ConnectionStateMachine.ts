/**************************************************************************
 *  (C) Copyright Mojaloop Foundation 2022                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 **************************************************************************/

import { createHash } from 'node:crypto';
import { createMachine, interpret, State, StateMachine } from 'xstate';
import { ActionObject } from 'xstate/lib/types';
import { inspect } from '@xstate/inspect/lib/server';
import WebSocket from 'ws';
import logger from '../logger'

import {
  DfspJWS,
  PeerJWS,
  DfspCA,
  DfspClientCert,
  DfspServerCert,
  HubCA,
  HubCert,
  ConnectorConfig,
  EndpointConfig,
  ProgressMonitor,
  PeerJWSNotify,
  UploadPeerJWS,
} from './states';

import { MachineOpts } from './states/MachineOpts';
import { EXTERNAL_EVENT_TYPES } from './constants';

type Context = PeerJWS.Context &
  DfspJWS.Context &
  DfspCA.Context &
  DfspClientCert.Context &
  DfspServerCert.Context &
  HubCert.Context &
  HubCA.Context &
  ConnectorConfig.Context &
  UploadPeerJWS.Context &
  PeerJWSNotify.Context &
  EndpointConfig.Context &
  ProgressMonitor.Context;

type Event =
  | PeerJWS.Event
  | DfspJWS.Event
  | DfspCA.Event
  | DfspClientCert.Event
  | DfspServerCert.Event
  | HubCert.Event
  | HubCA.Event
  | ConnectorConfig.Event
  | UploadPeerJWS.Event
  | PeerJWSNotify.Event
  | EndpointConfig.Event
  | ProgressMonitor.Event;

type ActionType = ActionObject<Context, Event>;

type StateMachineType = StateMachine<Context, any, Event>;

class ConnectionStateMachine {
  private static VERSION = 3;
  private started: boolean = false;
  private reportStatesStatusTimeout: NodeJS.Timeout | null = null;

  private readonly hash: string;
  private service: any; // todo: define type
  private readonly opts: MachineOpts;
  private context?: Context;
  private actions: Record<string, ActionType> = {};

  protected log = logger.child({ component: this.constructor.name })

  constructor(opts: MachineOpts) {
    this.opts = opts;
    this.serve();

    const machine = this.createMachine(opts);
    this.hash = ConnectionStateMachine.createHash(machine);

    this.service = interpret(machine, { devTools: true });
    this.service.onTransition(this.handleTransition.bind(this));
  }

  private handleTransition(state: State<Context, Event>) {
    this.opts.logger.push({ state: state.value }).debug('Transition');
    this.context = state.context;
    this.updateActions(state.actions);
    this.setState(state);
  }

  private setState(state: State<Context, Event>) {
    // (?) think if we need to add state format validation
    const log = this.log.child({ eventType: state.event?.type });

    const needToStore = this.needToStoreState(state);
    if (!needToStore) {
      log.verbose('skip setStateMachineState in vault secrets');
      return;
    }

    log.info(`setStateMachineState in vault secrets...`);
    this.opts.vault
      .setStateMachineState({
        state,
        hash: this.hash,
        version: ConnectionStateMachine.VERSION,
        actions: this.actions,
      })
      .catch((err) => {
        log.error('error in setStateMachineState to vault: ', err);
        // (?) think what to do with this error
      });
  }

  private needToStoreState(state: State<Context, Event>) {
    const { type = '' } = state?.event || {}
    const isExternal = EXTERNAL_EVENT_TYPES.includes(type)
    this.log.debug(`isExternal event: ${isExternal}`, { isExternal, event: state.event })
    return isExternal;
  }

  private updateActions(acts: Array<ActionType>) {
    this.opts.logger.debug('updateActions...', { acts });
    acts.forEach((action) => {
      if (action.type === 'xstate.cancel') {
        delete this.actions[action.sendId];
      }
      if (action.event?.type?.startsWith('xstate.after')) {
        this.actions[action.id] = action;
      }
      if (action.activity?.type === 'xstate.invoke') {
        if (action.type === 'xstate.stop') {
          delete this.actions[action.activity.id];
        }
        if (action.type === 'xstate.start') {
          this.actions[action.activity.id] = action;
        }
      }
    });
  }

  public sendEvent(event: Event) {
    this.service.send(event);
  }

  public async start() {
    const state = await this.opts.vault.getStateMachineState();
    const isPrevious =
      state?.hash === this.hash &&
      state?.version === ConnectionStateMachine.VERSION;

    if (isPrevious) {
      this.opts.logger.info('Restoring state machine from previous state');
      this.actions = state.actions;
      this.service.start({
        ...state.state,
        actions: Object.values(this.actions),
      });
    } else {
      const reason = state
        ? 'state machine changed'
        : 'no previous state found';
      this.opts.logger.info(`Starting state machine from scratch because ${reason}`);
      this.service.start();
    }

    this.started = true;
    this.reportStatesStatus();
  }

  public stop() {
    this.started = false;
    this.service.stop();
    if (this.reportStatesStatusTimeout) clearTimeout(this.reportStatesStatusTimeout);
  }

  getState(formatted = false) {
    const states = this.service.state.context.progressMonitor;

    return !formatted ? states : Object.entries(states).reduce((acc, [key, value]) => {
      const { status, stateDescription, lastUpdated, error } = value as {
        status: string;
        stateDescription: string;
        lastUpdated: string;
        error: string;
      };
      acc[key] = {
        status,
        stateDescription,
        lastUpdated: new Date(lastUpdated).toISOString(),
        ...(error && { errorDescription: `${error}` }),
      };
      return acc;
    }, {});
  }

  public async restart() {
    this.opts.logger.info('Restarting state machine from scratch');

    // Stop the current state machine
    this.stop();
    this.opts.logger.info('State machine stopped');

    // Clear the vault state
    try {
      await this.opts.vault.deleteStateMachineState();
      this.opts.logger.info('Vault state removed');
      const vaultState = await this.opts.vault.getStateMachineState();
      if (vaultState !== undefined) {
        this.opts.logger.warn('Vault state not fully cleared');
      }
    } catch (err) {
      this.opts.logger.error('Failed to clear state machine state', err);
      throw new Error(
        'Cannot restart state machine: failed to clear vault state',
      );
    }

    // Reset internal state
    this.actions = {};
    this.context = undefined;

    // Start the machine and force initial state
    const machine = this.createMachine(this.opts);
    if (this.hash !== ConnectionStateMachine.createHash(machine)) {
      this.opts.logger.warn('Hashes does not match');
    }
    this.service = interpret(machine, { devTools: true });
    this.service.onTransition(this.handleTransition.bind(this));

    await this.start();
  }

  public getContext() {
    return this.context;
  }

  private serve() {
    if (this.opts.config.stateMachineInspectEnabled) {
      const { port } = this.opts;
      inspect({
        server: new WebSocket.Server({ port }),
      });
      this.opts.logger.verbose(
        `StateMachine introspection URL: https://stately.ai/viz?inspect&server=ws://localhost:${port}`,
      );
    }
  }

  private createMachine(opts: MachineOpts): StateMachineType {
    return createMachine<Context, Event>(
      {
        id: 'machine',
        context: {},
        type: 'parallel',
        states: {
          fetchingHubCA: HubCA.createState<Context>(opts),
          creatingDFSPCA: DfspCA.createState<Context>(opts),
          creatingDfspClientCert: DfspClientCert.createState<Context>(opts),
          creatingDfspServerCert: DfspServerCert.createState<Context>(opts),
          creatingHubClientCert: HubCert.createState<Context>(opts),
          pullingPeerJWS: PeerJWS.createState<Context>(opts),
          uploadingPeerJWS: UploadPeerJWS.createState<Context>(opts),
          notifyingPeerJWS: PeerJWSNotify.createState<Context>(opts),
          creatingJWS: DfspJWS.createState<Context>(opts),
          endpointConfig: EndpointConfig.createState<Context>(opts),
          connectorConfig: ConnectorConfig.createState<Context>(opts),
          progressMonitor: ProgressMonitor.createState<Context>(opts),
        },
      },
      {
        guards: {
          ...PeerJWS.createGuards<Context>(),
          // ...DfspJWS.createGuards<Context>(),
          ...DfspClientCert.createGuards<Context>(opts),
          ...DfspServerCert.createGuards<Context>(opts),
          // ...DfspCA.createGuards<Context>(),
          ...HubCert.createGuards<Context>(),
          ...HubCA.createGuards<Context>(),
          ...EndpointConfig.createGuards<Context>(opts),
          ...ProgressMonitor.createGuards<Context>(opts),
        },
        actions: {
          // ...ConnectorConfig.createActions<Context>(),
        },
      },
    );
  }

  private reportStatesStatus() {
    const { dfspEndpointModel, logger, reportStatesStatusIntervalSeconds = 60 } = this.opts;
    const states = this.getState(true);
    dfspEndpointModel.uploadDfspStatesStatus(states)
      .then((result) => { logger.debug('States status uploaded:', { result }); })
      .catch((err) => { logger.warn('Failed to upload states status: ', err); })
      .finally(() => {
        this.reportStatesStatusTimeout = setTimeout(() => this.reportStatesStatus(), reportStatesStatusIntervalSeconds * 1000);
      })
  }

  static createHash(machine: StateMachineType) {
    return createHash('sha256')
      .update(JSON.stringify(machine.config.states))
      .digest('base64');
  }
}

export { ConnectionStateMachine };
