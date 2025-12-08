/**************************************************************************
 *  (C) Copyright Mojaloop Foundation 2022                                *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha <yevhen.kyriukha@modusbox.com>                   *
 *  CONTRIBUTORS:                                                         *
 *       James Bush <jbush@mojaloop.io>                                   *
 **************************************************************************/

import SDK from '@mojaloop/sdk-standard-components';
import { DFSPCertificateModel, DFSPEndpointModel, HubCertificateModel, HubEndpointModel } from '../../model';
import * as ControlServer from '@app/lib/ControlServer';
import Vault from '../../vault';

export interface MachineOpts {
  logger: SDK.Logger.SdkLogger;
  vault: Vault;
  refreshIntervalSeconds: number;
  reportStatesStatusIntervalSeconds?: number;
  certExpiryThresholdDays?: number;
  dfspCertificateModel: DFSPCertificateModel;
  dfspEndpointModel: DFSPEndpointModel;
  hubCertificateModel: HubCertificateModel;
  hubEndpointModel: HubEndpointModel;
  ControlServer: typeof ControlServer;
  port: number;
  config: any;
  certManager?: any;
  jwsRotationIntervalMs?: number;
}
