/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

/** ************************************************************************
 *  (C) Copyright ModusBox Inc. 2020 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Murthy Kakarlamudi - murthy@modusbox.com                   *
 ************************************************************************* */

const { Requests } = require('../requests');

class DFSPConfigModel {
    constructor(opts) {
        this._dfspId = opts.dfspId;
        this._mcmServerRequest = new Requests({
            logger: opts.logger,
            hubEndpoint: opts.hubEndpoint,
            auth: opts.auth,
        });
    }

    /**
     * Gets DFSPs details from MCM Server
     *
     */
    async getDFSPList() {
        const url = `/dfsps`;
        return this._mcmServerRequest.get(url);
    }

    async findStatus() {
        return this._mcmServerRequest.get(`/dfsps/${this._dfspId}/status`);
    }

    /**
     * Gets DFSPs details from MCM Server by MonetaryZone
     *
     * @param opts {object}
     * @param opts.monetaryZoneId {string}
     */
    async getDFSPListByMonetaryZone(opts) {
        const url = `/monetaryzones/${opts.monetaryZoneId}/dfsps`;
        return this._mcmServerRequest.get(url);
    }
}

module.exports = DFSPConfigModel;
