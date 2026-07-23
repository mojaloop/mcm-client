/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

/** ************************************************************************
 *  (C) Copyright ModusBox Inc. 2020 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Damián García - damian.garcia@modusbox.com                       *
 ************************************************************************* */

const { Requests } = require('../requests');

class MonetaryZoneModel {
    constructor(opts) {
        this._logger = opts.logger;
        this._hubEndpoint = opts.hubEndpoint;
        this._mcmServerRequest = new Requests({
            logger: opts.logger,
            hubEndpoint: opts.hubEndpoint,
            auth: opts.auth,
        });
    }

    /**
     * Returns the monetary zones supported from MCM Server
     */
    async getMonetaryZones() {
        const url = '/monetaryzones';
        return this._mcmServerRequest.get(url);
    }

    /**
     * Returns all the dfsps for that monetary zone
     */
    async getDfspsByMonetaryZone() {
        const url = '/monetaryzones';
        return this._mcmServerRequest.get(url);
    }
}

module.exports = MonetaryZoneModel;
