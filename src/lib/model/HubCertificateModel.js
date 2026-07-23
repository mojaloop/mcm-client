/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

/** ************************************************************************
 *  (C) Copyright ModusBox Inc. 2020 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Yevhen Kyriukha - yevhen.kyriukha@modusbox.com                   *
 ************************************************************************* */

const { Requests } = require('../requests');

class HubCertificateModel {
    constructor(opts) {
        this._dfspId = opts.dfspId;
        this._mcmServerRequest = new Requests({
            logger: opts.logger,
            hubEndpoint: opts.hubEndpoint,
            auth: opts.auth,
        });
    }

    /**
     * Gets Hub CA list from MCM Server
     *
     */
    async getHubCA() {
        const url = `/hub/ca`;
        return this._mcmServerRequest.get(url);
    }

    /**
     * Gets Hub Client CSRs and certificates from MCM Server
     *
     * @param [state] {('CERT_SIGNED'|'CSR_LOADED')}
     */
    async getClientCerts(state) {
        const url = `/dfsps/${this._dfspId}/enrollments/outbound${state ? `?state=${state}` : ''}`;
        return this._mcmServerRequest.get(url);
    }

    /**
     * Gets Hub server certificates from MCM Server
     *
     */
    async getServerCertificates() {
        const url = `/hub/servercerts`;
        return this._mcmServerRequest.get(url);
    }

    /**
     * Uploads DFSP Server Certificate, Root and Intermediate certificates to MCM Server
     *
     * @param opts {Object}
     * @param [opts.enId] {string}
     * @param [opts.entry] {object}
     */
    async uploadServerCertificate(opts) {
        const url = `/dfsps/${this._dfspId}/enrollments/outbound/${opts.enId}/certificate`;
        return this._mcmServerRequest.post(url, opts.entry);
    }
}

module.exports = HubCertificateModel;
