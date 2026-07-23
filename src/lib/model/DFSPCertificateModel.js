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

class DFSPCertificateModel {
    constructor(opts) {
        this._dfspId = opts.dfspId;
        this._mcmServerRequest = new Requests({
            logger: opts.logger,
            hubEndpoint: opts.hubEndpoint,
            auth: opts.auth,
            additionalHeaders: {
                'X-DFSP-ID': this._dfspId,
            },
        });
        this.log = opts.logger.child({ model: this.constructor.name });
    }

    /**
     * Uploads DFSP CSR to MCM Server
     *
     * @param opts {object}
     * @param opts.csr {string}
     */
    async uploadCSR(opts) {
        const url = `/dfsps/${this._dfspId}/enrollments/inbound`;
        this.log.verbose('sending uploadCSR request to MCM...', { url })
        return this._mcmServerRequest.post(url, { clientCSR: opts.csr });
    }

    /**
     *
     * @param {object} opts
     * @param {number} opts.inboundEnrollmentId
     */
    async signInboundEnrollment(opts) {
        const url = `/dfsps/${this._dfspId}/enrollments/inbound/${opts.inboundEnrollmentId}/sign`;
        this.log.verbose('sending signInboundEnrollment request to MCM...', { url });
        return this._mcmServerRequest.post(url, {});
    }

    /**
     *
     * @param {object} opts
     * @param {number} opts.inboundEnrollmentId
     */
    async getClientCertificate(opts) {
        const url = `/dfsps/${this._dfspId}/enrollments/inbound/${opts.inboundEnrollmentId}`;
        this.log.verbose('sending getClientCertificate request to MCM...', { url });
        return this._mcmServerRequest.get(url);
    }

    /**
     * Gets uploaded DFSP CSRs and certificates from MCM Server
     *
     */
    async getCertificates() {
        const url = `/dfsps/${this._dfspId}/enrollments/inbound`;
        this.log.verbose('sending getCertificates request to MCM...', { url });
        return this._mcmServerRequest.get(url);
    }

    /**
     * Gets uploaded DFSP CA from MCM Server
     *
     */
    async getDFSPCA() {
        const url = `/dfsps/${this._dfspId}/ca`;
        this.log.verbose('sending getDFSPCA request to MCM...', { url });
        return this._mcmServerRequest.get(url);
    }

    /**
     * Uploads DFSP CA Root and Intermediate certificates to MCM Server
     *
     * @param opts {Object}
     */
    async uploadDFSPCA(opts) {
        const url = `/dfsps/${this._dfspId}/ca`;
        this.log.verbose('sending uploadDFSPCA request to MCM...', { url });
        return this._mcmServerRequest.post(url, opts);
    }

    /**
     * Get DFSP Server Certificate, Root and Intermediate certificates to MCM Server
     */
    async getDFSPServerCertificates() {
        const url = `/dfsps/${this._dfspId}/servercerts`;
        this.log.verbose('sending getDFSPServerCertificates request to MCM...', { url });
        return this._mcmServerRequest.get(url);
    }

    /**
     * Uploads DFSP Server Certificate, Root and Intermediate certificates to MCM Server
     *
     * @param opts {Object}
     */
    async uploadServerCertificates(opts) {
        const url = `/dfsps/${this._dfspId}/servercerts`;
        this.log.verbose('sending uploadServerCertificates request to MCM...', { url });
        return this._mcmServerRequest.post(url, opts);
    }

    /**
     * Uploads DFSP JWS Certificate, Root and Intermediate certificates to MCM Server
     *
     * @param opts {Object}
     */
    async uploadJWS(opts) {
        const url = `/dfsps/${this._dfspId}/jwscerts`;
        this.log.verbose('sending uploadJWS request to MCM...', { url });
        return this._mcmServerRequest.post(url, opts);
    }

    /**
     * Uploads DFSP JWS Certificate, Root and Intermediate certificates to MCM Server
     *
     * @param opts {Object}
     */
    async updateJWS(opts) {
        const url = `/dfsps/${this._dfspId}/jwscerts`;
        this.log.verbose('sending updateJWS request to MCM...', { url });
        return this._mcmServerRequest.put(url, opts);
    }

    /**
     * Deletes DFSP JWS Certificate from MCM Server
     *
     * @param opts {Object}
     */
    async deleteJWS(opts) {
        const url = `/dfsps/${this._dfspId}/jwscerts`;
        this.log.verbose('sending deleteJWS request to MCM...', { url });
        return this._mcmServerRequest.delete(url, opts);
    }

    /**
     * Uploads External JWS Certificates, connection manager will filter out if there are any JWS keys passed for native DFSPs just incase.
     *
     * @param opts {Object}
     */
    async uploadExternalDfspJWS(opts) {
        const url = `/external-dfsps/jwscerts`;
        this.log.verbose('sending uploadExternalDfspJWS request to MCM...', { url });
        return this._mcmServerRequest.post(url, opts);
    }

    /**
     * Get DFSP JWS Certificate, Root and Intermediate certificates from MCM Server
     */
    async getDFSPJWSCertificates() {
        const url = `/dfsps/${this._dfspId}/jwscerts`;
        this.log.verbose('sending getDFSPJWSCertificates request to MCM...', { url });
        return this._mcmServerRequest.get(url);
    }

    /**
     * Get *all* JWS Certificate, Root and Intermediate certificates from MCM Server
     */
    async getAllJWSCertificates() {
        const url = `/dfsps/jwscerts`;
        this.log.verbose('sending getAllJWSCertificates request to MCM...', { url });
        return this._mcmServerRequest.get(url);
    }
}

module.exports = DFSPCertificateModel;
