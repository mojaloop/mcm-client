/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

/** ************************************************************************
 *  (C) Copyright ModusBox Inc. 2019 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Murthy Kakarlamudi - murthy@modusbox.com                             *
 ************************************************************************* */

const retry = require('async-retry');
const stringify = require('safe-stable-stringify')
const { request } = require('@mojaloop/sdk-standard-components');
const { AUTH_HEADER, DEFAULT_RETRIES_COUNT } = require('../constants');
const {
    buildUrl, throwOrJson, makeJsonHeaders, HTTPResponseError, defineAgent,
} = require('./common');


/**
 * A class for making requests to DFSP backend API
 */
class Requests {
    constructor(config) {
        this.config = config;
        this.logger = config.logger;
        this.retries = config.retries ?? DEFAULT_RETRIES_COUNT;
        this.additionalHeaders = config.additionalHeaders;
        this.auth = config.auth;
        // Switch or peer DFSP endpoint
        this.hubEndpoint = config.hubEndpoint;

        this.agent = defineAgent(this.hubEndpoint);
    }

    /**
     * Utility function for building outgoing request headers as required by the mojaloop api spec
     *
     * @returns {object} - headers object for use in requests to mojaloop api endpoints
     */
    _buildHeaders() {
        const token = this.auth?.getToken();

        const headers = makeJsonHeaders();

        if (token) {
            headers[AUTH_HEADER] = `Bearer ${token}`;
        }
        // Add any additional headers
        if (this.additionalHeaders) {
            Object.entries(this.additionalHeaders).forEach(([key, value]) => {
                headers[key] = value;
            });
        }

        return headers;
    }

    async get(url) {
        return this.#sendRequestWithRetry(url, 'GET');
    }

    async delete(url) {
        return this.#sendRequestWithRetry(url, 'DELETE');
    }

    async put(url, body) {
        return this.#sendRequestWithRetry(url, 'PUT', body);
    }

    async post(url, body) {
        return this.#sendRequestWithRetry(url, 'POST', body);
    }

    async #sendRequestWithRetry(url, method, body = null) {
        return await retry(async () => {
            const headers = this._buildHeaders();
            const uri = buildUrl(this.hubEndpoint, url);
            const reqOpts = {
                method,
                uri,
                headers,
                ...(body ? { body: stringify(body) } : null),
            };
            this.logger.push({ reqOpts }).debug(`Executing HTTP ${method}`);

            try {
                const data = throwOrJson(await request({ ...reqOpts, agent: this.agent }));
                this.logger.debug(`#sendRequestWithRetry is done: `, { data });
                return data;
            } catch (error) {
                const { statusCode } = error?.getData?.().res || error || {};
                this.logger.error(`Error attempting HTTP ${method} statusCode: ${statusCode}`, error);
                if ([401, 403].includes(statusCode)) {
                    this.logger.info(`Retrying login due to error statusCode: ${statusCode}`);
                    await this.auth?.login();
                }
                throw error;
            }
        }, {
            retries: this.retries,
        });
    }
}

module.exports = {
    Requests,
    HTTPResponseError,
};
