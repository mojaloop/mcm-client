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

class HubEndpointModel {
    constructor(opts) {
        this._mcmServerRequest = new Requests({
            logger: opts.logger,
            hubEndpoint: opts.hubEndpoint,
            auth: opts.auth,
        });
    }

    /**
     *
     * @param opts {Object}
     * @param opts.epId {string}
     */
    async findById(opts) {
        return this._mcmServerRequest.get(`/hub/endpoints/${opts.epId}`);
    }

    /**
     *
     * @param opts {Object}
     * @param [opts.direction] {string}
     * @param [opts.type] {string}
     * @param [opts.state] {string}
     */
    async findAll(opts) {
        const response = await this._mcmServerRequest.get(`/hub/endpoints`);
        const filters = [];

        if (opts.type) {
            filters.push((ep) => ep.type === opts.type);
        }

        if (opts.direction) {
            filters.push((ep) => ep.direction === opts.direction);
        }

        if (opts.state) {
            filters.push((ep) => ep.state === opts.state);
        }

        return response.filter((ep) => {
            const filterResult = filters.map((filter) => filter(ep));
            return !filterResult.includes(false);
        });
    }
}

module.exports = HubEndpointModel;
