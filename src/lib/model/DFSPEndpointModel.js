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

class DFSPEndpointModel {
    constructor(opts) {
        this._dfspId = opts.dfspId;
        this._hubRequest = new Requests({
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
        // TODO: We don't need dfspId here as there is no combined dfspId+epId primary key on Mgmt API side
        return this._hubRequest.get(`/dfsps/${this._dfspId}/endpoints/${opts.epId}`);
    }

    /**
     *
     * @param opts {Object}
     * @param [opts.direction] {string}
     * @param [opts.type] {string}
     * @param [opts.state] {string}
     */
    async findAll(opts) {
        const response = await this._hubRequest.get(`/dfsps/${this._dfspId}/endpoints`);
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

    /**
     * Creates dfsp endpoint item
     *
     * @param opts {Object}
     * @param opts.direction {Enum 'INGRESS' or 'EGRESS'}
     * @param [opts.ipList] {Array}
     * @param [opts.url] {string}
     */

    async create(opts) {
        const directionUrlPart = {
            INGRESS: 'ingress',
            EGRESS: 'egress',
        };

        let url = `/dfsps/${this._dfspId}/endpoints`;
        url += `/${directionUrlPart[opts.direction]}`;

        const entry = {};

        if (opts.direction === 'EGRESS') {
            entry.ipList = opts.ipList;
        } else if (opts.direction === 'INGRESS') {
            entry.url = opts.url;
        }

        return this._hubRequest.post(url, entry);
    }

    /**
     *
     * @param opts {Object}
     * @param opts.epId {string}
     */
    async delete(opts) {
        return this._hubRequest.delete(`/dfsps/${this._dfspId}/endpoints/${opts.epId}`);
    }

    /**
     * Creates dfsp endpoint item
     *
     * @param opts {Object}
     * @param [opts.direction] {Enum 'INGRESS' or 'EGRESS'}
     * @param [opts.type] {Enum 'IP' or 'URL'}
     * @param [opts.epId] {string}
     * @param [opts.ports] {Array<number>}
     * @param opts.address {string}
     */
    async update(opts) {
        const directionUrlPart = {
            INGRESS: 'ingress',
            EGRESS: 'egress',
        };
        const typeUrlPart = {
            IP: 'ips',
            URL: 'urls',
        };

        let url = `/dfsps/${this._dfspId}/endpoints`;
        url += `/${directionUrlPart[opts.direction]}`;
        url += `/${typeUrlPart[opts.type]}`;
        url += `/${opts.epId}`;

        const entry = {};

        if (opts.type === 'IP') {
            entry.value = {
                address: opts.address,
                ports: opts.ports,
            };
        } else if (opts.type === 'URL') {
            entry.value = {
                url: opts.address,
            };
        }

        return this._hubRequest.put(url, entry);
    }

    async uploadDfspStatesStatus(states) {
        return this._hubRequest.post(`/dfsps/${this._dfspId}/states`, states);
    }
}

module.exports = DFSPEndpointModel;
