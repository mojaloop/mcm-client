/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

/** ************************************************************************
 *  (C) Copyright ModusBox Inc. 2019 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       James Bush - james.bush@modusbox.com                             *
 ************************************************************************* */

const http = require('http');
const https = require('https');
const util = require('util');
const stringify = require('safe-stable-stringify')
const { CONTENT_TYPES, ERROR_MESSAGES } = require('../constants');

const respErrSym = Symbol('ResponseErrorDataSym');

/**
 * An HTTPResponseError class
 */
class HTTPResponseError extends Error {
    constructor(params) {
        super(params.msg);
        this[respErrSym] = params;
    }

    getData() {
        return this[respErrSym];
    }

    toString() {
        return util.inspect(this[respErrSym]);
    }

    toJSON() {
        return stringify(this[respErrSym]);
    }
}

// Strip all beginning and end forward-slashes from each of the arguments, then join all the
// stripped strings with a forward-slash between them. If the last string ended with a
// forward-slash, append that to the result.
const buildUrl = (...args) => args
    .filter((e) => e !== undefined)
    .map((s) => s.replace(/(^\/*|\/*$)/g, '')) /* This comment works around a problem with editor syntax highglighting */
    .join('/')
        + ((args[args.length - 1].slice(-1) === '/') ? '/' : '');

const throwOrJson = (res) => {
    // TODO: will a 503 or 500 with content-length zero generate an error?
    // or a 404 for that matter?!

    if (res.headers?.['content-length'] === '0' || res.statusCode === 204) {
        // success but no content, return null
        return null;
    }
    if (res.statusCode < 200 || res.statusCode >= 300) {
        // not a successful request
        throw new HTTPResponseError({
            msg: `${ERROR_MESSAGES.nonSuccessStatusCode} ${res.statusCode}`,
            res,
        });
    }

    return res.data;
};

const defineAgent = (url) =>  {
    if (!url?.includes('http')) {
        throw new Error(ERROR_MESSAGES.noProtocolInUrl);
    }

    const httpModule = url.startsWith('https') ? https : http;
    // make sure we keep alive connections to the backend
    return new httpModule.Agent({
        keepAlive: true,
    });
}

const makeHeaders = (contentType) => {
    const headers = {
        'Content-Type': contentType,
        Accept: CONTENT_TYPES.json,
    };

    // clarify, why do we need this header
    if (process.env.HOST_HEADER_MCM_SERVER) {
        headers.host = process.env.HOST_HEADER_MCM_SERVER;
    }

    return headers;
}

const makeJsonHeaders = () => makeHeaders(CONTENT_TYPES.json);
const makeFormUrlEncodedHeaders = () => makeHeaders(CONTENT_TYPES.formUrlEncoded);

// RFC 6749 2.3.1 client_secret_basic: the URL-encoded client id and secret,
// base64-encoded as "id:secret", carried in the Authorization header
const makeBasicAuthHeader = (clientId, clientSecret) => `Basic ${Buffer.from(
    `${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`,
).toString('base64')}`;

module.exports = {
    HTTPResponseError,
    buildUrl,
    throwOrJson,
    defineAgent,
    makeJsonHeaders,
    makeFormUrlEncodedHeaders,
    makeBasicAuthHeader,
};
