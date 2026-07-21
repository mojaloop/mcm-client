/* eslint-disable */
// TODO: Remove previous line and work through linting issues at next edit

/** ************************************************************************
 *  (C) Copyright ModusBox Inc. 2020 - All rights reserved.               *
 *                                                                        *
 *  This file is made available under the terms of the license agreement  *
 *  specified in the corresponding source code repository.                *
 *                                                                        *
 *  ORIGINAL AUTHOR:                                                      *
 *       Jose Sanchez - jose.sanchez@modusbox.com                   *
 ************************************************************************* */

const { JWTClient } = require('../requests/jwt');

class AuthModel {
    constructor(opts) {
        this._storage = opts.storage;
        this._jwt = new JWTClient({
            auth: opts.auth,
            logger: opts.logger,
            hubIamProviderUrl: opts.hubIamProviderUrl,
            oidcTokenRoute: opts.oidcTokenRoute,
            oidcGrantType: opts.oidcGrantType,
            oidcScope: opts.oidcScope,
            oidcAudience: opts.oidcAudience,
        });
    }

    async login() {
        await this._jwt.login();
    }

    getToken() {
        return this._jwt.getToken();
    }

    destroy() {
        this._jwt.destroy();
    }
}

module.exports = AuthModel;
