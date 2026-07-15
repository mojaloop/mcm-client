/* eslint-disable no-constructor-return, import/no-extraneous-dependencies */
const querystring = require('querystring');
const { request } = require('@mojaloop/sdk-standard-components');

const { ERROR_MESSAGES, OIDC_TOKEN_ROUTE, OIDC_GRANT_TYPE } = require('../constants');
const { oidcPayloadDto, oidcRefreshPayloadDto } = require('../dto');
const {
    buildUrl, defineAgent, makeFormUrlEncodedHeaders, makeBasicAuthHeader,
} = require('./common');

class JWTSingleton {
    constructor(opts) {
        if (JWTSingleton.instance) {
            return JWTSingleton.instance;
        }

        this._logger = opts.logger.child({ component: this.constructor.name });

        this._auth = opts.auth;
        if (opts.auth.enabled) {
            this._hubIamProviderUrl = opts.hubIamProviderUrl;
            this._oidcTokenRoute = opts.oidcTokenRoute || OIDC_TOKEN_ROUTE;
            this._oidcGrantType = opts.oidcGrantType || OIDC_GRANT_TYPE;
            this._oidcScope = opts.oidcScope; // e.g. 'email profile'
            this._tokenRefreshTimeout = null;

            this.agent = defineAgent(this._hubIamProviderUrl);
        }

        JWTSingleton.instance = this;

        return this;
    }

    async login() {
        if (!this._auth.enabled) {
            return;
        }
        const route = this._oidcTokenRoute;
        const headers = this._tokenRequestHeaders();

        const payload = oidcPayloadDto(this._oidcGrantType, this._oidcScope);
        const postData = querystring.stringify(payload);

        this.token = await this.post(route, postData, headers);

        this._scheduleTokenRefresh();

        this._logger.info('login is done');
    }

    getToken() {
        return this.token;
    }

    _tokenRequestHeaders() {
        const { clientId, clientSecret } = this._auth.creds || {};
        return {
            ...makeFormUrlEncodedHeaders(),
            Authorization: makeBasicAuthHeader(clientId, clientSecret),
        };
    }

    async refreshAccessToken() {
        if (!this._auth.enabled) {
            this._logger.warn('refresh accessToken not possible - auth disabled');
            return null;
        }

        if (!this._refreshToken) {
            this._logger.info('refresh accessToken not possible - no refresh token available, falling back to full login');
            return this.login();
        }

        try {
            const route = this._oidcTokenRoute;
            const headers = this._tokenRequestHeaders();

            const payload = oidcRefreshPayloadDto(this._refreshToken);
            const postData = querystring.stringify(payload);

            this._logger.info('Refreshing access token...');
            this.token = await this.post(route, postData, headers);

            this._logger.info('Token refresh successful');
            return this.token;
        } catch (error) {
            this._logger.error('Token refresh failed, falling back to full login:', error);
            return this.login();
        }
    }

    isTokenExpired(bufferSeconds = 5) {
        if (!this._tokenExpiresAt) {
            return true;
        }
        return Date.now() >= (this._tokenExpiresAt - (bufferSeconds * 1000));
    }

    getTokenExpiryInfo() {
        return {
            isExpired: this.isTokenExpired(),
            expiresAt: this._tokenExpiresAt || null,
            lifeTime: this._tokenLifeTime || undefined,
            refreshToken: this._refreshToken || null,
            hasRefreshToken: !!this._refreshToken,
        };
    }

    async post(route, body, headers) {
        try {
            const reqOpts = {
                method: 'POST',
                uri: buildUrl(this._hubIamProviderUrl, route),
                headers,
            };
            this._logger.push({ reqOpts }).verbose('Executing Login...');

            const { statusCode, data } = await request({ ...reqOpts, body, agent: this.agent });

            if (statusCode !== 200) {
                const errMessage = ERROR_MESSAGES.loginErrorInvalidStatusCode;
                this._logger.push({ statusCode, data }).warn(errMessage);
                throw new Error(errMessage);
            }
            if (!data?.access_token) {
                throw new Error(ERROR_MESSAGES.loginErrorNoToken);
            }

            // Storing the token expiry information for refresh scheduling
            this._tokenLifeTime = data.expires_in;

            // Validate expires_in is a valid number before calculating expiry time
            if (typeof data.expires_in === 'number' && data.expires_in > 0) {
                this._tokenExpiresAt = Date.now() + (data.expires_in * 1000);
            } else {
                this._logger.warn('Invalid or missing expires_in value in token response:', data.expires_in);
                this._tokenExpiresAt = null;
            }

            this._refreshToken = data.refresh_token;

            return data.access_token;
        } catch (error) {
            this._logger.error('Error Login: ', error);
            throw error;
        }
    }

    destroy() {
        if (this._tokenRefreshTimeout) {
            clearTimeout(this._tokenRefreshTimeout);
            this._tokenRefreshTimeout = null;
        }
        this.token = null;
        this._refreshToken = null;
        this._tokenExpiresAt = null;
        this._tokenLifeTime = null;
    }

    _scheduleTokenRefresh() {
        if (!this._auth.tokenRefreshEnabled) {
            return;
        }

        if (this._tokenRefreshTimeout) {
            clearTimeout(this._tokenRefreshTimeout);
        }

        if (!this._tokenLifeTime || typeof this._tokenLifeTime !== 'number' || this._tokenLifeTime <= 0) {
            this._logger.warn('No token lifetime available, cannot schedule refresh');
            return;
        }

        // Refresh token {tokenRefreshMarginSeconds or 30} seconds before it expires
        // or at 90% of lifetime, whichever is shorter
        const tokenRefreshMarginSeconds = this._auth.tokenRefreshMarginSeconds || 30;
        const refreshBuffer = Math.min(tokenRefreshMarginSeconds, this._tokenLifeTime * 0.1);
        const refreshTime = (this._tokenLifeTime - refreshBuffer) * 1000;

        this._logger.info(`Scheduling token refresh in ${refreshTime / 1000} seconds`);

        this._tokenRefreshTimeout = setTimeout(async () => {
            try {
                await this.refreshAccessToken();
                this._scheduleTokenRefresh();
            } catch (error) {
                this._logger.error('Scheduled token refresh failed:', error);
            }
        }, refreshTime);
    }
}

module.exports = {
    JWTSingleton,
};
