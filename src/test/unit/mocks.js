const { Logger } = require('@mojaloop/sdk-standard-components');

const mockAuth = ({
    enabled = true,
    clientId = 'clientId',
    clientSecret = 'clientSecret',
    tokenRefreshEnabled = true,
} = {}) => Object.freeze({
    enabled,
    tokenRefreshEnabled,
    creds: {
        clientId,
        clientSecret,
    },
});

const mockJwtOptions = ({
    auth = mockAuth(),
    hubIamProviderUrl = 'https://hubIamProviderUrl.com',
    oidcTokenRoute = 'oauth2/token',
    oidcAudience,
} = {}) => Object.freeze({
    auth,
    hubIamProviderUrl,
    oidcTokenRoute,
    oidcAudience,
    logger: new Logger.SdkLogger({}),
});

const mockModelOptions = ({
    dfspId = 'dfspId',
    hubEndpoint = 'http://hubEndpoint.com',
    retries,
    auth,
} = {}) => Object.freeze({
    dfspId,
    hubEndpoint,
    retries,
    auth,
    logger: new Logger.SdkLogger(),
});

const mockOidcData = ({
    access_token = 'fake.access.token',
    refresh_token,
} = {}) => Object.freeze({
    access_token,
    expires_in: 300,
    refresh_expires_in: 0,
    token_type: 'Bearer',
    'not-before-policy': 0,
    scope: 'profile email',
    ...(refresh_token ? { refresh_token } : {}),
});

const mockUploadExternalDfspJWSData = () => Object.freeze([
    {
        dfspId: 'test1',
        createdAt: 1,
        publicKey: 'publicKey',
    },
]);

const mockOidcHttpResponse = ({
    statusCode = 200,
    data = mockOidcData(),
    headers = {},
} = {}) => Object.freeze({
    statusCode,
    data,
    headers,
});

const mockUploadExternalDfspJWSHttpResponse = ({
    statusCode = 200,
    data = mockUploadExternalDfspJWSData(),
    headers = {},
} = {}) => Object.freeze({
    statusCode,
    data,
    headers,
});

const mockErrorData = ({
    // eslint-disable-next-line no-unused-vars
    access_token = 'fake.access.token',
} = {}) => Object.freeze({
    error: 'mock error response',
});

const mockErrorHttpResponse = ({
    statusCode = 400,
    data = mockErrorData(),
    headers = {},
} = {}) => Object.freeze({
    statusCode,
    data,
    headers,
});

module.exports = {
    mockAuth,
    mockJwtOptions,
    mockModelOptions,
    mockOidcData,
    mockOidcHttpResponse,
    mockUploadExternalDfspJWSData,
    mockUploadExternalDfspJWSHttpResponse,
    mockErrorData,
    mockErrorHttpResponse,
};
