const sdkSC = require('@mojaloop/sdk-standard-components');

const { Requests } = require('../../../lib/requests');
const { JWTClient } = require('../../../lib/requests/jwt');
const { makeJsonHeaders } = require('../../../lib/requests/common');
const constants = require('../../../lib/constants');
const mocks = require('../mocks');

let mockResponse;

// to prevent error: jest.mock() is not allowed to reference out-of-scope vars (use 'mock' prefix)
const mockLoginRoute = constants.OIDC_TOKEN_ROUTE;

jest.mock('@mojaloop/sdk-standard-components', () => ({
    ...jest.requireActual('@mojaloop/sdk-standard-components'),
    request: jest.fn(async ({ uri }) => {
        if (uri.includes(mockLoginRoute)) return mocks.mockOidcHttpResponse();
        if (mockResponse instanceof Error) throw mockResponse;
        return mockResponse;
    }),
}));

jest.setTimeout(30 * 1000);

describe('Requests Tests -->', () => {
    let jwt;

    beforeAll(() => {
        jwt = new JWTClient(mocks.mockJwtOptions());
    });

    afterEach(() => {
        sdkSC.request.mockClear(); // jest.restoreAllMocks() doesn't work here for some reason
    });

    test('should pass params to underlying sdkSC.request in proper format', async () => {
        const url = '/test';
        const body = { test: 1 };
        const r = new Requests(mocks.mockModelOptions({ retries: 1 }));
        const reqSpy = jest.spyOn(sdkSC, 'request');
        mockResponse = mocks.mockOidcHttpResponse();

        await r.post(url, body);
        expect(reqSpy.mock.calls.length).toBe(1);

        const [params] = reqSpy.mock.calls[0];
        expect(params.uri).toBe(`${r.hubEndpoint}${url}`);
        expect(params.body).toBe(JSON.stringify(body));
        expect(params.method).toBe('POST');
        expect(params.headers).toEqual(makeJsonHeaders());
    });

    describe('onRetry Tests -->', () => {
        test('should do retries in case of errors', async () => {
            const retries = 1;
            const r = new Requests(mocks.mockModelOptions({ retries }));
            const reqSpy = jest.spyOn(sdkSC, 'request');
            expect(reqSpy.mock.calls.length).toBe(0);

            mockResponse = mocks.mockOidcHttpResponse({ statusCode: 400 });
            await r.get('/test').catch(() => {});
            expect(reqSpy.mock.calls.length).toBe(1 + retries);
        });

        test('should do login call only in case of 401 or 403 errors', async () => {
            const r = new Requests(mocks.mockModelOptions({ auth: jwt }));

            const loginSpy = jest.spyOn(jwt, 'login');
            const initCalls = loginSpy.mock.calls.length;

            mockResponse = mocks.mockOidcHttpResponse({ statusCode: 400 });
            await r.get('/test').catch(() => {});
            expect(loginSpy.mock.calls.length).toBe(initCalls);

            mockResponse = mocks.mockOidcHttpResponse({ statusCode: 403 });
            await r.get('/test').catch(() => {});
            // note that async-retry will make retries + 1 total calls to the endpoint...
            // first call is not a retry.
            expect(loginSpy.mock.calls.length).toBe(initCalls + 1 + r.retries);
        });

        test('should throw error in case of bad statusCode of response', async () => {
            const r = new Requests(mocks.mockModelOptions({ retries: 1 }));
            mockResponse = mocks.mockOidcHttpResponse({ statusCode: 500 });
            await expect(() => r.get('/test'))
                .rejects.toThrow(constants.ERROR_MESSAGES.nonSuccessStatusCode);
        });

        test('should rethrow a raw Node.js error, received from sdkSC.request', async () => {
            const r = new Requests(mocks.mockModelOptions({ retries: 1 }));
            mockResponse = new Error('test');

            await expect(() => r.get('/test'))
                .rejects.toThrow(mockResponse);
        });
    });
});
