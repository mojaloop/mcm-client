const { JWTClient } = require('../../../lib/requests/jwt');
const { ERROR_MESSAGES } = require('../../../lib/constants');
const mocks = require('../mocks');

let mockResponse;

jest.mock('@mojaloop/sdk-standard-components', () => ({
    ...jest.requireActual('@mojaloop/sdk-standard-components'),
    request: jest.fn(async () => mockResponse),
}));

describe('JWTClient Tests -->', () => {
    let jwt;

    beforeAll(() => {
        jwt = new JWTClient(mocks.mockJwtOptions());
        expect(jwt.getToken()).toBeUndefined();
    });

    afterAll(() => {
        jwt.destroy();
    });

    test('should throw if oidcTokenRoute is not configured', () => {
        expect(() => new JWTClient({ ...mocks.mockJwtOptions(), oidcTokenRoute: undefined }))
            .toThrow(ERROR_MESSAGES.loginErrorNoTokenRoute);
    });

    test('should get access token', async () => {
        mockResponse = mocks.mockOidcHttpResponse();
        expect(jwt.getToken()).toBeUndefined();
        await jwt.login();
        expect(jwt.getToken()).toBe(mocks.mockOidcData().access_token);
    });

    test('should throw error if no access token in response', async () => {
        mockResponse = mocks.mockOidcHttpResponse({
            data: {},
        });
        await expect(() => jwt.login())
            .rejects.toThrow(ERROR_MESSAGES.loginErrorNoToken);
    });

    test('should throw error if response has wrong statusCode', async () => {
        mockResponse = mocks.mockOidcHttpResponse({
            statusCode: 204,
        });
        await expect(() => jwt.login())
            .rejects.toThrow(ERROR_MESSAGES.loginErrorInvalidStatusCode);
    });

    describe('Token Refresh Tests', () => {
        let refreshJwt;

        beforeEach(() => {
            jest.useFakeTimers();
        });

        afterEach(() => {
            if (refreshJwt) {
                refreshJwt.destroy();
            }
            jest.useRealTimers();
        });

        test('should refresh token manually using refreshAccessToken', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Mock initial login response with refresh token
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'refresh.token.value',
                },
            });
            await refreshJwt.login();

            // Mock refresh token response
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    access_token: 'refreshed.access.token',
                    refresh_token: 'new.refresh.token',
                },
            });

            const newToken = await refreshJwt.refreshAccessToken();
            expect(newToken).toBe('refreshed.access.token');
            expect(refreshJwt.token).toBe('refreshed.access.token');
        });

        test('should fall back to login when refresh token is not available', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Initial login without refresh token
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    // No refresh_token in response
                },
            });
            await refreshJwt.login();

            // Since there's no refresh token, refreshAccessToken should return null
            await refreshJwt.refreshAccessToken();
            expect(refreshJwt.token).toBe('fake.access.token');
        });

        test('should fall back to login when refresh token request fails', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Mock initial login response with refresh token
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'invalid.refresh.token',
                },
            });
            await refreshJwt.login();

            // Mock failed refresh response
            mockResponse = mocks.mockOidcHttpResponse({
                statusCode: 400,
                data: { error: 'invalid_grant' },
            });

            // Mock successful login fallback
            const loginSpy = jest.spyOn(refreshJwt, 'login').mockResolvedValue('fallback.token');

            const result = await refreshJwt.refreshAccessToken();
            expect(loginSpy).toHaveBeenCalled();
            expect(result).toBe('fallback.token');

            loginSpy.mockRestore();
        });

        test('should return null when auth is disabled for refresh', async () => {
            const disabledAuthOptions = mocks.mockJwtOptions({
                auth: { ...mocks.mockAuth(), enabled: false },
            });
            refreshJwt = new JWTClient(disabledAuthOptions);

            const result = await refreshJwt.refreshAccessToken();
            expect(result).toBeNull();
        });

        test('should check if token is expired correctly', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Test with no expiry time set
            expect(refreshJwt.isTokenExpired()).toBe(true);
            expect(refreshJwt.getTokenExpiryInfo().isExpired).toBe(true);
            expect(refreshJwt.getTokenExpiryInfo().expiresAt).toBeNull();

            // Mock login to set token expiry
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    expires_in: 60, // 1 minute
                },
            });
            await refreshJwt.login();

            // Token should not be expired immediately after login
            expect(refreshJwt.isTokenExpired()).toBe(false);
            expect(refreshJwt.getTokenExpiryInfo().isExpired).toBe(false);
            expect(refreshJwt.getTokenExpiryInfo().lifeTime).toBe(60);
            expect(refreshJwt.getTokenExpiryInfo().expiresAt).toBeGreaterThan(Date.now());

            // Test with buffer seconds
            expect(refreshJwt.isTokenExpired(65)).toBe(true); // Should be expired with 65s buffer
            expect(refreshJwt.isTokenExpired(1)).toBe(false); // Should not expire with 1s buffer
        });

        test('should schedule token refresh correctly', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Mock login response
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    expires_in: 300, // 5 minutes
                    refresh_token: 'refresh.token',
                },
            });
            await refreshJwt.login();

            expect(refreshJwt._tokenRefreshTimeout).toBeTruthy();

            const expiryInfo = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfo.lifeTime).toBe(300);
            expect(expiryInfo.hasRefreshToken).toBe(true);
            expect(expiryInfo.expiresAt).toBeGreaterThan(Date.now());
        });

        test('should clear timeouts on destroy', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Mock login response
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'refresh.token',
                },
            });
            await refreshJwt.login();

            expect(refreshJwt._tokenRefreshTimeout).toBeTruthy();
            expect(refreshJwt.token).toBeTruthy();

            const expiryInfoBefore = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfoBefore.hasRefreshToken).toBe(true);
            expect(expiryInfoBefore.lifeTime).toBeTruthy();
            expect(expiryInfoBefore.expiresAt).toBeTruthy();

            refreshJwt.destroy();

            expect(refreshJwt._tokenRefreshTimeout).toBeNull();
            expect(refreshJwt.token).toBeNull();

            const expiryInfoAfter = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfoAfter.hasRefreshToken).toBe(false);
            expect(expiryInfoAfter.lifeTime).toBeUndefined();
            expect(expiryInfoAfter.expiresAt).toBeNull();
            expect(expiryInfoAfter.isExpired).toBe(true);
        });

        test('should not schedule refresh when no token lifetime available', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Mock login response without expires_in
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    access_token: 'token.without.expiry',
                    // No expires_in field
                },
            });
            await refreshJwt.login();

            expect(refreshJwt._tokenRefreshTimeout).toBeNull();

            const expiryInfo = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfo.lifeTime).toBeUndefined();
            expect(expiryInfo.expiresAt).toBeNull();
            expect(expiryInfo.isExpired).toBe(true);
        });

        test('should clear existing timeout before scheduling new one', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // First login
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'first.refresh.token',
                },
            });
            await refreshJwt.login();

            const firstTimeout = refreshJwt._tokenRefreshTimeout;
            expect(firstTimeout).toBeTruthy();

            // Second login should clear the first timeout
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    access_token: 'second.token',
                    refresh_token: 'second.refresh.token',
                },
            });
            await refreshJwt.login();

            const secondTimeout = refreshJwt._tokenRefreshTimeout;
            expect(secondTimeout).toBeTruthy();
            expect(secondTimeout).not.toBe(firstTimeout);
        });

        test('should handle invalid expires_in values gracefully', async () => {
            refreshJwt = new JWTClient(mocks.mockJwtOptions());

            // Test with string expires_in
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    access_token: 'token.with.string.expiry',
                    expires_in: '300', // String instead of number
                    refresh_token: 'refresh.token',
                },
            });
            await refreshJwt.login();

            let expiryInfo = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfo.expiresAt).toBeNull();
            expect(expiryInfo.lifeTime).toBe('300'); // Stored as-is
            // Should be expired when _tokenExpiresAt is null
            expect(expiryInfo.isExpired).toBe(true);

            // Test with negative expires_in
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    access_token: 'token.with.negative.expiry',
                    expires_in: -100,
                    refresh_token: 'refresh.token',
                },
            });
            await refreshJwt.login();

            expiryInfo = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfo.expiresAt).toBeNull();
            expect(expiryInfo.lifeTime).toBe(-100);
            expect(expiryInfo.isExpired).toBe(true);

            // Test with null expires_in
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    access_token: 'token.with.null.expiry',
                    expires_in: null,
                    refresh_token: 'refresh.token',
                },
            });
            await refreshJwt.login();

            expiryInfo = refreshJwt.getTokenExpiryInfo();
            expect(expiryInfo.expiresAt).toBeNull();
            expect(expiryInfo.lifeTime).toBeUndefined();
            expect(expiryInfo.isExpired).toBe(true);
        });
    });
});
