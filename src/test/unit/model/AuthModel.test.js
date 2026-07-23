const AuthModel = require('../../../lib/model/AuthModel');
const { ERROR_MESSAGES } = require('../../../lib/constants');
const mocks = require('../mocks');

let mockResponse;

jest.mock('@mojaloop/sdk-standard-components', () => ({
    ...jest.requireActual('@mojaloop/sdk-standard-components'),
    request: jest.fn(async () => mockResponse),
}));

describe('AuthModel Tests -->', () => {
    let auth;

    beforeAll(() => {
        auth = new AuthModel(mocks.mockAuthOptions());
        expect(auth.getToken()).toBeUndefined();
    });

    afterAll(() => {
        auth.destroy();
    });

    test('should throw if oidcTokenRoute is not configured', () => {
        expect(() => new AuthModel({ ...mocks.mockAuthOptions(), oidcTokenRoute: undefined }))
            .toThrow(ERROR_MESSAGES.loginErrorNoTokenRoute);
    });

    test('should get access token', async () => {
        mockResponse = mocks.mockOidcHttpResponse();
        expect(auth.getToken()).toBeUndefined();
        await auth.login();
        expect(auth.getToken()).toBe(mocks.mockOidcData().access_token);
    });

    test('should throw error if no access token in response', async () => {
        mockResponse = mocks.mockOidcHttpResponse({
            data: {},
        });
        await expect(() => auth.login())
            .rejects.toThrow(ERROR_MESSAGES.loginErrorNoToken);
    });

    test('should throw error if response has wrong statusCode', async () => {
        mockResponse = mocks.mockOidcHttpResponse({
            statusCode: 204,
        });
        await expect(() => auth.login())
            .rejects.toThrow(ERROR_MESSAGES.loginErrorInvalidStatusCode);
    });

    describe('Token Refresh Tests', () => {
        let refreshAuth;

        beforeEach(() => {
            jest.useFakeTimers();
        });

        afterEach(() => {
            if (refreshAuth) {
                refreshAuth.destroy();
            }
            jest.useRealTimers();
        });

        test('should refresh token manually using refreshAccessToken', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Mock initial login response with refresh token
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'refresh.token.value',
                },
            });
            await refreshAuth.login();

            // Mock refresh token response
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    access_token: 'refreshed.access.token',
                    refresh_token: 'new.refresh.token',
                },
            });

            const newToken = await refreshAuth.refreshAccessToken();
            expect(newToken).toBe('refreshed.access.token');
            expect(refreshAuth.token).toBe('refreshed.access.token');
        });

        test('should fall back to login when refresh token is not available', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Initial login without refresh token
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    // No refresh_token in response
                },
            });
            await refreshAuth.login();

            // Since there's no refresh token, refreshAccessToken should return null
            await refreshAuth.refreshAccessToken();
            expect(refreshAuth.token).toBe('fake.access.token');
        });

        test('should fall back to login when refresh token request fails', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Mock initial login response with refresh token
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'invalid.refresh.token',
                },
            });
            await refreshAuth.login();

            // Mock failed refresh response
            mockResponse = mocks.mockOidcHttpResponse({
                statusCode: 400,
                data: { error: 'invalid_grant' },
            });

            // Mock successful login fallback
            const loginSpy = jest.spyOn(refreshAuth, 'login').mockResolvedValue('fallback.token');

            const result = await refreshAuth.refreshAccessToken();
            expect(loginSpy).toHaveBeenCalled();
            expect(result).toBe('fallback.token');

            loginSpy.mockRestore();
        });

        test('should return null when auth is disabled for refresh', async () => {
            const disabledAuthOptions = mocks.mockAuthOptions({
                auth: { ...mocks.mockAuth(), enabled: false },
            });
            refreshAuth = new AuthModel(disabledAuthOptions);

            const result = await refreshAuth.refreshAccessToken();
            expect(result).toBeNull();
        });

        test('should check if token is expired correctly', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Test with no expiry time set
            expect(refreshAuth.isTokenExpired()).toBe(true);
            expect(refreshAuth.getTokenExpiryInfo().isExpired).toBe(true);
            expect(refreshAuth.getTokenExpiryInfo().expiresAt).toBeNull();

            // Mock login to set token expiry
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    expires_in: 60, // 1 minute
                },
            });
            await refreshAuth.login();

            // Token should not be expired immediately after login
            expect(refreshAuth.isTokenExpired()).toBe(false);
            expect(refreshAuth.getTokenExpiryInfo().isExpired).toBe(false);
            expect(refreshAuth.getTokenExpiryInfo().lifeTime).toBe(60);
            expect(refreshAuth.getTokenExpiryInfo().expiresAt).toBeGreaterThan(Date.now());

            // Test with buffer seconds
            expect(refreshAuth.isTokenExpired(65)).toBe(true); // Should be expired with 65s buffer
            expect(refreshAuth.isTokenExpired(1)).toBe(false); // Should not expire with 1s buffer
        });

        test('should schedule token refresh correctly', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Mock login response
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    expires_in: 300, // 5 minutes
                    refresh_token: 'refresh.token',
                },
            });
            await refreshAuth.login();

            expect(refreshAuth._tokenRefreshTimeout).toBeTruthy();

            const expiryInfo = refreshAuth.getTokenExpiryInfo();
            expect(expiryInfo.lifeTime).toBe(300);
            expect(expiryInfo.hasRefreshToken).toBe(true);
            expect(expiryInfo.expiresAt).toBeGreaterThan(Date.now());
        });

        test('should clear timeouts on destroy', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Mock login response
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'refresh.token',
                },
            });
            await refreshAuth.login();

            expect(refreshAuth._tokenRefreshTimeout).toBeTruthy();
            expect(refreshAuth.token).toBeTruthy();

            const expiryInfoBefore = refreshAuth.getTokenExpiryInfo();
            expect(expiryInfoBefore.hasRefreshToken).toBe(true);
            expect(expiryInfoBefore.lifeTime).toBeTruthy();
            expect(expiryInfoBefore.expiresAt).toBeTruthy();

            refreshAuth.destroy();

            expect(refreshAuth._tokenRefreshTimeout).toBeNull();
            expect(refreshAuth.token).toBeNull();

            const expiryInfoAfter = refreshAuth.getTokenExpiryInfo();
            expect(expiryInfoAfter.hasRefreshToken).toBe(false);
            expect(expiryInfoAfter.lifeTime).toBeUndefined();
            expect(expiryInfoAfter.expiresAt).toBeNull();
            expect(expiryInfoAfter.isExpired).toBe(true);
        });

        test('should not schedule refresh when no token lifetime available', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Mock login response without expires_in
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    access_token: 'token.without.expiry',
                    // No expires_in field
                },
            });
            await refreshAuth.login();

            expect(refreshAuth._tokenRefreshTimeout).toBeNull();

            const expiryInfo = refreshAuth.getTokenExpiryInfo();
            expect(expiryInfo.lifeTime).toBeUndefined();
            expect(expiryInfo.expiresAt).toBeNull();
            expect(expiryInfo.isExpired).toBe(true);
        });

        test('should clear existing timeout before scheduling new one', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // First login
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    refresh_token: 'first.refresh.token',
                },
            });
            await refreshAuth.login();

            const firstTimeout = refreshAuth._tokenRefreshTimeout;
            expect(firstTimeout).toBeTruthy();

            // Second login should clear the first timeout
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    ...mocks.mockOidcData(),
                    access_token: 'second.token',
                    refresh_token: 'second.refresh.token',
                },
            });
            await refreshAuth.login();

            const secondTimeout = refreshAuth._tokenRefreshTimeout;
            expect(secondTimeout).toBeTruthy();
            expect(secondTimeout).not.toBe(firstTimeout);
        });

        test('should handle invalid expires_in values gracefully', async () => {
            refreshAuth = new AuthModel(mocks.mockAuthOptions());

            // Test with string expires_in
            mockResponse = mocks.mockOidcHttpResponse({
                data: {
                    access_token: 'token.with.string.expiry',
                    expires_in: '300', // String instead of number
                    refresh_token: 'refresh.token',
                },
            });
            await refreshAuth.login();

            let expiryInfo = refreshAuth.getTokenExpiryInfo();
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
            await refreshAuth.login();

            expiryInfo = refreshAuth.getTokenExpiryInfo();
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
            await refreshAuth.login();

            expiryInfo = refreshAuth.getTokenExpiryInfo();
            expect(expiryInfo.expiresAt).toBeNull();
            expect(expiryInfo.lifeTime).toBeUndefined();
            expect(expiryInfo.isExpired).toBe(true);
        });
    });
});
