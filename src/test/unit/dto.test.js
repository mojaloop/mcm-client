const dto = require('../../lib/dto');
const { ERROR_MESSAGES } = require('../../lib/constants');

describe('DTO Tests -->', () => {
    describe('oidcPayloadDto Tests -->', () => {
        test('should pass validation', () => {
            const data = dto.oidcPayloadDto('grantType');
            expect(data).toBeTruthy();
        });

        test('should throw on wrong format', () => {
            expect(() => dto.oidcPayloadDto({}))
                .toThrow(ERROR_MESSAGES.oidcPayloadFormatError);
        });

        test('should include audience when provided', () => {
            const data = dto.oidcPayloadDto('grantType', 'scope', 'connection-manager-api');
            expect(data.audience).toBe('connection-manager-api');
        });

        test('should omit audience when not provided', () => {
            expect(dto.oidcPayloadDto('grantType')).not.toHaveProperty('audience');
        });
    });
});
