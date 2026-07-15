const Ajv = require('ajv');
const { ERROR_MESSAGES } = require('./constants');

const ajv = new Ajv({ allErrors: true });

const makeErrMessage = (validateFn) => JSON.stringify(validateFn.errors.map((e) => e.message));

const oidcPayloadSchema = {
    type: 'object',
    properties: {
        grant_type: { type: 'string' },
        scope: { type: 'string' },
    },
    required: ['grant_type'],
    additionalProperties: false,
};
const validateOidcPayload = ajv.compile(oidcPayloadSchema);

const oidcRefreshPayloadSchema = {
    type: 'object',
    properties: {
        grant_type: { type: 'string' },
        refresh_token: { type: 'string' },
    },
    required: ['grant_type', 'refresh_token'],
    additionalProperties: false,
};
const validateOidcRefreshPayload = ajv.compile(oidcRefreshPayloadSchema);

const oidcPayloadDto = (grantType, scope) => {
    const dto = {
        grant_type: grantType, // todo: add possible values check
        ...(scope ? { scope } : null),
    };

    const isValid = validateOidcPayload(dto);
    if (!isValid) {
        const errMessage = makeErrMessage(validateOidcPayload);
        throw new TypeError(`${ERROR_MESSAGES.oidcPayloadFormatError}: ${errMessage}`);
    }

    return Object.freeze(dto);
};

const oidcRefreshPayloadDto = (refreshToken) => {
    const dto = {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
    };

    const isValid = validateOidcRefreshPayload(dto);
    if (!isValid) {
        const errMessage = makeErrMessage(validateOidcRefreshPayload);
        throw new TypeError(`${ERROR_MESSAGES.oidcPayloadFormatError}: ${errMessage}`);
    }

    return Object.freeze(dto);
};

module.exports = {
    oidcPayloadDto,
    oidcRefreshPayloadDto,
    validateOidcPayload,
};
