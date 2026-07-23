const { DFSPConfigModel } = require('../../../lib/model');
const mocks = require('../mocks');

jest.mock('@mojaloop/sdk-standard-components', () => ({
    ...jest.requireActual('@mojaloop/sdk-standard-components'),
    request: jest.fn(async () => mocks.mockOidcHttpResponse()),
}));

describe('DFSPConfigModel Tests -->', () => {
    test('should do findStatus call without error [bug IPROD-209]', async () => {
        const model = new DFSPConfigModel(mocks.mockModelOptions());
        const data = await model.findStatus();
        expect(data).toBeTruthy();
    });
});
