/**
 * For a detailed explanation regarding each configuration property, visit:
 * https://jestjs.io/docs/configuration
 */

/** @type {import('jest').Config} */
const config = {

  reporters: [
    'default',
    ['jest-junit', {outputDirectory: 'reports', outputName: 'report.xml'}],
  ],
 
  // Automatically clear mock calls, instances, contexts and results before every test
  clearMocks: false,

  // Indicates whether the coverage information should be collected while executing the test
  collectCoverage: true,

  // The directory where Jest should output its coverage files
  coverageDirectory: "coverage",

  // Indicates which provider should be used to instrument code for coverage
  coverageProvider: "v8",

  // A list of reporter names that Jest uses when writing coverage reports
  coverageReporters: [
    "json",
    "text",
    "lcov",
    'text-summary'
  ],

  // An object that configures minimum threshold enforcement for coverage results
  coverageThreshold: {
    global: {
      statements: 50,
      functions: 50,
      branches: 50,
      lines: 50
    }
  },

  // Module name mapper for path aliases
  moduleNameMapper: {
    '^@app/(.*)$': '<rootDir>/dist/$1'
  },

  // The test environment that will be used for testing
  testEnvironment: "jest-environment-node",

  // serialize-error/non-error are ESM-only; transform them to CommonJS for the runner
  transform: {
    "^.+\\.js$": ["ts-jest", {
      isolatedModules: true,
      diagnostics: false,
      tsconfig: { allowJs: true, module: "CommonJS", esModuleInterop: true, moduleResolution: "node" },
    }],
  },
  transformIgnorePatterns: [
    "/node_modules/(?!(serialize-error|non-error)/)",
  ],

};

module.exports = config;
