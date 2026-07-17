/** @type {import('jest').Config} */
const config = {
  preset: 'ts-jest',
  testEnvironment: "node",

  testMatch: [
    '**/src/test/unit/**/*.test.ts'
  ],
  clearMocks: false, // !! some unit tests fail if this is true

  moduleNameMapper: {
    '^@app/(.*)$': '<rootDir>/src/$1'
  },

  // TypeScript transformation configuration (modern ts-jest syntax)
  transform: {
    '^.+\\.ts$': ['ts-jest', {
      tsconfig: {
        // Inherit from tsconfig.json but allow JS files for tests
        allowJs: true,
        esModuleInterop: true,
        moduleResolution: 'node',
        resolveJsonModule: true,
        skipLibCheck: true
      }
    }],
    // serialize-error/non-error are ESM-only; transform them to CommonJS for the runner
    '^.+\\.js$': ['ts-jest', {
      isolatedModules: true,
      diagnostics: false,
      tsconfig: { allowJs: true, module: 'CommonJS', esModuleInterop: true, moduleResolution: 'node', skipLibCheck: true }
    }]
  },

  transformIgnorePatterns: [
    "/node_modules/(?!(serialize-error|non-error)/)",
  ],
};

module.exports = config;
