module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  transform: {
    '^.+\.ts$': 'ts-jest',
  },
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/**/__tests__/**',
    // index.ts entry points are now included — they expose the public API surface
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html'],
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
    // Chalk v5 is pure-ESM; map it to a CJS passthrough mock for Jest.
    '^chalk$': '<rootDir>/src/__mocks__/chalk.js',
    // Allow ESM-style .js extensions in TypeScript source imports (e.g. './foo.js' → './foo.ts').
    // Required because ts-jest resolves .ts files but the source uses explicit .js extensions
    // for Node16/NodeNext module resolution compatibility.
    '^(\\.{1,2}/.*)\\.js$': '$1',
  },
  setupFilesAfterEnv: [],
  testTimeout: 10000,
  extensionsToTreatAsEsm: ['.ts'],
  transformIgnorePatterns: ['node_modules/(?!(nanoid)/)'],
};
