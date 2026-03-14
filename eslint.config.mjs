import globals from 'globals';
import pluginJs from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';
import sonarjs from 'eslint-plugin-sonarjs';
import unicorn from 'eslint-plugin-unicorn';
import simpleImportSort from 'eslint-plugin-simple-import-sort';

export default [
  // ── Ignore patterns ────────────────────────────────────────────
  { ignores: ['dist/', 'node_modules/', 'coverage/', 'examples/'] },

  // ── File patterns ──────────────────────────────────────────────
  { files: ['**/*.{js,mjs,cjs,ts}'] },

  // ── Language globals ───────────────────────────────────────────
  { languageOptions: { globals: { ...globals.node } } },

  // ── Base ESLint + TypeScript ───────────────────────────────────
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  eslintConfigPrettier,

  // ── SonarJS ────────────────────────────────────────────────────
  sonarjs.configs.recommended,

  // ── Core rules ─────────────────────────────────────────────────
  {
    plugins: {
      'simple-import-sort': simpleImportSort,
    },
    rules: {
      // No raw console in library source — use logixia's own log system
      'no-console': 'warn',

      // ── TypeScript ─────────────────────────────────────────────
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_' },
      ],
      '@typescript-eslint/consistent-type-imports': ['warn', { prefer: 'type-imports' }],
      // Non-null assertions are intentional in library code — used after
      // Map.get(), optional checks, and other guarded patterns.
      '@typescript-eslint/no-non-null-assertion': 'off',

      // ── Import ordering ────────────────────────────────────────
      'simple-import-sort/imports': 'error',
      'simple-import-sort/exports': 'error',

      // ── SonarJS ────────────────────────────────────────────────
      // Threshold raised to match the real complexity of core transport/
      // search utility functions (highest observed: transport.manager = 49).
      'sonarjs/cognitive-complexity': ['warn', 55],
      'sonarjs/todo-tag': 'off',
    },
  },

  // ── Unicorn ────────────────────────────────────────────────────
  {
    plugins: { unicorn },
    rules: {
      'unicorn/prefer-node-protocol': 'error',
      'unicorn/prefer-module': 'off', // Uses CommonJS
      'unicorn/no-array-for-each': 'error',
      'unicorn/prefer-number-properties': 'error',
      'unicorn/no-instanceof-array': 'error',
      'unicorn/prefer-optional-catch-binding': 'error',
      'unicorn/no-useless-undefined': 'error',
      'unicorn/prefer-string-slice': 'error',
      'unicorn/throw-new-error': 'error',
      'unicorn/no-new-array': 'error',
      'unicorn/error-message': 'error',
      'unicorn/consistent-destructuring': 'warn',
    },
  },

  // ── Test file overrides ────────────────────────────────────────
  {
    files: ['test/**/*.ts', '**/*.test.ts', '**/*.spec.ts'],
    rules: {
      'no-console': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
      '@typescript-eslint/no-non-null-assertion': 'off',
      'sonarjs/no-duplicate-string': 'off',
      'sonarjs/no-hardcoded-credentials': 'off',
      'unicorn/prefer-node-protocol': 'off',
    },
  },

  // ── CLI commands: console.* is intentional for user output ─────
  {
    files: ['src/cli/**/*.ts'],
    rules: { 'no-console': 'off' },
  },

  // ── Console transport: wraps console.* by design ───────────────
  {
    files: ['src/transports/console.transport.ts'],
    rules: { 'no-console': 'off' },
  },

  // ── Internal log: IS the console wrapper ──────────────────────
  {
    files: ['src/utils/internal-log.ts'],
    rules: { 'no-console': 'off' },
  },

  // ── Logger core: fallback console output when no transports ───
  {
    files: ['src/core/logitron-logger.ts'],
    rules: { 'no-console': 'off' },
  },
];
