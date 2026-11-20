'use strict';

const noSecretLogging = require('./eslint-rules/no-secret-logging');

module.exports = [
  {
    files: ['lib/**/*.js'],
    ignores: ['lib/vendor/**'],
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: 'commonjs',
    },
    plugins: {
      local: {
        rules: {
          'no-secret-logging': noSecretLogging,
        },
      },
    },
    rules: {
      'local/no-secret-logging': 'error',
    },
  },
];
