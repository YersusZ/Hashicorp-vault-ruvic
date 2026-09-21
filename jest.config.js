/** @type {import('jest').Config} */
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.ts'],
  collectCoverageFrom: ['nodes/HashiCorpVault/transport/**/*.ts'],
  coveragePathIgnorePatterns: ['/node_modules/', '/dist/'],
};

