module.exports = {
    clearMocks: true,
    moduleFileExtensions: ['ts', 'js'],
    roots: ['<rootDir>/src', '<rootDir>/cdk'],
    testEnvironment: 'node',
    transform: {
        '^.+\\.ts$': ['ts-jest', { tsconfig: 'tsconfig.test.json' }],
    },
};
