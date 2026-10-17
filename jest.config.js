module.exports = {
  preset: "jest-expo",
  clearMocks: true,
  testMatch: ["**/__tests__/**/*.test.js"],
  // O app desktop (Electron/Node puro) tem sua propria suite Jest
  // (desktop/jest.config.cjs, rodada via `npm test` dentro de desktop/)
  // com babel.config.cjs proprio - sem esse ignore, `**/__tests__/**`
  // tambem casava com desktop/__tests__/, rodando esses testes por
  // acidente sob o preset jest-expo (ambiente/transform errados pro
  // codigo do desktop).
  testPathIgnorePatterns: ["/node_modules/", "<rootDir>/desktop/"],
  setupFiles: [
    "<rootDir>/node_modules/@react-native-google-signin/google-signin/jest/build/jest/setup.js",
  ],
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
};
