// So usado pelo Jest - o build/dev de verdade do app passa pelo electron-vite
// (Vite/Rollup), que ja entende import/export nativamente e nao usa Babel.
// preset-typescript so serve pra despir tipos do modulo compartilhado em
// shared/*.ts (ver src/main/core/vaultCrypto.js) - o desktop continua em JS.
module.exports = {
  presets: [
    ["@babel/preset-env", { targets: { node: "current" } }],
    "@babel/preset-typescript",
  ],
};
