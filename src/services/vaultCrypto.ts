// Porta a implementacao unica de shared/vaultCrypto.ts para o mobile,
// injetando react-native-quick-crypto como backend de crypto. Ver
// shared/vaultCrypto.ts para a logica e o formato do envelope (compativel
// byte-a-byte com o desktop, que usa o mesmo modulo com node:crypto).
import { Buffer } from "@craftzdog/react-native-buffer";
import QuickCrypto from "react-native-quick-crypto";

import {
  createVaultCrypto,
  type VaultCryptoAdapter,
} from "../../shared/vaultCrypto";

const adapter = {
  pbkdf2Sync: QuickCrypto.pbkdf2Sync,
  createHmac: QuickCrypto.createHmac,
  createCipheriv: QuickCrypto.createCipheriv,
  createDecipheriv: QuickCrypto.createDecipheriv,
  randomBytes: QuickCrypto.randomBytes,
  Buffer,
  // react-native-quick-crypto implementa a mesma API do node:crypto, mas os
  // tipos publicados nao batem estruturalmente com VaultCryptoAdapter (ex:
  // retorno de pbkdf2Sync/randomBytes e o Buffer da propria lib, nao
  // Uint8Array puro) - o formato do envelope e coberto por
  // __tests__/vaultCrypto.test.js, entao o cast aqui e seguro.
} as unknown as VaultCryptoAdapter;

const vaultCrypto = createVaultCrypto(adapter);

export const {
  createVaultSecret,
  emailFromVaultSecret,
  createVaultMeta,
  unlockVaultKeys,
  encryptVaultItem,
  decryptVaultItem,
  encryptVaultItems,
  decryptVaultEnvelope,
} = vaultCrypto;

export type {
  VaultItem,
  VaultKeys,
  VaultMeta,
  VaultItemRevision,
  EncryptedItemEnvelope,
  EncryptedVaultEnvelope,
} from "../../shared/vaultCrypto";
