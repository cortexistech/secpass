// Porta a implementacao unica de shared/vaultCrypto.ts para o desktop,
// injetando node:crypto como backend. Ver shared/vaultCrypto.ts para a
// logica e o formato do envelope (compativel byte-a-byte com o mobile, que
// usa o mesmo modulo com react-native-quick-crypto).
import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  pbkdf2Sync,
  randomBytes,
} from "node:crypto";
import { createVaultCrypto } from "../../../../shared/vaultCrypto";

const vaultCrypto = createVaultCrypto({
  pbkdf2Sync,
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  Buffer,
});

export const {
  createVaultSecret,
  emailFromVaultSecret,
  createVaultMeta,
  unlockVaultKeys,
  encryptVaultItem,
  decryptVaultItem,
  encryptVaultItems,
  decryptVaultEnvelope,
  validateCredentialFields,
} = vaultCrypto;
