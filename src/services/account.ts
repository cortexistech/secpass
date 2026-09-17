import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";
import QuickCrypto from "react-native-quick-crypto";

import { constantTimeCompare } from "../utils/constantTimeCompare";
import {
  DEVICE_AUTH_NOT_CONFIGURED,
  isDeviceAuthNotConfiguredError,
} from "../utils/secureStoreErrors";

const ACCOUNT_KEY = "secpass_account";
const ACCOUNT_VERSION = 3;

const PBKDF2_ITERATIONS = 600000;
const PBKDF2_KEY_SIZE_WORDS = 256 / 32;
const SECURE_STORE_ERROR = "Falha ao salvar conta no armazenamento seguro.";
const SECURE_STORE_OPTIONS = {
  keychainService: "secpass.account",
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

const DUMMY_SALT = "0123456789abcdef0123456789abcdef";
const DUMMY_HASH =
  "0000000000000000000000000000000000000000000000000000000000000000";

interface AccountV1 {
  email: string;
  legacyPassword: string;
  version: 1;
}

interface AccountV2 {
  email: string;
  salt: string;
  passwordHash: string;
  version: 2;
}

interface AccountV3 {
  email: string;
  salt: string;
  passwordHash: string;
  kdf: "pbkdf2";
  iterations: number;
  keySize: number;
  version: 3;
}

type StoredAccount = AccountV1 | AccountV2 | AccountV3;

const parseAccount = (rawValue: string | null): StoredAccount | null => {
  if (!rawValue) {
    return null;
  }

  try {
    const parsed = JSON.parse(rawValue);
    if (!parsed?.email) {
      return null;
    }

    if (
      parsed.version === ACCOUNT_VERSION &&
      parsed.passwordHash &&
      parsed.salt &&
      parsed.kdf === "pbkdf2"
    ) {
      return {
        email: parsed.email,
        salt: parsed.salt,
        passwordHash: parsed.passwordHash,
        kdf: parsed.kdf,
        iterations: parsed.iterations,
        keySize: parsed.keySize,
        version: ACCOUNT_VERSION,
      };
    }

    if (parsed.passwordHash && parsed.salt) {
      return {
        email: parsed.email,
        salt: parsed.salt,
        passwordHash: parsed.passwordHash,
        version: 2,
      };
    }

    if (parsed.password) {
      return {
        email: parsed.email,
        legacyPassword: parsed.password,
        version: 1,
      };
    }

    return null;
  } catch {
    return null;
  }
};

const createSalt = (): string => {
  const randomBytes = QuickCrypto.randomBytes(16);
  return Array.from(randomBytes, (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
};

const hashPasswordV2 = (password: string, salt: string): string => {
  return QuickCrypto.createHash("sha256")
    .update(`${salt}:${password}`)
    .digest("hex");
};

const hashPasswordV3 = (
  password: string,
  salt: string,
  iterations: number = PBKDF2_ITERATIONS,
): string => {
  return QuickCrypto.pbkdf2Sync(
    password,
    salt,
    iterations,
    PBKDF2_KEY_SIZE_WORDS * 4,
    "sha256",
  ).toString("hex");
};

const writeSecureAccount = async ({
  email,
  salt,
  passwordHash,
  version = ACCOUNT_VERSION,
}: {
  email: string;
  salt: string;
  passwordHash: string;
  version?: number;
}): Promise<"secure"> => {
  const isV3 = version === ACCOUNT_VERSION;
  const payload = JSON.stringify({
    email: email.trim().toLowerCase(),
    salt,
    passwordHash,
    version,
    ...(isV3
      ? {
          kdf: "pbkdf2",
          iterations: PBKDF2_ITERATIONS,
          keySize: 256,
        }
      : {}),
  });

  try {
    await SecureStore.setItemAsync(ACCOUNT_KEY, payload, SECURE_STORE_OPTIONS);
    return "secure";
  } catch (err) {
    if (isDeviceAuthNotConfiguredError(err)) {
      throw new Error(DEVICE_AUTH_NOT_CONFIGURED);
    }
    throw new Error(SECURE_STORE_ERROR);
  }
};

const getStoredAccount = async (): Promise<{
  account: StoredAccount;
  source: "secure" | "legacy";
} | null> => {
  let secureAccount: string | null = null;

  try {
    secureAccount = await SecureStore.getItemAsync(
      ACCOUNT_KEY,
      SECURE_STORE_OPTIONS,
    );
  } catch {
    // Nao autentica contra armazenamento nao seguro quando o backend seguro falha.
    return null;
  }

  const parsedSecureAccount = parseAccount(secureAccount);

  if (parsedSecureAccount) {
    return {
      account: parsedSecureAccount,
      source: "secure",
    };
  }

  const fallbackAccount = await AsyncStorage.getItem(ACCOUNT_KEY);
  const parsedFallbackAccount = parseAccount(fallbackAccount);

  if (!parsedFallbackAccount) {
    return null;
  }

  return {
    account: parsedFallbackAccount,
    source: "legacy",
  };
};

export const saveLocalAccount = async ({
  email,
  password,
}: {
  email: string;
  password: string;
}): Promise<void> => {
  const salt = createSalt();
  const passwordHash = hashPasswordV3(password, salt);

  const backend = await writeSecureAccount({ email, salt, passwordHash });
  if (backend === "secure") {
    await AsyncStorage.removeItem(ACCOUNT_KEY);
  }
};

export const loadLocalAccount = async (): Promise<{ email: string } | null> => {
  const storedAccount = await getStoredAccount();
  if (!storedAccount) {
    return null;
  }

  const { account, source } = storedAccount;

  if (account.version === 1) {
    try {
      await saveLocalAccount({
        email: account.email,
        password: account.legacyPassword,
      });
      if (source === "legacy") {
        await AsyncStorage.removeItem(ACCOUNT_KEY);
      }
    } catch {
      // Mantem a conta carregada mesmo sem conseguir concluir migracao.
    }

    return { email: account.email };
  }

  if (source === "legacy") {
    try {
      const backend = await writeSecureAccount({
        email: account.email,
        salt: account.salt,
        passwordHash: account.passwordHash,
        version: account.version,
      });
      if (backend === "secure") {
        await AsyncStorage.removeItem(ACCOUNT_KEY);
      }
    } catch {
      // Mantem leitura legada; migracao sera tentada novamente depois.
    }
  }

  return { email: account.email };
};

export const verifyLocalAccount = async ({
  email,
  password,
}: {
  email?: string;
  password?: string;
}): Promise<boolean> => {
  const normalizedEmail = (email || "").trim().toLowerCase();

  const storedAccount = await getStoredAccount();
  const account = storedAccount?.account || null;

  const isEmailValid = account
    ? constantTimeCompare(account.email, normalizedEmail)
    : false;

  if (account?.version === 1) {
    const isLegacyPasswordValid = constantTimeCompare(
      account.legacyPassword || "",
      password || "",
    );
    const isValid = isEmailValid && isLegacyPasswordValid;
    if (isValid) {
      await saveLocalAccount({
        email: account.email,
        password: account.legacyPassword,
      });
      return true;
    }
    hashPasswordV3(password || "", DUMMY_SALT, PBKDF2_ITERATIONS);
    return false;
  }

  if (account?.version === 2) {
    const inputHashV2 = hashPasswordV2(password || "", account.salt);
    const isHashValidV2 = constantTimeCompare(
      account.passwordHash,
      inputHashV2,
    );
    const isValid = isEmailValid && isHashValidV2;
    if (isValid) {
      try {
        await saveLocalAccount({ email: normalizedEmail, password: password || "" });
      } catch {
        // Login continua valido mesmo sem concluir promocao para v3.
      }
      return true;
    }
    hashPasswordV3(
      password || "",
      account.salt || DUMMY_SALT,
      PBKDF2_ITERATIONS,
    );
    return false;
  }

  const salt = account?.salt || DUMMY_SALT;
  const storedIterations = Number(account?.iterations) || PBKDF2_ITERATIONS;
  const expectedHash = account?.passwordHash || DUMMY_HASH;

  const inputHash = hashPasswordV3(password || "", salt, storedIterations);

  const isHashValid = constantTimeCompare(expectedHash, inputHash);
  const isValid = isEmailValid && isHashValid;

  if (isValid && storedIterations < PBKDF2_ITERATIONS) {
    try {
      await saveLocalAccount({ email: normalizedEmail, password: password || "" });
    } catch {
      // Login continua valido com as iteracoes antigas; promocao tenta de novo depois.
    }
  }

  return isValid;
};

export const deleteLocalAccount = async (): Promise<void> => {
  try {
    await SecureStore.deleteItemAsync(ACCOUNT_KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Continua para limpar fallback.
  }

  await AsyncStorage.removeItem(ACCOUNT_KEY);
};
