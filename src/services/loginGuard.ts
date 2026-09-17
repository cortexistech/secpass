import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";

const LOGIN_GUARD_KEY = "secpass_login_guard";
const SECURE_STORE_OPTIONS = {
  keychainService: "secpass.login-guard",
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export interface LoginGuardState {
  failedAttempts: number;
  lockLevel: number;
  lockUntil: number;
}

const parseGuard = (rawValue: string | null): LoginGuardState | null => {
  if (!rawValue) {
    return null;
  }

  try {
    const parsed = JSON.parse(rawValue);

    return {
      failedAttempts: Number(parsed?.failedAttempts) || 0,
      lockLevel: Number(parsed?.lockLevel) || 0,
      lockUntil: Number(parsed?.lockUntil) || 0,
    };
  } catch {
    return null;
  }
};

export const loadLoginGuard = async (): Promise<LoginGuardState | null> => {
  try {
    const secureValue = await SecureStore.getItemAsync(
      LOGIN_GUARD_KEY,
      SECURE_STORE_OPTIONS,
    );
    const parsedSecureValue = parseGuard(secureValue);

    if (parsedSecureValue) {
      return parsedSecureValue;
    }
  } catch {
    // Continua com fallback para preservar lock local em ambientes sem SecureStore.
  }

  const legacyValue = await AsyncStorage.getItem(LOGIN_GUARD_KEY);
  const parsedLegacyValue = parseGuard(legacyValue);

  if (!parsedLegacyValue) {
    return null;
  }

  try {
    await SecureStore.setItemAsync(
      LOGIN_GUARD_KEY,
      JSON.stringify(parsedLegacyValue),
      SECURE_STORE_OPTIONS,
    );
    await AsyncStorage.removeItem(LOGIN_GUARD_KEY);
  } catch {
    // Mantem legado ate proxima tentativa de migracao.
  }

  return parsedLegacyValue;
};

export const saveLoginGuard = async ({
  failedAttempts,
  lockLevel,
  lockUntil,
}: LoginGuardState): Promise<void> => {
  const payload = JSON.stringify({
    failedAttempts,
    lockLevel,
    lockUntil,
  });

  try {
    await SecureStore.setItemAsync(
      LOGIN_GUARD_KEY,
      payload,
      SECURE_STORE_OPTIONS,
    );
    await AsyncStorage.removeItem(LOGIN_GUARD_KEY);
  } catch {
    // Mantem apenas armazenamento seguro.
  }
};

export const clearLoginGuard = async (): Promise<void> => {
  try {
    await SecureStore.deleteItemAsync(LOGIN_GUARD_KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Continua para limpar fallback.
  }

  await AsyncStorage.removeItem(LOGIN_GUARD_KEY);
};
