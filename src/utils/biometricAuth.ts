import * as LocalAuthentication from "expo-local-authentication";

export async function authenticateVaultAccess(): Promise<
  LocalAuthentication.LocalAuthenticationResult | { success: false; error: string }
> {
  const hasHardware = await LocalAuthentication.hasHardwareAsync();
  const isEnrolled = await LocalAuthentication.isEnrolledAsync();

  if (!hasHardware || !isEnrolled) {
    return {
      success: false,
      error: "not_available",
    };
  }

  return LocalAuthentication.authenticateAsync({
    promptMessage: "Desbloquear cofre de senhas",
    cancelLabel: "Cancelar",
  });
}
