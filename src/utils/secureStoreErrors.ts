export const DEVICE_AUTH_NOT_CONFIGURED = "device_auth_not_configured";

export const isDeviceAuthNotConfiguredError = (err: unknown): boolean =>
  typeof (err as { message?: unknown })?.message === "string" &&
  /no user authentication method configured/i.test(
    (err as { message: string }).message,
  );
