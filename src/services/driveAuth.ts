// iOS: SDK nativo (Play Services no Android seria o equivalente, GoogleSignIn
// nativo no iOS), usada so para o escopo drive.appdata - o token nunca da
// acesso ao Drive visivel do usuario, so a pasta oculta do proprio app.
//
// Android: fluxo OAuth via navegador (mesmo principio do app desktop, ver
// desktop/src/main/core/driveAuth.js), NAO o SDK nativo. Motivo: o SDK
// nativo (GoogleSignin.signIn + requestScopes) falha de forma consistente e
// reproduzida em 4 certificados diferentes (EAS, release local, debug
// local, debug de emulador) ao pedir o escopo sensivel drive.appdata,
// sempre com "AutoManageHelper: Unresolved error while connecting client."
// no logcat - bate com relatos de terceiros de que escopos sensiveis via
// SDK nativo Android exigem instalacao via Play Store (nao algo que da pra
// depender aqui). iOS com o mesmo SDK/mesmo escopo funciona normalmente,
// entao so o Android foi trocado.
import { Platform } from "react-native";
import Constants from "expo-constants";
import * as SecureStore from "expo-secure-store";
import * as WebBrowser from "expo-web-browser";
import QuickCrypto from "react-native-quick-crypto";
import { GoogleSignin } from "@react-native-google-signin/google-signin";

const DRIVE_APPDATA_SCOPE = "https://www.googleapis.com/auth/drive.appdata";

// Fallback fixo: em builds fora do fluxo padrao do EAS (ex: `expo run:ios`
// direto, sem dev-launcher), o modulo nativo que expo-constants usa pra
// entregar o manifesto (EXDevLauncher) pode nao existir, deixando
// Constants.expoConfig vazio mesmo com o Metro servindo a config
// corretamente. O client ID do Google e um identificador publico (nao e
// segredo), entao usar um valor fixo como reserva aqui e seguro e evita
// depender de um mecanismo de manifesto fragil so pra entregar esse unico
// valor. Mantido sincronizado manualmente com app.json (expo.extra.googleIosClientId).
const GOOGLE_IOS_CLIENT_ID_FALLBACK =
  "114456559466-ko4p814or855id67eb000i5ipjojdtrr.apps.googleusercontent.com";

let isConfigured = false;
const ensureConfigured = (): void => {
  if (isConfigured) {
    return;
  }

  const iosClientId =
    (Constants.expoConfig?.extra?.googleIosClientId as string | undefined) ||
    GOOGLE_IOS_CLIENT_ID_FALLBACK;
  try {
    GoogleSignin.configure({
      scopes: [DRIVE_APPDATA_SCOPE],
      ...(Platform.OS === "ios" ? { iosClientId } : {}),
    });
    isConfigured = true;
  } catch {
    // Configuracao ausente/invalida - trata
    // como "Drive indisponivel neste aparelho" em vez de derrubar o app;
    // quem chama (isDriveSignedIn/getValidAccessToken) ja trata ausencia de
    // sessao como sync indisponivel, nunca como erro fatal do cofre local.
  }
};

// --- Android: fluxo OAuth via navegador -------------------------------

// Mesmo client "iOS" ja usado pelo GoogleSignin nativo no iPhone (ver
// ensureConfigured acima / plugins/withAndroidGoogleOAuthRedirect.js) -
// reaproveitado de proposito, nao um client "Android" novo: o objetivo e
// justamente sair do caminho que amarra a um client tipo Android. Esse
// tipo de client nao tem client_secret (fluxo publico/PKCE).
const ANDROID_OAUTH_CLIENT_ID =
  "114456559466-ko4p814or855id67eb000i5ipjojdtrr.apps.googleusercontent.com";
const ANDROID_REDIRECT_URI =
  "com.googleusercontent.apps.114456559466-ko4p814or855id67eb000i5ipjojdtrr:/oauth2redirect";
const ANDROID_REFRESH_TOKEN_KEY = "secpass_drive_refresh_token_android";
const ANDROID_SECURE_STORE_OPTIONS = {
  keychainService: "secpass.driveAuth",
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};
const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const EXPIRY_SAFETY_MARGIN_MS = 60_000;

interface CachedAccessToken {
  token: string;
  expiresAt: number;
}

let androidCachedAccessToken: CachedAccessToken | null = null;

// QuickCrypto.randomBytes/createHash(...).digest() devolvem um Buffer com
// toString(encoding) (API do node:crypto), nao o Uint8Array.toString() sem
// argumentos do lib padrao do TS - ver mesmo ajuste em shared/vaultCrypto.ts.
const base64url = (buffer: { toString(encoding: string): string }): string =>
  buffer.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

// RN/Hermes nao tem URL/URLSearchParams disponivel sem um polyfill que este
// projeto nao instala (ver src/services/driveVaultModule.ts, que ja
// constroi URLs por concatenacao de string pelo mesmo motivo) - por isso
// as duas funcoes abaixo, em vez de `new URL(...)`/`new URLSearchParams(...)`.
const toFormBody = (params: Record<string, string>): string =>
  Object.entries(params)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`)
    .join("&");

const parseQueryParams = (url: string): Record<string, string> => {
  const queryIndex = url.indexOf("?");
  if (queryIndex === -1) {
    return {};
  }

  const params: Record<string, string> = {};
  for (const pair of url.slice(queryIndex + 1).split("&")) {
    if (!pair) continue;
    const [key, rawValue = ""] = pair.split("=");
    params[decodeURIComponent(key)] = decodeURIComponent(rawValue.replace(/\+/g, " "));
  }
  return params;
};

const readAndroidRefreshToken = async (): Promise<string | null> => {
  try {
    return await SecureStore.getItemAsync(ANDROID_REFRESH_TOKEN_KEY, ANDROID_SECURE_STORE_OPTIONS);
  } catch {
    return null;
  }
};

const writeAndroidRefreshToken = async (token: string): Promise<void> => {
  await SecureStore.setItemAsync(ANDROID_REFRESH_TOKEN_KEY, token, ANDROID_SECURE_STORE_OPTIONS);
};

const deleteAndroidRefreshToken = async (): Promise<void> => {
  try {
    await SecureStore.deleteItemAsync(ANDROID_REFRESH_TOKEN_KEY, ANDROID_SECURE_STORE_OPTIONS);
  } catch {
    // Best-effort.
  }
};

export interface SignInResult {
  success: boolean;
  cancelled: boolean;
}

// Inicia o fluxo interativo (abre o navegador do sistema/Custom Tab). So
// deve ser chamado a partir de uma acao explicita do usuario, mesmo
// principio do fluxo nativo.
const signInWithGoogleDriveAndroid = async (): Promise<SignInResult> => {
  const codeVerifier = base64url(QuickCrypto.randomBytes(32));
  const codeChallenge = base64url(
    QuickCrypto.createHash("sha256").update(codeVerifier).digest(),
  );
  const state = base64url(QuickCrypto.randomBytes(16));

  const authUrl = `${AUTH_ENDPOINT}?${toFormBody({
    client_id: ANDROID_OAUTH_CLIENT_ID,
    redirect_uri: ANDROID_REDIRECT_URI,
    response_type: "code",
    scope: DRIVE_APPDATA_SCOPE,
    access_type: "offline",
    prompt: "consent",
    state,
    code_challenge: codeChallenge,
    code_challenge_method: "S256",
  })}`;

  let result: WebBrowser.WebBrowserAuthSessionResult;
  try {
    result = await WebBrowser.openAuthSessionAsync(authUrl, ANDROID_REDIRECT_URI);
  } catch {
    throw new Error("Falha ao autenticar com o Google.");
  }

  if (result.type !== "success" || !("url" in result) || !result.url) {
    return { success: false, cancelled: true };
  }

  const { state: receivedState, code, error } = parseQueryParams(result.url);

  if (error === "access_denied") {
    return { success: false, cancelled: true };
  }
  if (error || !code || receivedState !== state) {
    throw new Error("Falha ao autenticar com o Google.");
  }

  const tokenResponse = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: toFormBody({
      client_id: ANDROID_OAUTH_CLIENT_ID,
      code,
      code_verifier: codeVerifier,
      redirect_uri: ANDROID_REDIRECT_URI,
      grant_type: "authorization_code",
    }),
  });

  if (!tokenResponse.ok) {
    throw new Error("Falha ao autenticar com o Google.");
  }

  const tokenData = await tokenResponse.json();
  if (tokenData.refresh_token) {
    await writeAndroidRefreshToken(tokenData.refresh_token);
  }
  androidCachedAccessToken = {
    token: tokenData.access_token,
    expiresAt: Date.now() + (tokenData.expires_in || 0) * 1000,
  };

  return { success: true, cancelled: false };
};

const refreshAndroidAccessToken = async (
  refreshToken: string,
): Promise<{ access_token: string; expires_in?: number } | null> => {
  const response = await fetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: toFormBody({
      client_id: ANDROID_OAUTH_CLIENT_ID,
      refresh_token: refreshToken,
      grant_type: "refresh_token",
    }),
  });

  if (!response.ok) {
    return null;
  }
  return response.json();
};

const getValidAccessTokenAndroid = async (): Promise<string | null> => {
  const refreshToken = await readAndroidRefreshToken();
  if (!refreshToken) {
    return null;
  }

  if (
    androidCachedAccessToken &&
    Date.now() < androidCachedAccessToken.expiresAt - EXPIRY_SAFETY_MARGIN_MS
  ) {
    return androidCachedAccessToken.token;
  }

  const refreshed = await refreshAndroidAccessToken(refreshToken);
  if (!refreshed?.access_token) {
    return null;
  }

  androidCachedAccessToken = {
    token: refreshed.access_token,
    expiresAt: Date.now() + (refreshed.expires_in || 0) * 1000,
  };
  return androidCachedAccessToken.token;
};

const isDriveSignedInAndroid = async (): Promise<boolean> =>
  Boolean(await readAndroidRefreshToken());

const signOutDriveAndroid = async (): Promise<void> => {
  await deleteAndroidRefreshToken();
  androidCachedAccessToken = null;
};

// --- API publica, despachando por plataforma ---------------------------

export const signInWithGoogleDrive = async (): Promise<SignInResult> => {
  if (Platform.OS === "android") {
    return signInWithGoogleDriveAndroid();
  }

  ensureConfigured();
  try {
    await GoogleSignin.hasPlayServices({ showPlayServicesUpdateDialog: true });
    const result = await GoogleSignin.signIn();

    if (result.type !== "success") {
      return { success: false, cancelled: true };
    }

    return { success: true, cancelled: false };
  } catch {
    throw new Error("Falha ao autenticar com o Google.");
  }
};

// Devolve um access token valido para o escopo drive.appdata, ou null se
// nunca autenticou ou se a sessao nao pode ser renovada (ex: usuario
// revogou acesso na conta Google) - quem chama trata isso como "sync
// indisponivel", nunca como erro fatal do cofre local.
export const getValidAccessToken = async (): Promise<string | null> => {
  if (Platform.OS === "android") {
    return getValidAccessTokenAndroid();
  }

  ensureConfigured();
  if (!isConfigured || !GoogleSignin.hasPreviousSignIn()) {
    return null;
  }

  try {
    await GoogleSignin.signInSilently();
    const { accessToken } = await GoogleSignin.getTokens();
    return accessToken || null;
  } catch {
    return null;
  }
};

export const isDriveSignedIn = async (): Promise<boolean> => {
  if (Platform.OS === "android") {
    return isDriveSignedInAndroid();
  }

  ensureConfigured();
  if (!isConfigured) {
    return false;
  }
  return GoogleSignin.hasPreviousSignIn();
};

export const signOutDrive = async (): Promise<void> => {
  if (Platform.OS === "android") {
    await signOutDriveAndroid();
    return;
  }

  try {
    await GoogleSignin.signOut();
  } catch {
    // Best-effort: pior caso a sessao fica ativa ate a proxima tentativa.
  }
};
