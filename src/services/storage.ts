import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";
import { Platform } from "react-native";
import {
  createVaultMeta,
  decryptVaultEnvelope,
  decryptVaultItem,
  emailFromVaultSecret,
  encryptVaultItem,
  encryptVaultItems,
  unlockVaultKeys,
  type EncryptedVaultEnvelope,
  type VaultItem,
  type VaultItemRevision,
  type VaultMeta,
} from "./vaultCrypto";
import { mergeVaultItems } from "./vaultMerge";
import { isDriveSignedIn, signOutDrive } from "./driveAuth";
import {
  SYNC_BACKEND_ICLOUD,
  getSyncBackendPreference,
} from "./syncPreference";
import {
  DEVICE_AUTH_NOT_CONFIGURED,
  isDeviceAuthNotConfiguredError,
} from "../utils/secureStoreErrors";
import { logSecurityEvent } from "./securityAudit";
import type { RemoteVaultAccountStatus, RemoteVaultRecord } from "./driveVaultModule";

const KEY = "passwords";
const STORAGE_WRITE_ERROR =
  "Nao foi possivel salvar o cofre com seguranca neste dispositivo.";
const VAULT_SECRET_REQUIRED =
  "Nao e possivel salvar o cofre sem a senha de acesso.";
export const VAULT_DELETE_ERROR =
  "Nao foi possivel apagar o cofre sincronizado. Tente novamente.";
export const SYNC_BACKEND_UNAVAILABLE =
  "Este backend de sincronizacao nao esta disponivel neste aparelho.";
const SECURE_STORE_OPTIONS = {
  keychainService: "secpass.vault",
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export interface RemoteVaultModule {
  getAccountStatusAsync(): Promise<RemoteVaultAccountStatus>;
  fetchVaultMetaAsync(): Promise<unknown>;
  saveVaultMetaAsync(meta: unknown): Promise<void>;
  fetchCredentialsAsync(): Promise<RemoteVaultRecord[]>;
  upsertCredentialsAsync(records: RemoteVaultRecord[]): Promise<void>;
  deleteVaultAsync(): Promise<void>;
}

const getCloudKitModule = (): RemoteVaultModule | null => {
  if (Platform.OS !== "ios") {
    return null;
  }

  try {
    return require("../../modules/secure-vault-cloudkit/src/SecureVaultCloudKitModule")
      .default;
  } catch {
    return null;
  }
};

// So retorna o modulo Drive se ja houver sessao Google autenticada: sem
// login explicito do usuario nao ha "sync habilitado" (ver
// src/services/driveAuth.ts - login e sempre uma acao explicita, nunca
// automatica no boot). Disponivel tanto no Android quanto no iOS - e o
// mecanismo que permite Mac, iPhone e Android compartilharem o mesmo cofre
// com a mesma conta Google, sem depender de CloudKit (exclusivo Apple).
const getDriveVaultModule = async (): Promise<RemoteVaultModule | null> => {
  try {
    const signedIn = await isDriveSignedIn();
    if (!signedIn) {
      return null;
    }
    return require("./driveVaultModule").default;
  } catch {
    return null;
  }
};

// Ponto unico de despacho do backend remoto: qual dos dois usar e uma
// escolha explicita do usuario (ver src/services/syncPreference.ts), nao
// mais um fallback automatico. Drive e o mecanismo hibrido (Android + iOS +
// Mac, mesma conta Google); CloudKit e exclusivo Apple (so iPhone e Mac).
// Retornar null aqui e um estado normal ("sync desativado/indisponivel
// neste aparelho" -> cofre 100% local) - tornar isso visivel pro usuario e
// responsabilidade da UI (ver peekRemoteVault), nao deste ponto de
// despacho, pra nao quebrar o invariante de que salvar/carregar local
// nunca falha por causa do backend remoto escolhido.
const getRemoteVaultModule = async (): Promise<RemoteVaultModule | null> => {
  const preference = await getSyncBackendPreference();

  if (preference === SYNC_BACKEND_ICLOUD) {
    return getCloudKitModule();
  }

  return getDriveVaultModule();
};

interface LegacyKeychainSyncModule {
  getItemAsync(key: string, keychainService: string): Promise<string | null>;
  deleteItemAsync(key: string, keychainService: string): Promise<void>;
}

// Legado: blob unico no iCloud Keychain, usado so para migrar para CloudKit.
const getLegacyKeychainSyncModule = (): LegacyKeychainSyncModule | null => {
  if (Platform.OS !== "ios") {
    return null;
  }

  try {
    return require("../../modules/secure-vault-sync/src/SecureVaultSyncModule")
      .default;
  } catch {
    return null;
  }
};

const isEncryptedEnvelope = (parsed: unknown): parsed is EncryptedVaultEnvelope =>
  (parsed as { type?: string })?.type === "encrypted_vault";

const writeLocalVault = async (payload: string): Promise<void> => {
  await SecureStore.setItemAsync(KEY, payload, SECURE_STORE_OPTIONS);
};

// Usado so pelo reset de "esqueci minha senha": apaga o cache local (que
// ficaria inutil, cifrado com a senha antiga) sem tocar no cofre remoto -
// outro aparelho que ainda saiba a senha antiga continua acessando o cofre
// sincronizado normalmente. Sem isso, a proxima loadPasswords() neste
// aparelho ainda encontra o blob antigo em SecureStore e tenta decifra-lo
// com o vaultSecret da conta NOVA, falhando com "Falha de integridade do
// cofre." (mesmo bug ja corrigido no app desktop, ver account:resetLocalAccess).
export const clearLocalVaultCache = async (): Promise<void> => {
  try {
    await SecureStore.deleteItemAsync(KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Best-effort - proxima gravacao sobrescreve de qualquer forma.
  }
  await AsyncStorage.removeItem(KEY);
};

const readLegacyKeychainVault = async (): Promise<string | null> => {
  const vaultSync = getLegacyKeychainSyncModule();
  if (!vaultSync) {
    return null;
  }

  try {
    return await vaultSync.getItemAsync(
      KEY,
      SECURE_STORE_OPTIONS.keychainService,
    );
  } catch {
    return null;
  }
};

// Retorna se a exclusao realmente aconteceu (ou se nao havia nada a
// excluir) - so no fluxo de "Excluir conta e todos os dados" (clearVault)
// isso importa de verdade: silenciar essa falha ali faria o app reportar
// exclusao total quando o blob cifrado do cofre legado pode continuar
// retido no circulo de iCloud Keychain do usuario.
const deleteLegacyKeychainVault = async (): Promise<boolean> => {
  const vaultSync = getLegacyKeychainSyncModule();
  if (!vaultSync) {
    return true;
  }

  try {
    await vaultSync.deleteItemAsync(KEY, SECURE_STORE_OPTIONS.keychainService);
    return true;
  } catch {
    // Migracao ja foi para CloudKit; limpeza do Keychain e best-effort nos
    // fluxos de save/load (proxima gravacao tenta de novo) - so clearVault
    // trata o retorno false como algo a registrar.
    return false;
  }
};

const parseData = (rawValue: string | null): VaultItem[] => {
  if (!rawValue) return [];

  try {
    const parsed = JSON.parse(rawValue);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

const parsePayload = (rawValue: string | null | undefined): unknown => {
  if (!rawValue) {
    return null;
  }

  try {
    return JSON.parse(rawValue);
  } catch {
    return null;
  }
};

const encryptPayload = async (items: VaultItem[], vaultSecret: string): Promise<string> =>
  JSON.stringify(await encryptVaultItems(items, vaultSecret));

const toMetaShape = (rawMeta: unknown): VaultMeta | null => {
  if (!rawMeta) {
    return null;
  }

  const meta = rawMeta as Record<string, unknown>;
  const kdf = meta.kdf as Record<string, unknown> | undefined;

  if (kdf?.salt) {
    return rawMeta as VaultMeta;
  }

  return {
    type: "vault_meta",
    version: (meta.version as number) || 1,
    email: (meta.email as string) || "",
    kdf: {
      name: (meta.kdfName as string) || "pbkdf2-sha256",
      iterations: (meta.iterations as number) || 310000,
      salt: (meta.salt as string) || "",
    },
    verifier: (meta.verifier as string) || "",
  };
};

const parseLoadedData = async (
  rawValue: string | null,
  vaultSecret?: string,
): Promise<VaultItem[]> => {
  const parsedPayload = parsePayload(rawValue);

  if (Array.isArray(parsedPayload)) {
    return parsedPayload;
  }

  if (isEncryptedEnvelope(parsedPayload)) {
    if (!vaultSecret) {
      throw new Error("Cofre criptografado. Faca login novamente.");
    }

    return decryptVaultEnvelope(parsedPayload, vaultSecret);
  }

  return parseData(rawValue);
};

// Um unico registro remoto corrompido/adulterado (auth tag invalido, JSON
// malformado) nao deve derrubar o carregamento do cofre inteiro - descarta
// so o item afetado. So um erro de integridade do PROPRIO meta/verifier
// (ver unlockVaultKeys, chamado antes desta funcao) deve propagar e travar
// o load: isso sim significa "senha errada para este cofre", nao "um item
// especifico esta corrompido".
const decryptRemoteVaultItems = (
  records: RemoteVaultRecord[],
  keys: ReturnType<typeof unlockVaultKeys>,
): VaultItem[] => {
  const items: VaultItem[] = [];

  for (const record of Array.isArray(records) ? records : []) {
    try {
      const envelope =
        typeof record?.envelope === "string"
          ? parsePayload(record.envelope)
          : record?.envelope;
      const revision: VaultItemRevision = {
        revisionAt: Number(record?.updatedAt || 0),
        tombstone: Boolean(record?.tombstone),
      };
      items.push(decryptVaultItem(envelope as never, keys, revision));
    } catch {
      // Item individual descartado; o resto do cofre continua acessivel.
    }
  }

  return items;
};

const pushItemsToRemoteVault = async (
  remoteVault: RemoteVaultModule,
  items: VaultItem[],
  vaultSecret: string,
): Promise<void> => {
  const rawMeta = await remoteVault.fetchVaultMetaAsync();
  let meta = toMetaShape(rawMeta);

  if (!meta?.verifier) {
    meta = createVaultMeta({
      vaultSecret,
      email: emailFromVaultSecret(vaultSecret),
    });
    await remoteVault.saveVaultMetaAsync({
      email: meta.email,
      version: meta.version,
      kdfName: meta.kdf.name,
      iterations: meta.kdf.iterations,
      salt: meta.kdf.salt,
      verifier: meta.verifier,
    });
  }

  const keys = unlockVaultKeys(meta, vaultSecret);
  const records: RemoteVaultRecord[] = (Array.isArray(items) ? items : []).map(
    (item) => {
      const revision: VaultItemRevision = {
        revisionAt: Number(item.updatedAt || item.deletedAt || 0),
        tombstone: Boolean(item.tombstone),
      };
      return {
        id: String(item.id),
        envelope: JSON.stringify(encryptVaultItem(item, keys, revision)),
        updatedAt: revision.revisionAt || 0,
        tombstone: revision.tombstone || false,
      };
    },
  );

  await remoteVault.upsertCredentialsAsync(records);
};

// Resolve o modulo de um backend especifico (nao o preferido/ativo) - usado
// pela UI de configuracao para obter "de onde" e "para onde" migrar, sem
// depender da preferencia gravada (que so muda apos a migracao dar certo).
export const getVaultModuleForBackend = async (
  backendId: string,
): Promise<RemoteVaultModule | null> => {
  if (backendId === SYNC_BACKEND_ICLOUD) {
    return getCloudKitModule();
  }

  return getDriveVaultModule();
};

// Copia o cofre remoto (meta + credenciais, ainda cifradas) de um backend
// para outro, sem nunca decifrar os itens - so valida que a senha atual
// abre o cofre de origem antes de copiar, pra nao levar dados de uma conta
// que essa senha nao pertence. Nao apaga a origem: a migracao e aditiva,
// entao um dispositivo que ainda nao trocou de preferencia continua vendo
// o cofre antigo intacto. Quem chama so deve persistir a nova preferencia
// depois desta funcao resolver sem lancar.
export const migrateVaultBackend = async ({
  fromModule,
  toModule,
  vaultSecret,
}: {
  fromModule: RemoteVaultModule | null;
  toModule: RemoteVaultModule | null;
  vaultSecret: string;
}): Promise<void> => {
  if (!toModule || (await toModule.getAccountStatusAsync()) !== "available") {
    throw new Error(SYNC_BACKEND_UNAVAILABLE);
  }

  if (!fromModule) {
    return;
  }

  const fromStatus = await fromModule.getAccountStatusAsync();
  const rawMeta =
    fromStatus === "available" ? await fromModule.fetchVaultMetaAsync() : null;
  const meta = toMetaShape(rawMeta);

  if (!meta?.verifier) {
    return;
  }

  unlockVaultKeys(meta, vaultSecret);

  await toModule.saveVaultMetaAsync(rawMeta);

  const records = await fromModule.fetchCredentialsAsync();
  if (Array.isArray(records) && records.length > 0) {
    await toModule.upsertCredentialsAsync(records);
  }
};

export const peekRemoteVault = async (): Promise<{
  available: boolean;
  status: string;
  meta: VaultMeta | null;
}> => {
  const remoteVault = await getRemoteVaultModule();
  if (!remoteVault) {
    return { available: false, status: "unsupported", meta: null };
  }

  try {
    const status = await remoteVault.getAccountStatusAsync();
    if (status !== "available") {
      return { available: false, status, meta: null };
    }

    const rawMeta = await remoteVault.fetchVaultMetaAsync();
    return {
      available: true,
      status,
      meta: toMetaShape(rawMeta),
    };
  } catch {
    return { available: false, status: "error", meta: null };
  }
};

// So pra mostrar um resumo de sanidade ao usuario ANTES de um aparelho
// novo aceitar um cofre remoto existente pela primeira vez (nao ha cofre
// local pra comparar nesse momento - ver comentario em
// src/screens/HomeScreen.tsx, branch de registro com hasRemoteVault). Nao
// decifra nada: updatedAt/tombstone de cada record ja vem em texto claro.
// Chamar so quando a confirmacao for realmente necessaria, nao no boot do
// app - fetchCredentialsAsync e uma chamada de rede a mais que a maioria
// dos usuarios (que ja tem conta local) nao precisa pagar toda vez.
export const peekRemoteVaultSummary = async (): Promise<{
  itemCount: number;
  lastModifiedAt: number | null;
} | null> => {
  const remoteVault = await getRemoteVaultModule();
  if (!remoteVault) {
    return null;
  }

  try {
    const status = await remoteVault.getAccountStatusAsync();
    if (status !== "available") {
      return null;
    }

    const records = await remoteVault.fetchCredentialsAsync();
    const activeRecords = (Array.isArray(records) ? records : []).filter(
      (record) => !record?.tombstone,
    );
    const lastModifiedAt = activeRecords.reduce(
      (max, record) => Math.max(max, Number(record?.updatedAt) || 0),
      0,
    );

    return {
      itemCount: activeRecords.length,
      lastModifiedAt: lastModifiedAt || null,
    };
  } catch {
    return null;
  }
};

export const savePasswords = async (
  data: VaultItem[],
  { vaultSecret }: { vaultSecret?: string } = {},
): Promise<void> => {
  if (!vaultSecret) {
    throw new Error(VAULT_SECRET_REQUIRED);
  }

  const payload = await encryptPayload(data, vaultSecret);

  try {
    await writeLocalVault(payload);
    await AsyncStorage.removeItem(KEY);

    const remoteVault = await getRemoteVaultModule();
    if (remoteVault) {
      try {
        await pushItemsToRemoteVault(remoteVault, data, vaultSecret);
        await deleteLegacyKeychainVault();
      } catch {
        // Cache local ja foi gravado; o proximo unlock tenta o backend remoto de novo.
      }
    }

    return;
  } catch (err) {
    if (isDeviceAuthNotConfiguredError(err)) {
      throw new Error(DEVICE_AUTH_NOT_CONFIGURED);
    }
    throw new Error(STORAGE_WRITE_ERROR);
  }
};

export const loadPasswords = async ({
  vaultSecret,
}: { vaultSecret?: string } = {}): Promise<VaultItem[]> => {
  let cloudItems: VaultItem[] | null = null;
  const remoteVault = await getRemoteVaultModule();

  if (remoteVault && vaultSecret) {
    try {
      const rawMeta = await remoteVault.fetchVaultMetaAsync();
      const meta = toMetaShape(rawMeta);
      if (meta?.verifier) {
        const keys = unlockVaultKeys(meta, vaultSecret);
        const records = await remoteVault.fetchCredentialsAsync();
        cloudItems = decryptRemoteVaultItems(records, keys);
      }
    } catch (err) {
      if (
        typeof (err as { message?: unknown })?.message === "string" &&
        ((err as { message: string }).message.includes("integridade") ||
          (err as { message: string }).message.includes("Segredo do cofre") ||
          (err as { message: string }).message.includes("Metadados"))
      ) {
        throw err;
      }
      cloudItems = null;
    }
  }

  let localData: string | null = null;
  try {
    localData = await SecureStore.getItemAsync(KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Continua com backend remoto / legado.
  }

  const legacyKeychain = await readLegacyKeychainVault();
  const sources: VaultItem[][] = [];

  if (cloudItems) {
    sources.push(cloudItems);
  }

  if (localData) {
    sources.push(await parseLoadedData(localData, vaultSecret));
  }

  if (legacyKeychain) {
    sources.push(await parseLoadedData(legacyKeychain, vaultSecret));
  }

  if (sources.length === 0) {
    const legacyData = await AsyncStorage.getItem(KEY);
    const parsedLegacy = await parseLoadedData(legacyData, vaultSecret);

    if (legacyData && vaultSecret && remoteVault) {
      try {
        await pushItemsToRemoteVault(remoteVault, parsedLegacy, vaultSecret);
        await writeLocalVault(await encryptPayload(parsedLegacy, vaultSecret));
        await AsyncStorage.removeItem(KEY);
      } catch {
        // Mantem leitura legada.
      }
    }

    return parsedLegacy;
  }

  const merged = sources.reduce((acc, list) => mergeVaultItems(acc, list), [] as VaultItem[]);

  if (vaultSecret && remoteVault && !cloudItems) {
    try {
      await pushItemsToRemoteVault(remoteVault, merged, vaultSecret);
      await deleteLegacyKeychainVault();
    } catch {
      // Proxima gravacao tenta de novo.
    }
  }

  return merged;
};

export const clearVault = async (): Promise<void> => {
  const remoteVault = await getRemoteVaultModule();
  if (remoteVault) {
    try {
      const status = await remoteVault.getAccountStatusAsync();
      if (status === "available") {
        await remoteVault.deleteVaultAsync();
      }
    } catch {
      throw new Error(VAULT_DELETE_ERROR);
    }
  }

  const legacyKeychainDeleted = await deleteLegacyKeychainVault();
  if (!legacyKeychainDeleted) {
    // Nao interrompe a exclusao (o cofre remoto ativo e a conta local ja
    // foram apagados) - so registra que o blob legado no iCloud Keychain
    // sincronizavel pode ter ficado retido, pra nao dar falsa certeza de
    // exclusao total.
    logSecurityEvent({
      type: "vault_delete_incomplete",
      status: "warning",
      details: { reason: "legacy_keychain_delete_failed" },
    }).catch(() => {});
  }

  await signOutDrive();

  try {
    await SecureStore.deleteItemAsync(KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Continua para limpar fallback.
  }

  await AsyncStorage.removeItem(KEY);
};
