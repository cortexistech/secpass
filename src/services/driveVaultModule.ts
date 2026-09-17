// Backend de sincronizacao via Google Drive (appDataFolder), com o mesmo
// contrato que modules/secure-vault-cloudkit expoe no iOS (ver
// src/services/storage.ts): getAccountStatusAsync, fetchVaultMetaAsync,
// saveVaultMetaAsync, fetchCredentialsAsync, upsertCredentialsAsync,
// deleteVaultAsync. O Drive so guarda ciphertext - os dois arquivos
// (vault_meta.json e credentials.json) tem o mesmo formato que ja e
// persistido hoje no CloudKit, so o transporte muda.
import { mergeVaultItems } from "./vaultMerge";
import { getValidAccessToken } from "./driveAuth";
import type { VaultItem } from "./vaultCrypto";

const DRIVE_FILES_URL = "https://www.googleapis.com/drive/v3/files";
const DRIVE_UPLOAD_URL = "https://www.googleapis.com/upload/drive/v3/files";

const VAULT_META_FILE = "vault_meta.json";
const CREDENTIALS_FILE = "credentials.json";

export interface RemoteVaultRecord {
  id: string;
  envelope: string;
  updatedAt: number;
  tombstone: boolean;
}

export type RemoteVaultAccountStatus = "available" | "unavailable";

const authorizedFetch = async (
  url: string,
  options: RequestInit = {},
): Promise<Response> => {
  const accessToken = await getValidAccessToken();
  if (!accessToken) {
    throw new Error("Sincronizacao com Google Drive nao autenticada.");
  }

  const response = await fetch(url, {
    ...options,
    headers: {
      ...((options.headers as Record<string, string>) || {}),
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Falha na chamada ao Google Drive (${response.status}).`);
  }

  return response;
};

const findFileId = async (name: string): Promise<string | null> => {
  const query = encodeURIComponent(`name = '${name}' and trashed = false`);
  const url = `${DRIVE_FILES_URL}?spaces=appDataFolder&q=${query}&fields=files(id,name)`;
  const response = await authorizedFetch(url);
  const data = await response.json();
  return data?.files?.[0]?.id || null;
};

const readJsonFile = async (name: string): Promise<unknown> => {
  const fileId = await findFileId(name);
  if (!fileId) {
    return null;
  }

  const response = await authorizedFetch(`${DRIVE_FILES_URL}/${fileId}?alt=media`);
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

const createJsonFile = async (name: string, value: unknown): Promise<void> => {
  const boundary = "secpass-vault-sync-boundary";
  const metadata = JSON.stringify({ name, parents: ["appDataFolder"] });
  const body =
    `--${boundary}\r\n` +
    "Content-Type: application/json; charset=UTF-8\r\n\r\n" +
    `${metadata}\r\n` +
    `--${boundary}\r\n` +
    "Content-Type: application/json; charset=UTF-8\r\n\r\n" +
    `${JSON.stringify(value)}\r\n` +
    `--${boundary}--`;

  await authorizedFetch(`${DRIVE_UPLOAD_URL}?uploadType=multipart`, {
    method: "POST",
    headers: { "Content-Type": `multipart/related; boundary=${boundary}` },
    body,
  });
};

const updateJsonFile = async (fileId: string, value: unknown): Promise<void> => {
  await authorizedFetch(`${DRIVE_UPLOAD_URL}/${fileId}?uploadType=media`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(value),
  });
};

const writeJsonFile = async (name: string, value: unknown): Promise<void> => {
  const fileId = await findFileId(name);
  if (fileId) {
    await updateJsonFile(fileId, value);
  } else {
    await createJsonFile(name, value);
  }
};

const deleteFileIfExists = async (name: string): Promise<void> => {
  const fileId = await findFileId(name);
  if (!fileId) {
    return;
  }
  await authorizedFetch(`${DRIVE_FILES_URL}/${fileId}`, { method: "DELETE" });
};

const getAccountStatusAsync = async (): Promise<RemoteVaultAccountStatus> => {
  const accessToken = await getValidAccessToken();
  return accessToken ? "available" : "unavailable";
};

const fetchVaultMetaAsync = async (): Promise<unknown> => readJsonFile(VAULT_META_FILE);

const saveVaultMetaAsync = async (meta: unknown): Promise<void> =>
  writeJsonFile(VAULT_META_FILE, meta);

const fetchCredentialsAsync = async (): Promise<RemoteVaultRecord[]> => {
  const records = await readJsonFile(CREDENTIALS_FILE);
  return Array.isArray(records) ? records : [];
};

// Read-modify-write num unico arquivo: mais simples que um arquivo por
// credencial (como o CloudKit faz com records nativos) e suficiente pra um
// numero pequeno de aparelhos por usuario. O merge por item (updatedAt /
// tombstone) e o mesmo de src/services/vaultMerge.ts, que ja opera nos
// campos externos do record sem precisar decifrar o envelope.
const upsertCredentialsAsync = async (records: RemoteVaultRecord[]): Promise<void> => {
  const current = await fetchCredentialsAsync();
  const merged = mergeVaultItems(
    current as unknown as VaultItem[],
    records as unknown as VaultItem[],
  );
  await writeJsonFile(CREDENTIALS_FILE, merged);
};

const deleteVaultAsync = async (): Promise<void> => {
  await deleteFileIfExists(VAULT_META_FILE);
  await deleteFileIfExists(CREDENTIALS_FILE);
};

export default {
  getAccountStatusAsync,
  fetchVaultMetaAsync,
  saveVaultMetaAsync,
  fetchCredentialsAsync,
  upsertCredentialsAsync,
  deleteVaultAsync,
};
