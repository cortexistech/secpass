// Merge do cofre por item ao receber uma versao vinda do CloudKit
// (ver src/services/storage.ts e o modulo nativo em
// modules/secure-vault-cloudkit). Cada credencial e um registro; o merge
// ainda e usado quando ha cache local + remoto ou migracao do Keychain.
//
// Exclusoes viram tombstones `{ id, tombstone: true, deletedAt }` no blob.
// O merge honra o timestamp mais recente entre `updatedAt` e `deletedAt`,
// para um delete offline nao ser desfeito por uma copia antiga no outro
// aparelho.
import type { VaultItem } from "./vaultCrypto";

export const isVaultTombstone = (item: Partial<VaultItem> | null | undefined): boolean =>
  Boolean(item?.tombstone);

export const getVisibleVaultItems = (items: VaultItem[] | null | undefined): VaultItem[] =>
  (Array.isArray(items) ? items : []).filter((item) => !isVaultTombstone(item));

export const createVaultTombstone = (
  id: string,
  deletedAt: number = Date.now(),
): VaultItem => ({
  id,
  tombstone: true,
  deletedAt,
});

const itemRevision = (item: Partial<VaultItem>): number =>
  Math.max(Number(item?.updatedAt) || 0, Number(item?.deletedAt) || 0);

export const mergeVaultItems = (
  localItems: VaultItem[] | null | undefined,
  remoteItems: VaultItem[] | null | undefined,
): VaultItem[] => {
  const safeLocal = Array.isArray(localItems) ? localItems : [];
  const safeRemote = Array.isArray(remoteItems) ? remoteItems : [];

  const merged = new Map(safeLocal.map((item) => [item.id, item]));

  for (const remoteItem of safeRemote) {
    const localItem = merged.get(remoteItem.id);
    if (!localItem) {
      merged.set(remoteItem.id, remoteItem);
      continue;
    }

    if (itemRevision(remoteItem) > itemRevision(localItem)) {
      merged.set(remoteItem.id, remoteItem);
    }
  }

  return Array.from(merged.values());
};
