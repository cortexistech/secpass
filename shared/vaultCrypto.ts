// Implementacao unica de criptografia do cofre, compartilhada entre o app
// mobile (src/services/vaultCrypto.ts, via react-native-quick-crypto) e o
// desktop (desktop/src/main/core/vaultCrypto.js, via node:crypto). As duas
// bibliotecas de crypto tem a mesma API (QuickCrypto foi feita pra ser
// compativel com node:crypto), entao aqui a logica fica so uma vez e cada
// plataforma injeta suas proprias primitivas via createVaultCrypto(adapter).
// O formato do envelope cifrado e identico nas duas, entao um cofre e
// compativel byte-a-byte entre mobile e desktop.
import { constantTimeCompare } from "./constantTimeCompare";

const VAULT_VERSION = 2;
const LEGACY_VAULT_VERSION = 1;
// v3 do envelope por item (encryptVaultItem/decryptVaultItem, usado so no
// registro remoto de sync): amarra updatedAt/tombstone na AAD do GCM junto
// com id, alem da versao. Sem isso, um backend remoto adulterado (Drive/
// CloudKit comprometido) pode reetiquetar um envelope antigo legitimo com
// um updatedAt forjado no futuro para vencer o merge (mergeVaultItems e
// last-write-wins) e ressuscitar permanentemente um item ja apagado ou
// reverter uma senha ja trocada - o merge nunca decifra nada, so compara
// esse campo em texto claro. Com a revisao amarrada na AAD, adulterar
// updatedAt/tombstone sem a senha mestra invalida o authTag e o item e
// descartado (ver decryptRemoteVaultItems), em vez de aceito com uma
// revisao forjada.
const ITEM_ENVELOPE_VERSION = 3;
// OWASP recomenda >=600k para PBKDF2-HMAC-SHA256 (2023+). So usado para
// novas contas/cofres: cofres existentes continuam com o valor gravado no
// proprio kdf.iterations, lido dinamicamente (nunca forcamos re-derivacao).
const PBKDF2_ITERATIONS = 600000;
// Fallback apenas para ler um envelope v1 legado que (por algum motivo)
// nao tenha "iterations" gravado - todo envelope v1 gerado em producao
// sempre gravou esse campo; isto e so uma rede de seguranca.
const LEGACY_PBKDF2_ITERATIONS = 310000;
const KEY_SIZE_BYTES = 64;
const GCM_NONCE_BYTES = 12;
const MAX_ITEM_FIELD_LENGTH = 4096;

// Node's Buffer.toString(encoding) tem uma assinatura diferente do
// Uint8Array.toString() padrao (0 argumentos) - usa intersection (nao
// "interface extends Uint8Array") pra nao colidir com o toString() nativo
// do lib.dom/lib.es5.
export type VaultCryptoBuffer = Uint8Array & { toString(encoding: string): string };

export interface CipherLike {
  setAAD(buffer: Uint8Array): void;
  update(data: Uint8Array): VaultCryptoBuffer;
  final(): VaultCryptoBuffer;
  getAuthTag(): VaultCryptoBuffer;
}

export interface DecipherLike {
  setAAD(buffer: Uint8Array): void;
  setAuthTag(buffer: Uint8Array): void;
  update(data: Uint8Array): VaultCryptoBuffer;
  final(): VaultCryptoBuffer;
}

export interface HmacLike {
  update(data: string): HmacLike;
  digest(encoding: "hex"): string;
}

export interface VaultCryptoBufferStatic {
  from(data: string | Uint8Array | number[], encoding?: string): VaultCryptoBuffer;
  concat(list: Uint8Array[]): VaultCryptoBuffer;
}

export interface VaultCryptoAdapter {
  pbkdf2Sync(
    secret: string,
    salt: Uint8Array,
    iterations: number,
    keylen: number,
    digest: string,
  ): Uint8Array;
  createHmac(algorithm: string, key: Uint8Array): HmacLike;
  createCipheriv(algorithm: string, key: Uint8Array, iv: Uint8Array): CipherLike;
  createDecipheriv(algorithm: string, key: Uint8Array, iv: Uint8Array): DecipherLike;
  randomBytes(size: number): Uint8Array;
  Buffer: VaultCryptoBufferStatic;
}

export interface VaultKeys {
  encKey: Uint8Array;
  macKey: Uint8Array;
}

export interface VaultKdfMeta {
  name: string;
  iterations: number;
  salt: string;
}

export interface VaultMeta {
  type: "vault_meta";
  version: number;
  email: string;
  kdf: VaultKdfMeta;
  verifier: string;
}

export interface VaultItemRevision {
  revisionAt?: number;
  tombstone?: boolean;
}

export interface VaultItem {
  id: string;
  title?: string;
  username?: string;
  password?: string;
  tombstone?: boolean;
  deletedAt?: number;
  [key: string]: unknown;
}

export interface EncryptedItemEnvelope {
  type: "encrypted_item";
  version: number;
  id: string;
  iv: string;
  ciphertext: string;
  authTag: string;
}

export interface EncryptedVaultEnvelope {
  type: "encrypted_vault";
  version: number;
  alg: string;
  kdf: VaultKdfMeta;
  iv: string;
  ciphertext: string;
  authTag?: string;
  mac?: string;
}

const bytesToHex = (bytes: Uint8Array): string =>
  Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

const hexToBytes = (hex: string): Uint8Array => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = parseInt(hex.substr(index * 2, 2), 16);
  }
  return bytes;
};

// O GCM aceita authTags truncados (de 4 a 16 bytes) se o tamanho não for
// fixado, o que deixa forjar um envelope com bem menos tentativas. O cofre
// sempre grava tags de 16 bytes, então qualquer outro tamanho é rejeitado.
const GCM_AUTH_TAG_HEX_LENGTH = 32;

const gcmAuthTag = (authTag: string): Uint8Array => {
  if (
    authTag.length !== GCM_AUTH_TAG_HEX_LENGTH ||
    !/^[0-9a-f]+$/i.test(authTag)
  ) {
    throw new Error("authTag inválido.");
  }
  return hexToBytes(authTag);
};

export const createVaultCrypto = (adapter: VaultCryptoAdapter) => {
  const { Buffer } = adapter;

  const deriveKeys = ({
    vaultSecret,
    saltHex,
    iterations = PBKDF2_ITERATIONS,
  }: {
    vaultSecret: string;
    saltHex: string;
    iterations?: number;
  }): VaultKeys => {
    const derived = adapter.pbkdf2Sync(
      vaultSecret,
      hexToBytes(saltHex),
      iterations,
      KEY_SIZE_BYTES,
      "sha256",
    );

    return {
      encKey: derived.subarray(0, 32),
      macKey: derived.subarray(32, 64),
    };
  };

  const createVaultSecret = ({
    email,
    password,
  }: {
    email: string;
    password: string;
  }): string => {
    const normalizedEmail = email.trim().toLowerCase();
    return `${normalizedEmail}:${password}`;
  };

  const emailFromVaultSecret = (vaultSecret: unknown): string => {
    if (!vaultSecret || typeof vaultSecret !== "string") {
      return "";
    }

    const separator = vaultSecret.indexOf(":");
    return separator === -1 ? "" : vaultSecret.slice(0, separator);
  };

  const VERIFIER_PAYLOAD = "secpass-vault-verifier-v1";

  const createVaultMeta = ({
    vaultSecret,
    email,
  }: {
    vaultSecret: string;
    email?: string;
  }): VaultMeta => {
    if (!vaultSecret) {
      throw new Error("Segredo do cofre ausente.");
    }

    const saltBytes = adapter.randomBytes(16);
    const saltHex = bytesToHex(saltBytes);
    const { macKey } = deriveKeys({ vaultSecret, saltHex });
    const verifier = adapter
      .createHmac("sha256", macKey)
      .update(VERIFIER_PAYLOAD)
      .digest("hex");

    return {
      type: "vault_meta",
      version: VAULT_VERSION,
      email: (email || emailFromVaultSecret(vaultSecret)).trim().toLowerCase(),
      kdf: {
        name: "pbkdf2-sha256",
        iterations: PBKDF2_ITERATIONS,
        salt: saltHex,
      },
      verifier,
    };
  };

  const unlockVaultKeys = (
    meta: Partial<VaultMeta> & { salt?: string; iterations?: number },
    vaultSecret: string,
  ): VaultKeys => {
    if (!vaultSecret) {
      throw new Error("Segredo do cofre ausente.");
    }

    const saltHex = meta?.kdf?.salt || meta?.salt || "";
    const iterations = Number(meta?.kdf?.iterations || meta?.iterations || 0);
    const expectedVerifier = meta?.verifier || "";

    if (!saltHex || !expectedVerifier) {
      throw new Error("Metadados do cofre invalidos.");
    }

    const keys = deriveKeys({
      vaultSecret,
      saltHex,
      iterations: iterations || PBKDF2_ITERATIONS,
    });
    const verifier = adapter
      .createHmac("sha256", keys.macKey)
      .update(VERIFIER_PAYLOAD)
      .digest("hex");

    if (!constantTimeCompare(verifier, expectedVerifier)) {
      throw new Error("Falha de integridade do cofre.");
    }

    return keys;
  };

  // v1 (legado): AES-256-CBC + HMAC-SHA256 em encrypt-then-MAC manual.
  // Mantido so para DESCRIPTOGRAFAR cofres/backups ja existentes; nada
  // nesse codigo volta a cifrar nesse formato.
  const decryptVaultItemV1 = (
    envelope: {
      version: number;
      id: string;
      ivHex: string;
      ciphertext: string;
      expectedMac: string;
    },
    keys: VaultKeys,
  ): string => {
    const { version, id, ivHex, ciphertext, expectedMac } = envelope;

    const macPayload = `${version}:${id}:${ivHex}:${ciphertext}`;
    const computedMac = adapter
      .createHmac("sha256", keys.macKey)
      .update(macPayload)
      .digest("hex");

    if (!constantTimeCompare(computedMac, expectedMac)) {
      throw new Error("Falha de integridade do cofre.");
    }

    try {
      const decipher = adapter.createDecipheriv(
        "aes-256-cbc",
        keys.encKey,
        hexToBytes(ivHex),
      );
      return Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Falha ao descriptografar cofre.");
    }
  };

  // v2 (atual): AES-256-GCM (AEAD). O authTag do GCM ja autentica
  // ciphertext+IV+AAD, entao a verificacao de integridade e a propria
  // descriptografia: nao ha comparacao manual de MAC.
  const decryptVaultItemV2 = (
    envelope: {
      version: number;
      id: string;
      ivHex: string;
      ciphertext: string;
      authTag?: string;
    },
    keys: VaultKeys,
  ): string => {
    const { version, id, ivHex, ciphertext, authTag } = envelope;

    if (!authTag) {
      throw new Error("Payload criptografado incompleto.");
    }

    try {
      const decipher = adapter.createDecipheriv(
        "aes-256-gcm",
        keys.encKey,
        hexToBytes(ivHex),
      );
      decipher.setAAD(Buffer.from(`${version}:${id}`, "utf8"));
      decipher.setAuthTag(gcmAuthTag(authTag));
      return Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Falha de integridade do cofre.");
    }
  };

  const encryptVaultItem = (
    item: VaultItem,
    keys: VaultKeys,
    revision?: VaultItemRevision,
  ): EncryptedItemEnvelope => {
    if (!keys?.encKey || !keys?.macKey) {
      throw new Error("Segredo do cofre ausente.");
    }

    const ivBytes = adapter.randomBytes(GCM_NONCE_BYTES);
    const ivHex = bytesToHex(ivBytes);
    const plaintext = JSON.stringify(item ?? {});
    const id = item?.id || "";
    const revisionAt = Number(revision?.revisionAt || 0);
    const tombstone = Boolean(revision?.tombstone);

    const cipher = adapter.createCipheriv("aes-256-gcm", keys.encKey, ivBytes);
    cipher.setAAD(
      Buffer.from(
        `${ITEM_ENVELOPE_VERSION}:${id}:${revisionAt}:${tombstone}`,
        "utf8",
      ),
    );
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext, "utf8")),
      cipher.final(),
    ]).toString("base64");
    const authTag = cipher.getAuthTag().toString("hex");

    return {
      type: "encrypted_item",
      version: ITEM_ENVELOPE_VERSION,
      id,
      iv: ivHex,
      ciphertext,
      authTag,
    };
  };

  // v3 (atual, so para o envelope por item de sync remoto): igual ao v2, mas
  // a AAD tambem amarra updatedAt/tombstone - ver comentario de
  // ITEM_ENVELOPE_VERSION. `revision` precisa vir de fora (do registro
  // remoto que acompanha o envelope, nunca de dentro dele) com os MESMOS
  // valores usados por quem chamou encryptVaultItem, senao a autenticacao
  // falha por design.
  const decryptVaultItemV3 = (
    envelope: {
      version: number;
      id: string;
      ivHex: string;
      ciphertext: string;
      authTag?: string;
      revision?: VaultItemRevision;
    },
    keys: VaultKeys,
  ): string => {
    const { version, id, ivHex, ciphertext, authTag, revision } = envelope;

    if (!authTag) {
      throw new Error("Payload criptografado incompleto.");
    }

    const revisionAt = Number(revision?.revisionAt || 0);
    const tombstone = Boolean(revision?.tombstone);

    try {
      const decipher = adapter.createDecipheriv(
        "aes-256-gcm",
        keys.encKey,
        hexToBytes(ivHex),
      );
      decipher.setAAD(
        Buffer.from(`${version}:${id}:${revisionAt}:${tombstone}`, "utf8"),
      );
      decipher.setAuthTag(gcmAuthTag(authTag));
      return Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Falha de integridade do cofre.");
    }
  };

  const decryptVaultItem = (
    envelope: Partial<EncryptedItemEnvelope> & { type?: string },
    keys: VaultKeys,
    revision?: VaultItemRevision,
  ): VaultItem => {
    if (!keys?.encKey || !keys?.macKey) {
      throw new Error("Segredo do cofre ausente.");
    }

    if (!envelope || envelope.type !== "encrypted_item") {
      throw new Error("Formato de cofre criptografado invalido.");
    }

    const version = Number(envelope.version || 0);
    const id = envelope.id || "";
    const ivHex = envelope.iv || "";
    const ciphertext = envelope.ciphertext || "";

    if (!version || !ivHex || !ciphertext) {
      throw new Error("Payload criptografado incompleto.");
    }

    let plaintext: string;
    if (version === LEGACY_VAULT_VERSION) {
      plaintext = decryptVaultItemV1(
        {
          version,
          id,
          ivHex,
          ciphertext,
          expectedMac: (envelope as { mac?: string }).mac || "",
        },
        keys,
      );
    } else if (version >= ITEM_ENVELOPE_VERSION) {
      plaintext = decryptVaultItemV3(
        { version, id, ivHex, ciphertext, authTag: envelope.authTag, revision },
        keys,
      );
    } else {
      plaintext = decryptVaultItemV2(
        { version, id, ivHex, ciphertext, authTag: envelope.authTag },
        keys,
      );
    }

    return JSON.parse(plaintext);
  };

  const encryptVaultItems = async (
    items: VaultItem[] | null | undefined,
    vaultSecret: string,
  ): Promise<EncryptedVaultEnvelope> => {
    if (!vaultSecret) {
      throw new Error("Segredo do cofre ausente.");
    }

    const safeItems = Array.isArray(items) ? items : [];
    const plaintext = JSON.stringify({ items: safeItems });

    const saltBytes = adapter.randomBytes(16);
    const ivBytes = adapter.randomBytes(GCM_NONCE_BYTES);
    const saltHex = bytesToHex(saltBytes);
    const ivHex = bytesToHex(ivBytes);
    const iterations = PBKDF2_ITERATIONS;

    const { encKey } = deriveKeys({ vaultSecret, saltHex, iterations });

    const cipher = adapter.createCipheriv("aes-256-gcm", encKey, ivBytes);
    cipher.setAAD(
      Buffer.from(`${VAULT_VERSION}:${saltHex}:${iterations}`, "utf8"),
    );
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(plaintext, "utf8")),
      cipher.final(),
    ]).toString("base64");
    const authTag = cipher.getAuthTag().toString("hex");

    return {
      type: "encrypted_vault",
      version: VAULT_VERSION,
      alg: "aes-256-gcm",
      kdf: {
        name: "pbkdf2-sha256",
        iterations,
        salt: saltHex,
      },
      iv: ivHex,
      ciphertext,
      authTag,
    };
  };

  // Exportado pra ser chamado tambem no momento de escrita (vault:add/
  // vault:update no processo main do desktop), nao so na releitura - um
  // item invalido gravado hoje (ex: renderer comprometido chamando
  // addItem(123, {}, null) via DevTools) so seria pego depois, no proximo
  // load, e a checagem de validateVaultItems e tudo-ou-nada: um item
  // invalido derruba a leitura do cofre inteiro. Rejeitar na escrita evita
  // que um item ruim chegue a existir no cofre.
  const validateCredentialFields = ({
    title,
    username,
    password,
  }: Partial<VaultItem>): void => {
    if (
      typeof title !== "string" ||
      typeof username !== "string" ||
      typeof password !== "string" ||
      title.length > MAX_ITEM_FIELD_LENGTH ||
      username.length > MAX_ITEM_FIELD_LENGTH ||
      password.length > MAX_ITEM_FIELD_LENGTH
    ) {
      throw new Error("Credencial invalida.");
    }
  };

  const validateVaultItems = (items: unknown): VaultItem[] => {
    if (!Array.isArray(items)) {
      throw new Error("Formato de cofre invalido.");
    }

    for (const item of items as VaultItem[]) {
      if (!item || typeof item !== "object" || typeof item.id !== "string") {
        throw new Error("Item de cofre invalido.");
      }

      if (item.id.length === 0 || item.id.length > MAX_ITEM_FIELD_LENGTH) {
        throw new Error("Item de cofre invalido.");
      }

      if (item.tombstone) {
        if (!Number.isFinite(Number(item.deletedAt))) {
          throw new Error("Item de cofre invalido.");
        }
        continue;
      }

      try {
        validateCredentialFields(item);
      } catch {
        throw new Error("Item de cofre invalido.");
      }
    }

    return items as VaultItem[];
  };

  // v1 (legado): AES-256-CBC + HMAC-SHA256 sobre o envelope inteiro. Mantido
  // so para abrir cofres locais e backups exportados anteriores a esta
  // versao; toda escrita nova usa decryptVaultEnvelopeV2 (GCM).
  const decryptVaultEnvelopeV1 = ({
    version,
    saltHex,
    iterations,
    ivHex,
    ciphertext,
    expectedMac,
    vaultSecret,
  }: {
    version: number;
    saltHex: string;
    iterations: number;
    ivHex: string;
    ciphertext: string;
    expectedMac: string;
    vaultSecret: string;
  }): string => {
    const { encKey, macKey } = deriveKeys({
      vaultSecret,
      saltHex,
      iterations: iterations || LEGACY_PBKDF2_ITERATIONS,
    });

    const macPayload = `${version}:${saltHex}:${ivHex}:${ciphertext}`;
    const computedMac = adapter
      .createHmac("sha256", macKey)
      .update(macPayload)
      .digest("hex");

    if (!constantTimeCompare(computedMac, expectedMac)) {
      throw new Error("Falha de integridade do cofre.");
    }

    try {
      const decipher = adapter.createDecipheriv(
        "aes-256-cbc",
        encKey,
        hexToBytes(ivHex),
      );
      return Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Falha ao descriptografar cofre.");
    }
  };

  const decryptVaultEnvelopeV2 = ({
    version,
    saltHex,
    iterations,
    ivHex,
    ciphertext,
    authTag,
    vaultSecret,
  }: {
    version: number;
    saltHex: string;
    iterations: number;
    ivHex: string;
    ciphertext: string;
    authTag: string;
    vaultSecret: string;
  }): string => {
    const effectiveIterations = iterations || PBKDF2_ITERATIONS;
    const { encKey } = deriveKeys({
      vaultSecret,
      saltHex,
      iterations: effectiveIterations,
    });

    try {
      const decipher = adapter.createDecipheriv(
        "aes-256-gcm",
        encKey,
        hexToBytes(ivHex),
      );
      decipher.setAAD(
        Buffer.from(`${version}:${saltHex}:${effectiveIterations}`, "utf8"),
      );
      decipher.setAuthTag(gcmAuthTag(authTag));
      return Buffer.concat([
        decipher.update(Buffer.from(ciphertext, "base64")),
        decipher.final(),
      ]).toString("utf8");
    } catch {
      throw new Error("Falha de integridade do cofre.");
    }
  };

  const decryptVaultEnvelope = async (
    envelope: Partial<EncryptedVaultEnvelope> & { type?: string },
    vaultSecret: string,
  ): Promise<VaultItem[]> => {
    if (!vaultSecret) {
      throw new Error("Segredo do cofre ausente.");
    }

    if (!envelope || envelope.type !== "encrypted_vault") {
      throw new Error("Formato de cofre criptografado invalido.");
    }

    const version = Number(envelope.version || 0);
    const saltHex = envelope.kdf?.salt || "";
    const iterations = Number(envelope.kdf?.iterations || 0);
    const ivHex = envelope.iv || "";
    const ciphertext = envelope.ciphertext || "";

    if (!version || !saltHex || !ivHex || !ciphertext) {
      throw new Error("Payload criptografado incompleto.");
    }

    let plaintext: string;
    if (version === LEGACY_VAULT_VERSION) {
      const expectedMac = envelope.mac || "";
      if (!expectedMac) {
        throw new Error("Payload criptografado incompleto.");
      }
      plaintext = decryptVaultEnvelopeV1({
        version,
        saltHex,
        iterations,
        ivHex,
        ciphertext,
        expectedMac,
        vaultSecret,
      });
    } else {
      const authTag = envelope.authTag || "";
      if (!authTag) {
        throw new Error("Payload criptografado incompleto.");
      }
      plaintext = decryptVaultEnvelopeV2({
        version,
        saltHex,
        iterations,
        ivHex,
        ciphertext,
        authTag,
        vaultSecret,
      });
    }

    if (!plaintext) {
      throw new Error("Falha ao descriptografar cofre.");
    }

    const parsed = JSON.parse(plaintext);
    return validateVaultItems(parsed?.items);
  };

  return {
    createVaultSecret,
    emailFromVaultSecret,
    createVaultMeta,
    unlockVaultKeys,
    encryptVaultItem,
    decryptVaultItem,
    encryptVaultItems,
    decryptVaultEnvelope,
    validateCredentialFields,
  };
};

export type VaultCrypto = ReturnType<typeof createVaultCrypto>;
