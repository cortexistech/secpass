import crypto from "crypto";

import {
  createVaultSecret,
  decryptVaultEnvelope,
  decryptVaultItem,
  encryptVaultItems,
  createVaultMeta,
  encryptVaultItem,
  unlockVaultKeys,
} from "../src/services/vaultCrypto";

const sampleItems = [
  { id: "1", title: "GitHub", username: "dev", password: "Secr3t!" },
  { id: "2", title: "Email", username: "user@mail.com", password: "Ou7r@Pass" },
];

// Reproduz o formato v1 (AES-256-CBC + HMAC-SHA256, encrypt-then-MAC manual)
// usado pelo app antes da migracao para AES-256-GCM, para provar que cofres
// e backups antigos ainda abrem com o codigo atual.
const buildLegacyV1Envelope = (items, vaultSecret, iterations = 310000) => {
  const saltBytes = crypto.randomBytes(16);
  const ivBytes = crypto.randomBytes(16);
  const saltHex = saltBytes.toString("hex");
  const ivHex = ivBytes.toString("hex");

  const derived = crypto.pbkdf2Sync(vaultSecret, saltBytes, iterations, 64, "sha256");
  const encKey = derived.subarray(0, 32);
  const macKey = derived.subarray(32, 64);

  const plaintext = JSON.stringify({ items });
  const cipher = crypto.createCipheriv("aes-256-cbc", encKey, ivBytes);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]).toString("base64");

  const macPayload = `1:${saltHex}:${ivHex}:${ciphertext}`;
  const mac = crypto.createHmac("sha256", macKey).update(macPayload).digest("hex");

  return {
    type: "encrypted_vault",
    version: 1,
    alg: "aes-256-cbc+hmac-sha256",
    kdf: { name: "pbkdf2-sha256", iterations, salt: saltHex },
    iv: ivHex,
    ciphertext,
    mac,
  };
};

const buildLegacyV1Item = (item, keys) => {
  const ivBytes = crypto.randomBytes(16);
  const ivHex = ivBytes.toString("hex");
  const plaintext = JSON.stringify(item ?? {});
  const cipher = crypto.createCipheriv("aes-256-cbc", keys.encKey, ivBytes);
  const ciphertext = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]).toString("base64");
  const id = item?.id || "";
  const macPayload = `1:${id}:${ivHex}:${ciphertext}`;
  const mac = crypto.createHmac("sha256", keys.macKey).update(macPayload).digest("hex");

  return { type: "encrypted_item", version: 1, id, iv: ivHex, ciphertext, mac };
};

describe("vaultCrypto", () => {

  it("faz o round-trip completo de criptografia e descriptografia", async () => {
    const vaultSecret = createVaultSecret({
      email: "User@Email.com",
      password: "Senha!123",
    });
    const envelope = await encryptVaultItems(sampleItems, vaultSecret);

    expect(envelope.type).toBe("encrypted_vault");
    expect(envelope.version).toBe(2);
    expect(envelope.alg).toBe("aes-256-gcm");
    expect(envelope.kdf.name).toBe("pbkdf2-sha256");
    expect(envelope.kdf.iterations).toBe(600000);
    expect(envelope.kdf.salt).toEqual(expect.any(String));
    expect(envelope.iv).toEqual(expect.any(String));
    expect(envelope.ciphertext).toEqual(expect.any(String));
    expect(envelope.authTag).toEqual(expect.any(String));

    const decrypted = await decryptVaultEnvelope(envelope, vaultSecret);
    expect(decrypted).toEqual(sampleItems);
  });

  it("le um cofre legado v1 (AES-CBC+HMAC) gerado antes da migracao para GCM", async () => {
    const vaultSecret = "secret";
    const legacyEnvelope = buildLegacyV1Envelope(sampleItems, vaultSecret);

    const decrypted = await decryptVaultEnvelope(legacyEnvelope, vaultSecret);
    expect(decrypted).toEqual(sampleItems);
  });

  it("normaliza email na criacao do segredo do cofre", () => {
    const secret = createVaultSecret({
      email: "  User@Email.COM  ",
      password: "abc",
    });

    expect(secret).toBe("user@email.com:abc");
  });

  it("trata items nao-array como lista vazia ao criptografar", async () => {
    const vaultSecret = "secret";
    const envelope = await encryptVaultItems(null, vaultSecret);
    const decrypted = await decryptVaultEnvelope(envelope, vaultSecret);

    expect(decrypted).toEqual([]);
  });

  it("gera salt, iv e ciphertext diferentes a cada criptografia", async () => {
    const vaultSecret = "secret";
    const first = await encryptVaultItems(sampleItems, vaultSecret);
    const second = await encryptVaultItems(sampleItems, vaultSecret);

    expect(first.kdf.salt).not.toBe(second.kdf.salt);
    expect(first.iv).not.toBe(second.iv);
    expect(first.ciphertext).not.toBe(second.ciphertext);
    expect(first.authTag).not.toBe(second.authTag);
  });

  it("rejeita criptografar sem vaultSecret", async () => {
    await expect(encryptVaultItems(sampleItems, "")).rejects.toThrow(
      "Segredo do cofre ausente.",
    );
  });

  it("rejeita descriptografar sem vaultSecret", async () => {
    await expect(
      decryptVaultEnvelope({ type: "encrypted_vault" }, ""),
    ).rejects.toThrow("Segredo do cofre ausente.");
  });

  it("rejeita envelope com tipo invalido", async () => {
    await expect(
      decryptVaultEnvelope({ type: "plain" }, "secret"),
    ).rejects.toThrow("Formato de cofre criptografado invalido.");
  });

  it("rejeita envelope nulo", async () => {
    await expect(decryptVaultEnvelope(null, "secret")).rejects.toThrow(
      "Formato de cofre criptografado invalido.",
    );
  });

  it("rejeita envelope com campos incompletos", async () => {
    await expect(
      decryptVaultEnvelope(
        { type: "encrypted_vault", version: 1, kdf: {} },
        "secret",
      ),
    ).rejects.toThrow("Payload criptografado incompleto.");
  });

  it("rejeita envelope v2 sem authTag", async () => {
    const envelope = await encryptVaultItems(sampleItems, "secret");
    const { authTag: _authTag, ...withoutAuthTag } = envelope;

    await expect(
      decryptVaultEnvelope(withoutAuthTag, "secret"),
    ).rejects.toThrow("Payload criptografado incompleto.");
  });

  it("descriptografa quando iterations nao esta presente (usa padrao)", async () => {
    const vaultSecret = "secret";
    const envelope = await encryptVaultItems(sampleItems, vaultSecret);
    delete envelope.kdf.iterations;

    const decrypted = await decryptVaultEnvelope(envelope, vaultSecret);
    expect(decrypted).toEqual(sampleItems);
  });

  it("detecta senha/segredo errado como falha de integridade", async () => {
    const envelope = await encryptVaultItems(sampleItems, "senha-certa");

    await expect(
      decryptVaultEnvelope(envelope, "senha-errada"),
    ).rejects.toThrow("Falha de integridade do cofre.");
  });

  it("detecta ciphertext adulterado", async () => {
    const envelope = await encryptVaultItems(sampleItems, "secret");
    const tampered = {
      ...envelope,
      ciphertext: `${envelope.ciphertext.slice(0, -4)}AAAA`,
    };

    await expect(decryptVaultEnvelope(tampered, "secret")).rejects.toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("detecta iv adulterado", async () => {
    const envelope = await encryptVaultItems(sampleItems, "secret");
    const tampered = { ...envelope, iv: "00".repeat(12) };

    await expect(decryptVaultEnvelope(tampered, "secret")).rejects.toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("detecta salt adulterado", async () => {
    const envelope = await encryptVaultItems(sampleItems, "secret");
    const tampered = {
      ...envelope,
      kdf: { ...envelope.kdf, salt: "00".repeat(16) },
    };

    await expect(decryptVaultEnvelope(tampered, "secret")).rejects.toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("detecta authTag adulterado", async () => {
    const envelope = await encryptVaultItems(sampleItems, "secret");
    const tampered = { ...envelope, authTag: "0".repeat(32) };

    await expect(decryptVaultEnvelope(tampered, "secret")).rejects.toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("detecta authTag truncado (tamanho diferente do esperado)", async () => {
    const envelope = await encryptVaultItems(sampleItems, "secret");
    const tampered = { ...envelope, authTag: envelope.authTag.slice(0, 10) };

    await expect(decryptVaultEnvelope(tampered, "secret")).rejects.toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("rejeita authTag correto mas truncado para um tamanho que o GCM aceita", async () => {
    // Sem fixar o tamanho, o GCM aceita os primeiros 4, 8 ou 12 bytes da tag
    // certa, o que reduz o custo de forjar um envelope para 2^32 tentativas.
    const envelope = await encryptVaultItems(sampleItems, "secret");

    for (const hexLength of [8, 16, 24]) {
      const tampered = {
        ...envelope,
        authTag: envelope.authTag.slice(0, hexLength),
      };
      await expect(decryptVaultEnvelope(tampered, "secret")).rejects.toThrow(
        "Falha de integridade do cofre.",
      );
    }
  });

  it("preserva itens com caracteres unicode e especiais", async () => {
    const vaultSecret = "secret";
    const unicodeItems = [
      {
        id: "1",
        title: "Café ☕",
        username: "usuário",
        password: "Sénh@!ñ中文🔒",
      },
    ];

    const envelope = await encryptVaultItems(unicodeItems, vaultSecret);
    const decrypted = await decryptVaultEnvelope(envelope, vaultSecret);

    expect(decrypted).toEqual(unicodeItems);
  });

  it("cria meta com verifier e rejeita senha errada no unlock", () => {
    const vaultSecret = "user@email.com:Senha!123";
    const meta = createVaultMeta({ vaultSecret, email: "user@email.com" });

    expect(meta.type).toBe("vault_meta");
    expect(unlockVaultKeys(meta, vaultSecret)).toEqual(
      expect.objectContaining({
        encKey: expect.anything(),
        macKey: expect.anything(),
      }),
    );
    expect(() => unlockVaultKeys(meta, "user@email.com:errada")).toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("cifra e decifra um item com as chaves do cofre", () => {
    const vaultSecret = "secret";
    const meta = createVaultMeta({ vaultSecret, email: "a@b.c" });
    const keys = unlockVaultKeys(meta, vaultSecret);
    const envelope = encryptVaultItem(sampleItems[0], keys);

    expect(envelope.type).toBe("encrypted_item");
    expect(envelope.version).toBe(3);
    expect(envelope.authTag).toEqual(expect.any(String));
    expect(decryptVaultItem(envelope, keys)).toEqual(sampleItems[0]);
  });

  it("recusa decifrar um item de sync remoto cuja revisao (updatedAt/tombstone) foi adulterada", () => {
    const vaultSecret = "secret";
    const meta = createVaultMeta({ vaultSecret, email: "a@b.c" });
    const keys = unlockVaultKeys(meta, vaultSecret);
    const revision = { revisionAt: 1000, tombstone: false };
    const envelope = encryptVaultItem(sampleItems[0], keys, revision);

    // A mesma revisao usada para cifrar decifra normalmente.
    expect(decryptVaultItem(envelope, keys, revision)).toEqual(sampleItems[0]);

    // Um backend remoto adulterado que reetiqueta o mesmo envelope com um
    // updatedAt forjado (ex: pra vencer o merge e ressuscitar um item
    // apagado) precisa falhar a autenticacao, nao ser aceito silenciosamente.
    expect(() =>
      decryptVaultItem(envelope, keys, { revisionAt: 9999999999999, tombstone: false }),
    ).toThrow("Falha de integridade do cofre.");

    expect(() =>
      decryptVaultItem(envelope, keys, { revisionAt: 1000, tombstone: true }),
    ).toThrow("Falha de integridade do cofre.");
  });

  it("detecta item com id trocado (impede substituicao entre registros)", () => {
    const vaultSecret = "secret";
    const meta = createVaultMeta({ vaultSecret, email: "a@b.c" });
    const keys = unlockVaultKeys(meta, vaultSecret);
    const envelope = encryptVaultItem(sampleItems[0], keys);
    const swapped = { ...envelope, id: sampleItems[1].id };

    expect(() => decryptVaultItem(swapped, keys)).toThrow(
      "Falha de integridade do cofre.",
    );
  });

  it("le um item legado v1 (usado no sync CloudKit) gerado antes da migracao para GCM", () => {
    const vaultSecret = "secret";
    const meta = createVaultMeta({ vaultSecret, email: "a@b.c" });
    const keys = unlockVaultKeys(meta, vaultSecret);
    const legacyItemEnvelope = buildLegacyV1Item(sampleItems[0], keys);

    expect(decryptVaultItem(legacyItemEnvelope, keys)).toEqual(sampleItems[0]);
  });
});
