import AsyncStorage from "@react-native-async-storage/async-storage";
import * as SecureStore from "expo-secure-store";
import QuickCrypto from "react-native-quick-crypto";
import { createItemId } from "../utils/createItemId";
import { constantTimeCompare } from "../utils/constantTimeCompare";

const AUDIT_KEY = "secpass_security_audit";
// Selo de integridade (ver sealSecurityLog/verifySecurityLogIntegrity):
// guardado separado do log em si, mesmo keychainService.
const AUDIT_SEAL_KEY = "secpass_security_audit_seal";
const MAX_AUDIT_EVENTS = 200;
const SECURE_STORE_OPTIONS = {
  keychainService: "secpass.audit",
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export interface SecurityEvent {
  id: string;
  type: string;
  status: string;
  details: Record<string, unknown>;
  createdAt: string;
}

export type SecurityLogIntegrity = "ok" | "tampered" | "inconclusive";

const parseEvents = (rawValue: string | null): SecurityEvent[] => {
  if (!rawValue) {
    return [];
  }

  try {
    const parsed = JSON.parse(rawValue);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
};

export const loadSecurityEvents = async (): Promise<SecurityEvent[]> => {
  try {
    const secureValue = await SecureStore.getItemAsync(
      AUDIT_KEY,
      SECURE_STORE_OPTIONS,
    );
    if (secureValue) {
      return parseEvents(secureValue);
    }
  } catch {
    // Continua com fallback de leitura legado.
  }

  const legacyValue = await AsyncStorage.getItem(AUDIT_KEY);
  const legacyEvents = parseEvents(legacyValue);

  if (legacyEvents.length) {
    try {
      await SecureStore.setItemAsync(
        AUDIT_KEY,
        JSON.stringify(legacyEvents),
        SECURE_STORE_OPTIONS,
      );
      await AsyncStorage.removeItem(AUDIT_KEY);
    } catch {
      // Mantem legado e tenta migrar novamente depois.
    }
  }

  return legacyEvents;
};

export const logSecurityEvent = async ({
  type,
  status = "info",
  details = {},
}: {
  type: string;
  status?: string;
  details?: Record<string, unknown>;
}): Promise<void> => {
  const events = await loadSecurityEvents();
  const nextEvents = [
    {
      id: createItemId(),
      type,
      status,
      details,
      createdAt: new Date().toISOString(),
    },
    ...events,
  ].slice(0, MAX_AUDIT_EVENTS);

  const payload = JSON.stringify(nextEvents);

  try {
    await SecureStore.setItemAsync(AUDIT_KEY, payload, SECURE_STORE_OPTIONS);
    await AsyncStorage.removeItem(AUDIT_KEY);
  } catch {
    throw new Error(
      "Nao foi possivel registrar evento de seguranca em armazenamento protegido.",
    );
  }
};

export const clearSecurityEvents = async (): Promise<void> => {
  try {
    await SecureStore.deleteItemAsync(AUDIT_KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Continua para limpar fallback.
  }

  try {
    await SecureStore.deleteItemAsync(AUDIT_SEAL_KEY, SECURE_STORE_OPTIONS);
  } catch {
    // Continua mesmo se o selo nao puder ser removido.
  }

  await AsyncStorage.removeItem(AUDIT_KEY);
};

// --- Selo de integridade do log de auditoria -------------------------------
//
// O log em si (acima) fica no SecureStore, mas um atacante com acesso root/
// jailbreak ao aparelho ja consegue ler e reescrever qualquer item do
// Keychain do app - inclusive esse. Por isso o selo NAO usa uma chave
// guardada no proprio dispositivo (isso so protegeria contra adulteracao
// acidental, nao contra quem ja tem esse nivel de acesso): ele e assinado
// com uma chave derivada da propria senha mestra (vaultSecret), que so
// existe transitoriamente em memoria quando o usuario desbloqueia o cofre.
// Um atacante que so tem acesso ao armazenamento do aparelho (sem saber a
// senha) nao consegue forjar um selo valido depois de editar/apagar
// entradas do historico.
//
// O selo cobre so o PREFIXO do log que existia no momento de selar (contagem
// registrada em `count`) - novas entradas legitimas adicionadas depois nao
// invalidam o selo antigo, e a verificacao seguinte reconfirma exatamente
// esse prefixo. Isso e reconciliado com o limite MAX_AUDIT_EVENTS: se
// entradas antigas demais foram descartadas por causa do limite antes da
// proxima verificacao, o selo fica inconclusivo (nao da pra confirmar nem
// desmentir), em vez de soar falso alarme.
const canonicalizeEvent = (event: Partial<SecurityEvent>): string =>
  JSON.stringify({
    id: event?.id ?? null,
    type: event?.type ?? null,
    status: event?.status ?? null,
    details: event?.details ?? null,
    createdAt: event?.createdAt ?? null,
  });

// Sem o 2o argumento de encoding: QuickCrypto.Hash.update(data, encoding)
// tem um overload que devolve o digest direto como Buffer (atalho "one-
// shot"), quebrando o encadeamento com .digest() - string ja usa utf8 por
// padrao (ver doc de update() em node_modules/react-native-quick-crypto),
// entao omitir o encoding aqui mantem o mesmo resultado e o tipo Hash
// encadeavel.
const sha256Hex = (value: string): string =>
  QuickCrypto.createHash("sha256").update(value).digest("hex");

const hmacHex = (key: string, value: string): string =>
  QuickCrypto.createHmac("sha256", key).update(value, "utf8").digest("hex");

// Deriva uma chave dedicada ao selo a partir da senha mestra - nunca reusa
// vaultSecret cru como chave em mais de um lugar (mesmo padrao de
// separacao de dominio usado no resto do app).
const deriveSealKey = (vaultSecret: string): string =>
  hmacHex(vaultSecret, "secpass-audit-seal-key-v1");

// Encadeia do evento mais antigo para o mais novo (a lista em disco fica
// mais-novo-primeiro; inverte antes de calcular).
const computeChainHash = (eventsOldestFirst: SecurityEvent[]): string => {
  let hash = "0".repeat(64);
  for (const event of eventsOldestFirst) {
    hash = sha256Hex(hash + canonicalizeEvent(event));
  }
  return hash;
};

interface SecurityLogSeal {
  hash: string;
  mac: string;
  count: number;
  boundaryId?: string | null;
}

const loadSeal = async (): Promise<SecurityLogSeal | null> => {
  try {
    const raw = await SecureStore.getItemAsync(
      AUDIT_SEAL_KEY,
      SECURE_STORE_OPTIONS,
    );
    if (!raw) {
      return null;
    }
    const parsed = JSON.parse(raw);
    if (
      typeof parsed?.hash !== "string" ||
      typeof parsed?.mac !== "string" ||
      !Number.isFinite(parsed?.count)
    ) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
};

// Chamar sempre que o cofre for desbloqueado com sucesso (a senha mestra
// esta disponivel nesse momento) - "fecha" a integridade de tudo que foi
// registrado ate agora, inclusive eventos de login que aconteceram antes
// deste desbloqueio (ex: tentativas falhas anteriores).
export const sealSecurityLog = async (vaultSecret: string): Promise<void> => {
  if (!vaultSecret) {
    return;
  }

  const events = await loadSecurityEvents();
  const chainHash = computeChainHash([...events].reverse());
  // Ancora de alinhamento: o id do evento mais ANTIGO coberto por este
  // selo (ultima posicao da lista, ja que ela fica mais-novo-primeiro). Na
  // verificacao, se a fatia final da lista atual nao terminar com esse
  // mesmo id, a posicao dos eventos mudou desde a selagem (evento apagado
  // do meio, ou o limite MAX_AUDIT_EVENTS empurrou o que foi selado pra
  // fora) - nesses casos nao da pra comparar a fatia certa com seguranca,
  // entao o resultado e "inconclusive", nunca uma comparacao as cegas que
  // podia acusar adulteracao por engano.
  const boundaryId = events.length > 0 ? events[events.length - 1].id : null;
  const sealKey = deriveSealKey(vaultSecret);
  const mac = hmacHex(
    sealKey,
    `${chainHash}:${events.length}:${boundaryId ?? ""}`,
  );

  try {
    await SecureStore.setItemAsync(
      AUDIT_SEAL_KEY,
      JSON.stringify({ hash: chainHash, count: events.length, boundaryId, mac }),
      SECURE_STORE_OPTIONS,
    );
  } catch {
    // Selagem e best-effort: nao deve travar o desbloqueio do cofre.
  }
};

// Retorna "ok" (nada selado ainda, ou selo confere), "tampered" (o prefixo
// coberto pelo ultimo selo foi editado sem deixar a fatia desalinhada) ou
// "inconclusive" (nao da pra localizar com seguranca o mesmo prefixo que
// foi selado - por exemplo, um evento foi removido do meio da lista, ou o
// limite MAX_AUDIT_EVENTS empurrou o prefixo selado pra fora do
// historico). "inconclusive" e deliberadamente distinto de "tampered":
// remocao de eventos desalinha a lista e por si so nao prova adulteracao
// (poderia ser so o limite de retencao normal), entao nao vira alarme.
export const verifySecurityLogIntegrity = async (
  vaultSecret: string,
): Promise<SecurityLogIntegrity> => {
  if (!vaultSecret) {
    return "inconclusive";
  }

  const seal = await loadSeal();
  if (!seal) {
    return "ok";
  }

  const events = await loadSecurityEvents();
  if (events.length < seal.count) {
    return "inconclusive";
  }

  const sealedPortion = events.slice(events.length - seal.count);
  const currentBoundaryId =
    sealedPortion.length > 0
      ? sealedPortion[sealedPortion.length - 1].id
      : null;

  if (
    seal.boundaryId !== undefined &&
    currentBoundaryId !== (seal.boundaryId ?? null)
  ) {
    return "inconclusive";
  }

  const chainHash = computeChainHash([...sealedPortion].reverse());
  const sealKey = deriveSealKey(vaultSecret);
  const expectedMac = hmacHex(
    sealKey,
    `${chainHash}:${seal.count}:${seal.boundaryId ?? ""}`,
  );

  return constantTimeCompare(expectedMac, seal.mac) ? "ok" : "tampered";
};
