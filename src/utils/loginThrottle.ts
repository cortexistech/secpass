// LIMITACAO ACEITA (achado de seguranca, severidade media): todo este
// bloqueio compara `lockUntil` contra `Date.now()`, o relogio do proprio
// aparelho - sem servidor, nao ha como impor um limite real de tentativas.
// Quem tem o aparelho fisicamente desbloqueado pode ir em Ajustes,
// adiantar o relogio do sistema alem de `lockUntil` e pular a espera na
// hora (repetivel). Verificar a hora contra um servidor nao resolve de
// verdade: o mesmo atacante liga o modo aviao antes de mexer no relogio,
// e o app tem que confiar no relogio local mesmo assim (senao travaria
// qualquer usuario legitimo offline). A defesa real contra forca bruta
// e o custo computacional do PBKDF2 (600 mil iteracoes, ver
// vaultCrypto.ts) - esse contador aqui so cobre o caso comum de alguem
// tentando adivinhar de cabeca, nao um atacante que sabe manipular o
// relogio do sistema.
export const MAX_LOGIN_ATTEMPTS = 5;
const BASE_LOCK_MS = 30 * 1000;
const MAX_LOCK_MS = 15 * 60 * 1000;
export const LOCK_LEVEL_DECAY_MS = 6 * 60 * 60 * 1000;

export const isLoginLocked = (
  lockUntil: number,
  nowMs: number = Date.now(),
): boolean => Number(lockUntil) > nowMs;

export const getLockRemainingSeconds = (
  lockUntil: number,
  nowMs: number = Date.now(),
): number => {
  if (!isLoginLocked(lockUntil, nowMs)) {
    return 0;
  }

  return Math.ceil((Number(lockUntil) - nowMs) / 1000);
};

const getProgressiveLockMs = (nextLockLevel: number): number => {
  const duration = BASE_LOCK_MS * 2 ** (nextLockLevel - 1);
  return Math.min(duration, MAX_LOCK_MS);
};

export interface FailedLoginState {
  failedAttempts: number;
  lockLevel: number;
  lockUntil: number;
  justLocked: boolean;
  remainingAttempts: number;
  lockDurationSeconds: number;
}

export const computeFailedLoginState = ({
  failedAttempts,
  lockLevel,
  nowMs = Date.now(),
}: {
  failedAttempts: number;
  lockLevel: number;
  nowMs?: number;
}): FailedLoginState => {
  const nextFailedAttempts = failedAttempts + 1;

  if (nextFailedAttempts < MAX_LOGIN_ATTEMPTS) {
    return {
      failedAttempts: nextFailedAttempts,
      lockLevel,
      lockUntil: 0,
      justLocked: false,
      remainingAttempts: MAX_LOGIN_ATTEMPTS - nextFailedAttempts,
      lockDurationSeconds: 0,
    };
  }

  const nextLockLevel = lockLevel + 1;
  const lockDurationMs = getProgressiveLockMs(nextLockLevel);

  return {
    failedAttempts: 0,
    lockLevel: nextLockLevel,
    lockUntil: nowMs + lockDurationMs,
    justLocked: true,
    remainingAttempts: 0,
    lockDurationSeconds: Math.ceil(lockDurationMs / 1000),
  };
};

export const applyLockDecay = ({
  failedAttempts,
  lockLevel,
  lockUntil,
  nowMs = Date.now(),
}: {
  failedAttempts: number;
  lockLevel: number;
  lockUntil: number;
  nowMs?: number;
}): { failedAttempts: number; lockLevel: number; lockUntil: number } => {
  if (isLoginLocked(lockUntil, nowMs)) {
    return {
      failedAttempts,
      lockLevel,
      lockUntil,
    };
  }

  if (!lockLevel) {
    return {
      failedAttempts,
      lockLevel,
      lockUntil: 0,
    };
  }

  const elapsedSinceUnlock = Math.max(0, nowMs - Number(lockUntil || 0));
  const stepsToReduce =
    1 + Math.floor(elapsedSinceUnlock / LOCK_LEVEL_DECAY_MS);
  const nextLockLevel = Math.max(0, lockLevel - stepsToReduce);

  return {
    failedAttempts: 0,
    lockLevel: nextLockLevel,
    lockUntil: nextLockLevel > 0 ? lockUntil : 0,
  };
};
