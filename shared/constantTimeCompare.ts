// Compartilhado entre o app mobile (src/utils/constantTimeCompare.ts) e o
// desktop (desktop/src/main/core/constantTimeCompare.js) - logica pura, sem
// dependencia de plataforma, nada a adaptar.
export const constantTimeCompare = (left: unknown, right: unknown): boolean => {
  if (typeof left !== "string" || typeof right !== "string") {
    return false;
  }

  const maxLength = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;

  for (let index = 0; index < maxLength; index += 1) {
    const leftChar = index < left.length ? left.charCodeAt(index) : 0;
    const rightChar = index < right.length ? right.charCodeAt(index) : 0;
    diff |= leftChar ^ rightChar;
  }

  return diff === 0;
};
