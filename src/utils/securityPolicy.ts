export const MIN_ACCESS_PASSWORD_LENGTH = 8;
export const MAX_ACCESS_PASSWORD_LENGTH = 64;

export const validateAccessPasswordPolicy = (
  password: string | null | undefined,
): string | null => {
  if (!password || password.length < MIN_ACCESS_PASSWORD_LENGTH) {
    return `Senha deve ter no minimo ${MIN_ACCESS_PASSWORD_LENGTH} caracteres.`;
  }

  if (password.length > MAX_ACCESS_PASSWORD_LENGTH) {
    return `Senha deve ter no maximo ${MAX_ACCESS_PASSWORD_LENGTH} caracteres.`;
  }

  if (!/[A-Za-z]/.test(password)) {
    return "Senha deve incluir ao menos 1 letra.";
  }

  if (!/[0-9]/.test(password)) {
    return "Senha deve incluir ao menos 1 numero.";
  }

  if (!/[^A-Za-z0-9]/.test(password)) {
    return "Senha deve incluir ao menos 1 caractere especial.";
  }

  return null;
};
