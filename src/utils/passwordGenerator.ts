import QuickCrypto from "react-native-quick-crypto";

const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWER = "abcdefghijklmnopqrstuvwxyz";
const DIGITS = "0123456789";
const SPECIAL = "!@#$%";
const ALL_CHARS = UPPER + LOWER + DIGITS + SPECIAL;

const PASSWORD_LENGTH = 16;

const getRandomChar = (charset: string): string => {
  const len = charset.length;
  const maxUnbiasedByte = Math.floor(256 / len) * len;

  while (true) {
    const randomByte = QuickCrypto.randomBytes(1)[0];
    if (randomByte < maxUnbiasedByte) {
      return charset.charAt(randomByte % len);
    }
  }
};

const shuffleArray = (arr: string[]): string[] => {
  for (let i = arr.length - 1; i > 0; i -= 1) {
    const range = i + 1;
    const maxUnbiasedByte = Math.floor(256 / range) * range;
    let j: number;
    while (true) {
      const randomByte = QuickCrypto.randomBytes(1)[0];
      if (randomByte < maxUnbiasedByte) {
        j = randomByte % range;
        break;
      }
    }
    const temp = arr[i];
    arr[i] = arr[j];
    arr[j] = temp;
  }
  return arr;
};

export const generatePassword = (): string => {
  const charArray = [
    getRandomChar(UPPER),
    getRandomChar(LOWER),
    getRandomChar(DIGITS),
    getRandomChar(SPECIAL),
  ];

  while (charArray.length < PASSWORD_LENGTH) {
    charArray.push(getRandomChar(ALL_CHARS));
  }

  return shuffleArray(charArray).join("");
};
