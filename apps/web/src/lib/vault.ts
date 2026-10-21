const PASSWORD_GROUPS = [
  "abcdefghijklmnopqrstuvwxyz",
  "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "0123456789",
  "!@#$%^&*()-_=+[]{}:,.?",
] as const;
const PASSWORD_ALPHABET = PASSWORD_GROUPS.join("");

/** Uniform samples: reject the incomplete tail of the byte range. */
function randomIndex(size: number, random: Crypto): number {
  const limit = 256 - (256 % size);
  const byte = new Uint8Array(1);
  do { random.getRandomValues(byte); } while (byte[0] >= limit);
  return byte[0] % size;
}

/** A browser-only generator; there is no Math.random fallback. */
export function generateVaultPassword(length = 24, random: Crypto = globalThis.crypto): string {
  if (!Number.isInteger(length) || length < 12 || length > 128) throw new Error("Choose a password length between 12 and 128.");
  if (!random?.getRandomValues) throw new Error("Secure password generation is unavailable in this browser.");
  const characters = PASSWORD_GROUPS.map(group => group[randomIndex(group.length, random)]);
  while (characters.length < length) characters.push(PASSWORD_ALPHABET[randomIndex(PASSWORD_ALPHABET.length, random)]);
  for (let index = characters.length - 1; index > 0; index--) {
    const other = randomIndex(index + 1, random);
    [characters[index], characters[other]] = [characters[other], characters[index]];
  }
  return characters.join("");
}
