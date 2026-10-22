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

export class VaultCopyError extends Error {
  constructor(readonly reason: "save_failed" | "copy_failed" | "cancelled") {
    super(reason);
    this.name = "VaultCopyError";
  }
}

/** Reserve the clipboard during the click without releasing an unsaved secret.
 * WebKit requires user activation, so the ClipboardItem contains a promise whose
 * data becomes available only after the database confirms the save.
 * https://webkit.org/blog/10855/async-clipboard-api/
 */
export async function copyVaultPasswordAfterSave(password: string, save: (() => Promise<void>) | undefined, isCurrent: () => boolean): Promise<void> {
  let saving: Promise<void>;
  try { saving = save ? save() : Promise.resolve(); }
  catch { throw new VaultCopyError("save_failed"); }
  const clipboard = globalThis.navigator?.clipboard;
  if (typeof globalThis.ClipboardItem === "function" && typeof clipboard?.write === "function") {
    const payload = saving.then(() => {
      if (!isCurrent()) throw new VaultCopyError("cancelled");
      return new Blob([password], { type: "text/plain" });
    });
    // The browser may refuse permission before consuming the promised payload.
    void payload.catch(() => undefined);
    let copying: Promise<void>;
    try { copying = clipboard.write([new ClipboardItem({ "text/plain": payload })]); }
    catch { copying = Promise.reject(new VaultCopyError("copy_failed")); }
    const [saved, copied] = await Promise.allSettled([saving, copying]);
    if (saved.status === "rejected") throw new VaultCopyError("save_failed");
    if (!isCurrent()) throw new VaultCopyError("cancelled");
    if (copied.status === "rejected") throw new VaultCopyError("copy_failed");
    return;
  }
  if (save) {
    try { await saving; } catch { throw new VaultCopyError("save_failed"); }
  }
  if (!isCurrent()) throw new VaultCopyError("cancelled");
  try {
    if (!clipboard?.writeText) throw new VaultCopyError("copy_failed");
    await clipboard.writeText(password);
  } catch { throw new VaultCopyError("copy_failed"); }
  if (!isCurrent()) throw new VaultCopyError("cancelled");
}
