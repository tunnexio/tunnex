import { describe, expect, it } from "vitest";
import { generateVaultPassword } from "../src/lib/vault";

describe("Vault secure password generation", () => {
  it("generates distinct passwords with all four required character groups", () => {
    const passwords = Array.from({ length: 50 }, () => generateVaultPassword());
    expect(new Set(passwords).size).toBe(passwords.length);
    for (const password of passwords) {
      expect(password).toHaveLength(24);
      expect(password).toMatch(/[a-z]/);
      expect(password).toMatch(/[A-Z]/);
      expect(password).toMatch(/[0-9]/);
      expect(password).toMatch(/[!@#$%^&*()\-_=+\[\]{}:,.?]/);
      expect(password).not.toMatch(/\s/);
    }
  });
  it.each([0, 11, 129, 24.5, NaN])("refuses an unsupported length %s", length => {
    expect(() => generateVaultPassword(length)).toThrow();
  });
  it("refuses generation when cryptographic randomness is unavailable", () => {
    expect(() => generateVaultPassword(24, {} as Crypto)).toThrow(/Secure password generation/);
  });
  it("rejects out-of-range random bytes instead of biasing character selection", () => {
    let calls = 0;
    const random = { getRandomValues: (values: Uint8Array) => { values[0] = ++calls === 1 ? 255 : 0; return values; } } as Crypto;
    const password = generateVaultPassword(12, random);
    expect(password).toHaveLength(12);
    expect(calls).toBe(24); // 12 characters, 11 shuffle samples, and one rejected byte.
    expect(password).toMatch(/[a-z]/);
    expect(password).toMatch(/[A-Z]/);
    expect(password).toMatch(/[0-9]/);
    expect(password).toContain("!");
  });
});
