const encoder = new TextEncoder();

export function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

export function fromHex(hex: string): Uint8Array {
  if (hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const data = typeof input === "string" ? encoder.encode(input) : input;
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

// comparison whose duration does not depend on where the strings differ
export function constantTimeEqual(a: string, b: string): boolean {
  const x = encoder.encode(a);
  const y = encoder.encode(b);
  let diff = x.length ^ y.length;
  const len = Math.max(x.length, y.length);
  for (let i = 0; i < len; i++) diff |= (x[i] ?? 0) ^ (y[i] ?? 0);
  return diff === 0;
}

// cloudflare workers reject pbkdf2 above 100000 iterations so this is the ceiling here
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_PREFIX = "pbkdf2-sha256";

async function pbkdf2(password: string, salt: Uint8Array, iterations: number): Promise<string> {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, key, 256);
  return toHex(new Uint8Array(bits));
}

// returns the hash as scheme iterations salt and digest
export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await pbkdf2(password, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_PREFIX}$${PBKDF2_ITERATIONS}$${toHex(salt)}$${hash}`;
}

export interface PasswordCheck {
  valid: boolean;
  // true when the stored hash uses the old scheme or fewer iterations and should be replaced
  needsUpgrade: boolean;
}

export async function verifyPassword(password: string, stored: string, legacySalt: string): Promise<PasswordCheck> {
  if (stored.startsWith(`${PBKDF2_PREFIX}$`)) {
    const [, iterText, saltHex, hashHex] = stored.split("$");
    const iterations = Number(iterText);
    if (!Number.isInteger(iterations) || iterations < 1 || iterations > PBKDF2_ITERATIONS || !saltHex || !hashHex) {
      return { valid: false, needsUpgrade: false };
    }
    const candidate = await pbkdf2(password, fromHex(saltHex), iterations);
    return { valid: constantTimeEqual(candidate, hashHex), needsUpgrade: iterations < PBKDF2_ITERATIONS };
  }
  // accounts created before the upgrade one round of sha 256 over salt password
  const salt = fromHex(legacySalt);
  const pw = encoder.encode(password);
  const combined = new Uint8Array(salt.length + pw.length);
  combined.set(salt);
  combined.set(pw, salt.length);
  const candidate = await sha256Hex(combined);
  return { valid: constantTimeEqual(candidate, stored), needsUpgrade: true };
}

// spends the same time as a real check so a missing username is not detectable by timing
export async function burnPasswordCheck(password: string): Promise<void> {
  await pbkdf2(password, new Uint8Array(16), PBKDF2_ITERATIONS);
}

export function randomToken(): string {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}
