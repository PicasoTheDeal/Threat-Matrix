export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 256;

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+";

// twenty four random characters from the browsers cryptographic generator
export function generatePassword(length = 24): string {
  const out: string[] = [];
  // rejection sampling keeps every character equally likely
  const limit = 256 - (256 % ALPHABET.length);
  while (out.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length * 2));
    for (const byte of bytes) {
      if (byte < limit && out.length < length) out.push(ALPHABET[byte % ALPHABET.length]);
    }
  }
  return out.join("");
}

export interface Strength {
  // from zero for too short to four for strong
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
}

export function passwordStrength(password: string): Strength {
  if (password.length < PASSWORD_MIN) {
    return { score: 0, label: `${PASSWORD_MIN - password.length} more character${PASSWORD_MIN - password.length === 1 ? "" : "s"} needed` };
  }
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  const unique = new Set(password).size;
  let score = 1;
  if (unique >= 8 && (classes >= 2 || password.length >= 16)) score = 2;
  if (unique >= 10 && ((classes >= 3 && password.length >= 14) || password.length >= 20)) score = 3;
  if (unique >= 12 && ((classes >= 3 && password.length >= 18) || password.length >= 28)) score = 4;
  return { score: score as Strength["score"], label: ["", "Weak", "Fair", "Good", "Strong"][score] };
}
