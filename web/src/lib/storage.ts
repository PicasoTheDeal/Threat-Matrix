// localstorage can throw private windows blocked site data so every access is guarded

export function readJson<T>(key: string): T | null {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : null;
  } catch {
    return null;
  }
}

export function writeJson(key: string, value: unknown): void {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // storage full or unavailable the app works without it
  }
}

export function remove(key: string): void {
  try {
    localStorage.removeItem(key);
  } catch {
    // ignore
  }
}

export const KEYS = {
  feed: "tm.feed.v2",
  session: "tm.session.v3",
  theme: "tm.theme",
  // keys written by the previous version of the app cleared on start
  legacy: ["matrix_logs_cache", "matrix_auth_token", "tm.session.v2"],
};
