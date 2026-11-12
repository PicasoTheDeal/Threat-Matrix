import { KEYS, readJson, remove, writeJson } from "./storage";
import type { Feed, Interaction, Session } from "./types";

// the api is served from the same origin under /api so the session cookie stays first party
export const API_BASE = "";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: { method?: string; body?: unknown; cache?: RequestCache } = {}): Promise<T> {
  const headers: Record<string, string> = {};
  if (options.body !== undefined) headers["Content-Type"] = "application/json";
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: options.method || "GET",
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
      cache: options.cache,
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError(0, "Can't reach the server. Check your connection and try again.");
  }
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    // empty or non json body
  }
  if (!res.ok) {
    const message = (data as { error?: string } | null)?.error;
    throw new ApiError(res.status, message || `Request failed (${res.status}).`);
  }
  return data as T;
}

// feed

interface StoredFeed {
  savedAt: number;
  feed: Feed;
}

// how long a stored feed is shown without asking the server at all
export const FEED_FRESH_MS = 2 * 60_000;

export function cachedFeed(): StoredFeed | null {
  const stored = readJson<StoredFeed>(KEYS.feed);
  return stored && Array.isArray(stored.feed?.items) ? stored : null;
}

// sent without custom headers so the browserskips the cors preflight and uses its own http cache the servers etag turns repeat requests into small 304 responses
export async function fetchFeed(force = false): Promise<Feed> {
  const feed = await request<Feed>("/api/feed", { cache: force ? "no-cache" : "default" });
  if (!feed || !Array.isArray(feed.items)) throw new ApiError(502, "The server sent an unexpected response.");
  if (feed.items.length > 0) writeJson(KEYS.feed, { savedAt: Date.now(), feed } satisfies StoredFeed);
  return feed;
}

// session

export function loadSession(): Session | null {
  const session = readJson<Session>(KEYS.session);
  if (!session?.username || session.expiresAt * 1000 < Date.now()) {
    remove(KEYS.session);
    return null;
  }
  return session;
}

export function saveSession(session: Session | null): void {
  if (session) writeJson(KEYS.session, session);
  else remove(KEYS.session);
}

interface Credentials {
  username: string;
  password: string;
  turnstileToken: string;
}

export const login = (body: Credentials) => request<Session>("/api/login", { method: "POST", body });
export const signup = (body: Credentials) => request<Session>("/api/signup", { method: "POST", body });
export const logout = () => request<unknown>("/api/logout", { method: "POST", body: {} });
export const deleteAccount = (password: string) =>
  request<unknown>("/api/account/delete", { method: "POST", body: { password } });

export const fetchTopics = () => request<{ tags: string[] }>("/api/parameters");
export const saveTopics = (tags: string[]) =>
  request<{ tags: string[] }>("/api/parameters", { method: "POST", body: { tags } });

// likes and comments

export interface InteractionSummary {
  // item id likes comments
  counts: Record<string, [number, number]>;
  liked: string[];
}

export const fetchSummary = () => request<InteractionSummary>("/api/interactions");
export const fetchInteraction = (id: string) => request<Interaction>(`/api/comments?id=${encodeURIComponent(id)}`);

type Action =
  | { action: "like" | "unlike"; log_id: string }
  | { action: "comment"; log_id: string; content: string; turnstileToken: string }
  | { action: "edit_comment"; log_id: string; comment_id: number; content: string }
  | { action: "delete_comment"; log_id: string; comment_id: number };

export async function interact(body: Action): Promise<Interaction> {
  const data = await request<{ interaction: Interaction }>("/api/interact", { method: "POST", body });
  return data.interaction;
}
