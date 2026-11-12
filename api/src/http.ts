import type { Env } from "./env";

const LOCAL_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d{1,5})?$/;

export class HttpError extends Error {
  status: number;
  headers?: Record<string, string>;
  constructor(status: number, message: string, headers?: Record<string, string>) {
    super(message);
    this.status = status;
    this.headers = headers;
  }
}

export function json(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers },
  });
}

// returns the origin to echo back or null when the callers origin is not allowed
export function allowedOrigin(request: Request, env: Env): string | null {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const extra = (env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((o) => o.trim())
    .filter(Boolean);
  // requests that arrive through the site proxy carry the sites own origin
  if (origin === new URL(request.url).origin) return origin;
  // any other site has to be listed in the allowed origins variable
  if (extra.includes(origin)) return origin;
  // wrangler dev serves the api on localhost only then are localhost front ends accepted
  const host = new URL(request.url).hostname;
  if ((host === "localhost" || host === "127.0.0.1") && LOCAL_ORIGIN.test(origin)) return origin;
  return null;
}

export function withStandardHeaders(response: Response, origin: string | null): Response {
  const res = new Response(response.body, response);
  const h = res.headers;
  if (origin) {
    h.set("Access-Control-Allow-Origin", origin);
    h.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    h.set("Access-Control-Allow-Headers", "Content-Type");
    h.set("Access-Control-Expose-Headers", "ETag, Retry-After");
    h.set("Access-Control-Max-Age", "86400");
  }
  h.append("Vary", "Origin");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("X-Frame-Options", "DENY");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  return res;
}

const MAX_BODY_BYTES = 16 * 1024;

// reads the body as text and stops as soon as it grows past the limit
async function readLimitedText(request: Request, maxBytes: number): Promise<string> {
  if (Number(request.headers.get("Content-Length") || "0") > maxBytes) throw new HttpError(413, "Request is too large.");
  if (!request.body) return "";
  const reader = request.body.getReader();
  const decoder = new TextDecoder();
  let received = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel();
      throw new HttpError(413, "Request is too large.");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

// parses a small json object body and requiring json also forces a cors preflight
export async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  const type = request.headers.get("Content-Type") || "";
  if (!type.toLowerCase().includes("application/json")) throw new HttpError(415, "Send the request as application/json.");
  const text = await readLimitedText(request, MAX_BODY_BYTES);
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, "The request body is not valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new HttpError(400, "Expected a JSON object.");
  return parsed as Record<string, unknown>;
}

export function clientIp(request: Request): string {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}
