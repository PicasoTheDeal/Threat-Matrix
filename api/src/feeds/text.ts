import type { Severity } from "./types";

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", ndash: "-", mdash: "-", hellip: "...",
  rsquo: "'", lsquo: "'", rdquo: '"', ldquo: '"',
};

export function decodeEntities(input: string): string {
  return input.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, body: string) => {
    if (body[0] === "#") {
      const code = body[1].toLowerCase() === "x" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : "";
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? match;
  });
}

// normalises upstream text plain string no control characters single spaces bounded length
export function clean(value: unknown, max = 600): string {
  if (typeof value !== "string") return "";
  const text = value.replace(/[\u0000-\u001f\u007f​-‏‪-‮⁦-⁩]+/g, " ").replace(/\s+/g, " ").trim();
  if (text.length <= max) return text;
  const cut = text.slice(0, max - 1);
  const lastSpace = cut.lastIndexOf(" ");
  return `${(lastSpace > max * 0.6 ? cut.slice(0, lastSpace) : cut).trimEnd()}…`;
}

export function stripHtml(html: string): string {
  return decodeEntities(
    html
      .replace(/<(script|style)[\s\S]*?<\/\1>/gi, " ")
      .replace(/<[^>]*>/g, " "),
  )
    .replace(/\s+/g, " ")
    .replace(/ ([.,;:!?])/g, "$1");
}

export function stripMarkdown(md: string): string {
  return md
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/!?\[([^\]]*)\]\([^)]*\)/g, "$1")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/[*_`>]+/g, "")
    .replace(/<[^>]*>/g, " ");
}

// only absolute http or https urls are passed through to the client
export function safeUrl(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  try {
    const url = new URL(value.trim());
    return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : undefined;
  } catch {
    return undefined;
  }
}

export function toIso(value: unknown): string | undefined {
  if (typeof value !== "string" || !value) return undefined;
  let text = value.trim();
  // nvd timestamps carry no zone they are utc
  if (/^\d{4}-\d{2}-\d{2}T[\d:.]+$/.test(text)) text += "Z";
  if (/^\d{4}-\d{2}-\d{2}$/.test(text)) text += "T00:00:00Z";
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(\.\d+)?$/.test(text)) text = `${text.replace(" ", "T")}Z`;
  const ms = Date.parse(text);
  if (!Number.isFinite(ms)) return undefined;
  // feeds occasionally publish dates in the future clamp so they cannot pin the top of the list
  return new Date(Math.min(ms, Date.now())).toISOString();
}

export function severityFromScore(score: number | undefined): Severity | undefined {
  if (typeof score !== "number" || !Number.isFinite(score) || score <= 0) return undefined;
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  return "low";
}

export function severityFromLabel(label: unknown): Severity | undefined {
  const s = typeof label === "string" ? label.toLowerCase() : "";
  if (s === "critical" || s === "high" || s === "medium" || s === "low") return s;
  if (s === "moderate") return "medium";
  return undefined;
}

// small non cryptographic hash cyrb53 for building stable ids from urls
export function shortHash(input: string): string {
  let h1 = 0xdeadbeef;
  let h2 = 0x41c6ce57;
  for (let i = 0; i < input.length; i++) {
    const ch = input.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16).padStart(14, "0");
}

export function uniqueTags(values: unknown[], max = 6): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const tag = clean(value, 40);
    const key = tag.toLowerCase();
    if (!tag || key === "n/a" || key === "unknown" || key === "not known" || seen.has(key)) continue;
    seen.add(key);
    out.push(tag);
    if (out.length >= max) break;
  }
  return out;
}
