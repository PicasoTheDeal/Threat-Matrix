import type { FeedItem, Severity } from "./types";

const relative = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const absolute = new Intl.DateTimeFormat("en", { year: "numeric", month: "short", day: "numeric" });

export function timeAgo(iso: string | number, now = Date.now()): string {
  const ms = typeof iso === "number" ? iso : Date.parse(iso);
  if (!Number.isFinite(ms)) return "";
  const seconds = Math.round((ms - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 60) return "just now";
  if (abs < 3600) return relative.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return relative.format(Math.round(seconds / 3600), "hour");
  if (abs < 7 * 86400) return relative.format(Math.round(seconds / 86400), "day");
  return absolute.format(ms);
}

// compact age for table cells in minutes hours or days then a date
export function shortAge(iso: string, now = Date.now()): string {
  const ms = Date.parse(iso);
  if (!Number.isFinite(ms)) return "";
  const minutes = Math.max(0, Math.round((now - ms) / 60000));
  if (minutes < 1) return "NOW";
  if (minutes < 60) return `${minutes} MIN`;
  if (minutes < 1440) return `${Math.round(minutes / 60)} H`;
  if (minutes < 14 * 1440) return `${Math.round(minutes / 1440)} D`;
  return new Intl.DateTimeFormat("en", { month: "short", day: "2-digit" }).format(ms).toUpperCase();
}

export function fullDate(iso: string): string {
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? absolute.format(ms) : iso;
}

export const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export function percent(value: number): string {
  const pct = value * 100;
  if (pct >= 10) return `${Math.round(pct)}%`;
  if (pct >= 1) return `${pct.toFixed(1)}%`;
  return pct < 0.1 ? "<0.1%" : `${pct.toFixed(1)}%`;
}

// vulnerabilities from nvd have no headline the id is their title
export function hasHeadline(item: FeedItem): boolean {
  return item.title !== item.id;
}

export function kindLabel(item: FeedItem): string {
  if (item.kind === "vuln") return item.id;
  if (item.kind === "ransomware") return "Ransomware claim";
  return item.sources[0] || "News";
}

// links are only ever opened when they are plain http or https
export function safeHref(url: string | undefined): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.toString() : undefined;
  } catch {
    return undefined;
  }
}
