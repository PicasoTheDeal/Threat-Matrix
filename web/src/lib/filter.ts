import { SEVERITY_RANK } from "./format";
import type { FeedItem, Filters, Range, Severity, Sort, View } from "./types";

export const DEFAULT_FILTERS: Filters = { q: "", view: "all", severity: [], source: "", range: "", sort: "newest" };

const RANGE_MS: Record<Exclude<Range, "">, number> = { "24h": 86400_000, "7d": 7 * 86400_000, "30d": 30 * 86400_000 };
const VIEWS: View[] = ["all", "vuln", "exploited", "news", "ransomware", "foryou", "liked"];
const SORTS: Sort[] = ["newest", "severity", "epss", "liked"];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];

const haystacks = new WeakMap<FeedItem, string>();

// lower cased searchable text for an item computed once
export function haystack(item: FeedItem): string {
  let text = haystacks.get(item);
  if (text === undefined) {
    text = [item.id, item.title, item.summary, item.sources.join(" "), (item.tags || []).join(" ")].join(" ").toLowerCase();
    haystacks.set(item, text);
  }
  return text;
}

const escapeRegExp = (text: string) => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// matches whole words so the topic rat does not match integration
export function topicMatcher(topics: string[]): (item: FeedItem) => boolean {
  const patterns = topics
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean)
    .map((t) => new RegExp(`(^|[^a-z0-9])${escapeRegExp(t)}($|[^a-z0-9])`));
  if (patterns.length === 0) return () => false;
  return (item) => {
    const text = haystack(item);
    return patterns.some((p) => p.test(text));
  };
}

export interface FilterContext {
  topics: string[];
  liked: Set<string>;
  likeCounts: Record<string, [number, number]>;
  now: number;
}

export function applyFilters(items: FeedItem[], filters: Filters, ctx: FilterContext): FeedItem[] {
  const terms = filters.q.toLowerCase().split(/\s+/).filter(Boolean);
  const matchesTopics = filters.view === "foryou" ? topicMatcher(ctx.topics) : null;
  const since = filters.range ? ctx.now - RANGE_MS[filters.range] : 0;

  const out = items.filter((item) => {
    switch (filters.view) {
      case "vuln": if (item.kind !== "vuln") return false; break;
      case "exploited": if (!item.kev) return false; break;
      case "news": if (item.kind !== "news") return false; break;
      case "ransomware": if (item.kind !== "ransomware") return false; break;
      case "foryou": if (!matchesTopics!(item)) return false; break;
      case "liked": if (!ctx.liked.has(item.id)) return false; break;
    }
    if (filters.severity.length > 0 && (!item.severity || !filters.severity.includes(item.severity))) return false;
    if (filters.source && !item.sources.includes(filters.source)) return false;
    if (since && Date.parse(item.date) < since) return false;
    if (terms.length > 0) {
      const text = haystack(item);
      if (!terms.every((term) => text.includes(term))) return false;
    }
    return true;
  });

  const byDate = (a: FeedItem, b: FeedItem) => b.date.localeCompare(a.date);
  switch (filters.sort) {
    case "severity":
      return out.sort(
        (a, b) =>
          (b.severity ? SEVERITY_RANK[b.severity] : 0) - (a.severity ? SEVERITY_RANK[a.severity] : 0) ||
          (b.cvss ?? 0) - (a.cvss ?? 0) ||
          byDate(a, b),
      );
    case "epss":
      return out.sort((a, b) => (b.epss ?? -1) - (a.epss ?? -1) || byDate(a, b));
    case "liked":
      return out.sort((a, b) => (ctx.likeCounts[b.id]?.[0] ?? 0) - (ctx.likeCounts[a.id]?.[0] ?? 0) || byDate(a, b));
    default:
      return out;
  }
}

export function countActive(filters: Filters): number {
  return (filters.severity.length > 0 ? 1 : 0) + (filters.source ? 1 : 0) + (filters.range ? 1 : 0);
}

// url state filters live in the query string so views can be bookmarked and shared

export function filtersFromUrl(search: string): Filters {
  const params = new URLSearchParams(search);
  const view = params.get("view") as View;
  const sort = params.get("sort") as Sort;
  const range = params.get("range") as Range;
  return {
    q: (params.get("q") || "").slice(0, 120),
    view: VIEWS.includes(view) ? view : "all",
    severity: (params.get("sev") || "").split(",").filter((s): s is Severity => SEVERITIES.includes(s as Severity)),
    source: (params.get("src") || "").slice(0, 60),
    range: range in RANGE_MS ? range : "",
    sort: SORTS.includes(sort) ? sort : "newest",
  };
}

export function filtersToUrl(filters: Filters, itemId: string | null): string {
  const params = new URLSearchParams();
  if (filters.q) params.set("q", filters.q);
  if (filters.view !== "all") params.set("view", filters.view);
  if (filters.severity.length) params.set("sev", filters.severity.join(","));
  if (filters.source) params.set("src", filters.source);
  if (filters.range) params.set("range", filters.range);
  if (filters.sort !== "newest") params.set("sort", filters.sort);
  if (itemId) params.set("item", itemId);
  const query = params.toString();
  return query ? `?${query}` : window.location.pathname;
}
