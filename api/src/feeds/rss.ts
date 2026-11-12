import { clean, decodeEntities, safeUrl, stripHtml, toIso } from "./text";

export interface RssEntry {
  title: string;
  url: string;
  date: string;
  summary: string;
}

function unwrap(raw: string): string {
  const cdata = raw.match(/^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/);
  return cdata ? cdata[1] : decodeEntities(raw.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1"));
}

function tag(block: string, names: string[]): string {
  for (const name of names) {
    const match = block.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i"));
    if (match) return unwrap(match[1]);
  }
  return "";
}

function atomLink(block: string): string {
  const links = block.match(/<link\b[^>]*>/gi) || [];
  let fallback = "";
  for (const link of links) {
    const href = link.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1];
    if (!href) continue;
    const rel = link.match(/\brel\s*=\s*["']([^"']+)["']/i)?.[1];
    if (!rel || rel === "alternate") return decodeEntities(href);
    fallback ||= decodeEntities(href);
  }
  return fallback;
}

// minimal rss and atom reader
export function parseFeed(xml: string, limit: number): RssEntry[] {
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) || [];
  const entries: RssEntry[] = [];
  for (const block of blocks) {
    if (entries.length >= limit) break;
    const title = clean(stripHtml(tag(block, ["title"])), 200);
    const url = safeUrl(tag(block, ["link"]).trim() || atomLink(block));
    const date = toIso(tag(block, ["pubDate", "published", "updated", "dc:date"]));
    if (!title || !url || !date) continue;
    const summary = clean(stripHtml(tag(block, ["description", "summary", "content"])), 320);
    entries.push({ title, url, date, summary });
  }
  return entries;
}
