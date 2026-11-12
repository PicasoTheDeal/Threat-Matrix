import type { Env } from "../env";
import { parseFeed } from "./rss";
import {
  clean, safeUrl, severityFromLabel, severityFromScore, shortHash, stripMarkdown, toIso, uniqueTags,
} from "./text";
import type { FeedItem, Pulse, Severity } from "./types";

const USER_AGENT = "ThreatMatrix/2.0";

type Json = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

async function request(url: string, headers: Record<string, string> = {}, timeoutMs = 12000): Promise<Response> {
  const res = await fetch(url, {
    headers: { "User-Agent": USER_AGENT, ...headers },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res;
}

async function getJson(url: string, headers: Record<string, string> = {}, timeoutMs?: number): Promise<any> { // eslint-disable-line @typescript-eslint/no-explicit-any
  return (await request(url, { Accept: "application/json", ...headers }, timeoutMs)).json();
}

const nvdUrl = (id: string) => `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id)}`;
const isCve = (id: unknown): id is string => typeof id === "string" && /^CVE-\d{4}-\d{4,}$/i.test(id);

// cisa known exploited vulnerabilities

async function fetchKev(): Promise<FeedItem[]> {
  const data = await getJson("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
  const list: Json[] = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  const items: FeedItem[] = [];
  for (const v of list) {
    const date = toIso(v?.dateAdded);
    if (!isCve(v?.cveID) || !date) continue;
    const id = v.cveID.toUpperCase();
    items.push({
      id,
      kind: "vuln",
      title: clean(v.vulnerabilityName, 160) || id,
      summary: clean(v.shortDescription),
      url: nvdUrl(id),
      date,
      sources: ["CISA KEV"],
      kev: true,
      ransomware: String(v.knownRansomwareCampaignUse || "").toLowerCase() === "known" || undefined,
      due: toIso(v.dueDate)?.slice(0, 10),
      tags: uniqueTags([v.vendorProject, v.product]),
      links: [
        { label: "NVD", url: nvdUrl(id) },
        { label: "CISA KEV catalog", url: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}` },
      ],
    });
  }
  // the catalog is not guaranteed to be newest first so sort before trimming
  return items.sort((a, b) => b.date.localeCompare(a.date));
}

// nvd

function nvdCvss(metrics: Json | undefined): { cvss?: number; severity?: Severity } {
  for (const key of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const list: Json[] = Array.isArray(metrics?.[key]) ? metrics![key] : [];
    const metric = list.find((m) => m?.type === "Primary") || list[0];
    const score = Number(metric?.cvssData?.baseScore);
    if (Number.isFinite(score) && score > 0) {
      return {
        cvss: score,
        severity: severityFromLabel(metric.cvssData.baseSeverity ?? metric.baseSeverity) ?? severityFromScore(score),
      };
    }
  }
  return {};
}

function mapNvd(entry: Json): FeedItem | null {
  const cve = entry?.cve;
  const date = toIso(cve?.published);
  if (!isCve(cve?.id) || !date || String(cve.vulnStatus || "").toLowerCase() === "rejected") return null;
  const descriptions: Json[] = Array.isArray(cve.descriptions) ? cve.descriptions : [];
  const summary = clean(descriptions.find((d) => d?.lang === "en")?.value);
  if (!summary || /^rejected reason/i.test(summary)) return null;
  const id = cve.id.toUpperCase();
  return {
    id,
    kind: "vuln",
    title: id,
    summary,
    url: nvdUrl(id),
    date,
    sources: ["NVD"],
    ...nvdCvss(cve.metrics),
    links: [{ label: "NVD", url: nvdUrl(id) }],
  };
}

async function fetchNvd(env: Env): Promise<FeedItem[]> {
  const PAGE = 150;
  const stamp = (ms: number) => new Date(ms).toISOString().replace("Z", "");
  const base =
    "https://services.nvd.nist.gov/rest/json/cves/2.0" +
    `?pubStartDate=${stamp(Date.now() - 12 * 3600_000)}&pubEndDate=${stamp(Date.now())}&resultsPerPage=${PAGE}`;
  const headers: Record<string, string> = env.NVD_API_KEY ? { apiKey: env.NVD_API_KEY } : {};
  let data = await getJson(base, headers, 20000);
  // results come oldest first
  const total = Number(data?.totalResults) || 0;
  if (total > PAGE) data = await getJson(`${base}&startIndex=${total - PAGE}`, headers, 20000);
  const list: Json[] = Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : [];
  return list.map(mapNvd).filter((item): item is FeedItem => item !== null);
}

// circl vulnerability lookup

function cveV5Cvss(metrics: unknown): { cvss?: number; severity?: Severity } {
  for (const metric of Array.isArray(metrics) ? (metrics as Json[]) : []) {
    for (const key of ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]) {
      const score = Number(metric?.[key]?.baseScore);
      if (Number.isFinite(score) && score > 0) {
        return { cvss: score, severity: severityFromLabel(metric[key].baseSeverity) ?? severityFromScore(score) };
      }
    }
  }
  return {};
}

// circl returns records in their native formats
function mapCircl(record: Json): FeedItem | null {
  const meta = record?.cveMetadata;
  if (meta) {
    const date = toIso(meta.datePublished);
    if (!isCve(meta.cveId) || !date || meta.state !== "PUBLISHED") return null;
    const cna: Json = record.containers?.cna || {};
    const descriptions: Json[] = Array.isArray(cna.descriptions) ? cna.descriptions : [];
    const summary = clean(descriptions.find((d) => String(d?.lang || "").startsWith("en"))?.value);
    if (!summary) return null;
    const id = meta.cveId.toUpperCase();
    const affected: Json[] = Array.isArray(cna.affected) ? cna.affected : [];
    return {
      id,
      kind: "vuln",
      title: clean(cna.title, 160) || id,
      summary,
      url: nvdUrl(id),
      date,
      sources: ["CIRCL"],
      ...cveV5Cvss(cna.metrics),
      tags: uniqueTags(affected.slice(0, 3).flatMap((a) => [a?.vendor, a?.product])),
      links: [
        { label: "NVD", url: nvdUrl(id) },
        { label: "CIRCL", url: `https://cve.circl.lu/vuln/${id}` },
      ],
    };
  }
  if (isCve(record?.id)) {
    const date = toIso(record.Published ?? record.published);
    const summary = clean(record.summary);
    if (!date || !summary) return null;
    const id = record.id.toUpperCase();
    const score = Number(record.cvss3 ?? record.cvss);
    return {
      id,
      kind: "vuln",
      title: id,
      summary,
      url: nvdUrl(id),
      date,
      sources: ["CIRCL"],
      cvss: Number.isFinite(score) && score > 0 ? score : undefined,
      severity: severityFromScore(score),
      links: [{ label: "NVD", url: nvdUrl(id) }],
    };
  }
  return null;
}

async function fetchCircl(): Promise<FeedItem[]> {
  let data: unknown;
  try {
    data = await getJson("https://cve.circl.lu/api/vulnerability/last/cvelistv5/40");
  } catch {
    data = await getJson("https://cve.circl.lu/api/last/40");
  }
  const list: Json[] = Array.isArray(data) ? data : Array.isArray((data as Json)?.data) ? (data as Json).data : [];
  return list.map(mapCircl).filter((item): item is FeedItem => item !== null);
}

// github security advisories

async function fetchGhsa(env: Env): Promise<FeedItem[]> {
  const headers: Record<string, string> = {
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  if (env.GITHUB_TOKEN) headers.Authorization = `Bearer ${env.GITHUB_TOKEN}`;
  const data = await getJson(
    "https://api.github.com/advisories?type=reviewed&sort=published&direction=desc&per_page=40",
    headers,
  );
  const items: FeedItem[] = [];
  for (const adv of Array.isArray(data) ? (data as Json[]) : []) {
    const date = toIso(adv?.published_at);
    const ghsa = typeof adv?.ghsa_id === "string" && /^GHSA(-[a-z0-9]{4}){3}$/i.test(adv.ghsa_id) ? adv.ghsa_id : null;
    if (!ghsa || !date || adv.withdrawn_at) continue;
    const id = isCve(adv.cve_id) ? adv.cve_id.toUpperCase() : ghsa;
    const advisoryUrl = `https://github.com/advisories/${ghsa}`;
    const packages: Json[] = Array.isArray(adv.vulnerabilities) ? adv.vulnerabilities : [];
    const score = Number(adv.cvss?.score);
    const links = [{ label: "GitHub advisory", url: advisoryUrl }];
    if (isCve(adv.cve_id)) links.unshift({ label: "NVD", url: nvdUrl(id) });
    items.push({
      id,
      kind: "vuln",
      title: clean(adv.summary, 160) || id,
      summary: clean(stripMarkdown(String(adv.description || ""))),
      url: advisoryUrl,
      date,
      sources: ["GitHub"],
      severity: severityFromLabel(adv.severity),
      cvss: Number.isFinite(score) && score > 0 ? score : undefined,
      tags: uniqueTags(packages.slice(0, 3).flatMap((p) => [p?.package?.name, p?.package?.ecosystem])),
      links,
    });
  }
  return items;
}

// security news rss

const NEWS_FEEDS = [
  { name: "The Hacker News", url: "https://feeds.feedburner.com/TheHackersNews" },
  { name: "BleepingComputer", url: "https://www.bleepingcomputer.com/feed/" },
  { name: "Krebs on Security", url: "https://krebsonsecurity.com/feed/" },
  { name: "CISA Advisories", url: "https://www.cisa.gov/cybersecurity-advisories/all.xml" },
  { name: "SANS ISC", url: "https://isc.sans.edu/rssfeed.xml" },
];
const NEWS_PER_FEED = 12;

async function fetchNews(): Promise<FeedItem[]> {
  const results = await Promise.allSettled(
    NEWS_FEEDS.map(async (feed) => {
      const res = await request(feed.url, { Accept: "application/rss+xml, application/atom+xml, application/xml, text/xml" });
      const xml = (await res.text()).slice(0, 600_000);
      return parseFeed(xml, NEWS_PER_FEED).map<FeedItem>((entry) => ({
        id: `news-${shortHash(entry.url)}`,
        kind: "news",
        title: entry.title,
        summary: entry.summary,
        url: entry.url,
        date: entry.date,
        sources: [feed.name],
      }));
    }),
  );
  const items = results.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
  if (items.length === 0) throw new Error("no news feed responded");
  return items;
}

// ransomware live

async function fetchRansomware(): Promise<FeedItem[]> {
  const data = await getJson("https://api.ransomware.live/v2/recentvictims");
  const items: FeedItem[] = [];
  for (const v of Array.isArray(data) ? (data as Json[]) : []) {
    const victim = clean(v?.victim ?? v?.post_title, 120);
    const group = clean(v?.group ?? v?.group_name, 40);
    const date = toIso(v?.discovered ?? v?.attackdate ?? v?.published);
    if (!victim || !group || !date) continue;
    const country = clean(v.country, 40);
    const sector = clean(v.activity ?? v.sector, 60);
    const facts = [sector && sector.toLowerCase() !== "not found" ? `Sector: ${sector}.` : "", country ? `Country: ${country}.` : ""];
    // only ransomware live pages are linked
    const page = safeUrl(v.url ?? v.permalink);
    const url = page && new URL(page).hostname.endsWith("ransomware.live")
      ? page
      : `https://www.ransomware.live/group/${encodeURIComponent(group.toLowerCase())}`;
    items.push({
      id: `rw-${shortHash(`${group}|${victim}|${date.slice(0, 10)}`)}`,
      kind: "ransomware",
      title: victim,
      summary: clean(`Listed as a victim by the ${group} ransomware group. ${facts.filter(Boolean).join(" ")}`),
      url,
      date,
      sources: ["ransomware.live"],
      tags: uniqueTags([group, country, sector && sector.toLowerCase() !== "not found" ? sector : ""]),
    });
  }
  return items.sort((a, b) => b.date.localeCompare(a.date));
}

// sans internet storm center

async function fetchPulse(): Promise<Pulse> {
  const [infocon, ports] = await Promise.allSettled([
    getJson("https://isc.sans.edu/api/infocon?json"),
    getJson("https://isc.sans.edu/api/topports/records/8?json"),
  ]);
  const pulse: Pulse = {};
  if (infocon.status === "fulfilled") {
    const level = String(infocon.value?.status ?? "").toLowerCase();
    if (["green", "yellow", "orange", "red"].includes(level)) pulse.infocon = level;
  }
  if (ports.status === "fulfilled" && ports.value && typeof ports.value === "object") {
    const rows = (Array.isArray(ports.value) ? ports.value : Object.values(ports.value)) as Json[];
    pulse.ports = rows
      .map((row) => ({ port: Number(row?.targetport), records: Number(row?.records) }))
      .filter((row) => Number.isInteger(row.port) && row.port > 0 && row.port < 65536 && Number.isFinite(row.records))
      .slice(0, 8);
    if (pulse.ports.length === 0) delete pulse.ports;
  }
  if (!pulse.infocon && !pulse.ports) throw new Error("no usable data");
  return pulse;
}

// epss

export type EpssScores = Record<string, [number, number]>;

// looks up exploit prediction scores for the given cve ids up to 300 per call
export async function fetchEpss(ids: string[]): Promise<EpssScores> {
  const scores: EpssScores = {};
  const wanted = ids.filter(isCve).slice(0, 300);
  const chunks: string[][] = [];
  for (let i = 0; i < wanted.length; i += 100) chunks.push(wanted.slice(i, i + 100));
  const results = await Promise.allSettled(
    chunks.map((chunk) => getJson(`https://api.first.org/data/v1/epss?cve=${chunk.join(",")}&limit=100`)),
  );
  if (results.length > 0 && results.every((r) => r.status === "rejected")) throw new Error("EPSS lookup failed");
  for (const result of results) {
    if (result.status !== "fulfilled") continue;
    for (const row of Array.isArray(result.value?.data) ? (result.value.data as Json[]) : []) {
      const epss = Number(row?.epss);
      const percentile = Number(row?.percentile);
      if (isCve(row?.cve) && Number.isFinite(epss)) {
        scores[row.cve.toUpperCase()] = [epss, Number.isFinite(percentile) ? percentile : 0];
      }
    }
  }
  return scores;
}

// registry

export interface SourceDef {
  key: string;
  label: string;
  // seconds before the source is fetched again
  ttl: number;
  // rough cpu weight
  cost: number;
  // items kept after merging with the previous fetch
  keep: number;
  fetch(env: Env): Promise<FeedItem[] | Pulse>;
}

export const SOURCES: SourceDef[] = [
  { key: "news", label: "Security news", ttl: 20 * 60, cost: 2, keep: 70, fetch: fetchNews },
  { key: "nvd", label: "NVD", ttl: 30 * 60, cost: 3, keep: 70, fetch: fetchNvd },
  { key: "kev", label: "CISA KEV", ttl: 2 * 3600, cost: 3, keep: 40, fetch: fetchKev },
  { key: "circl", label: "CIRCL", ttl: 30 * 60, cost: 2, keep: 50, fetch: fetchCircl },
  { key: "ghsa", label: "GitHub Advisories", ttl: 3600, cost: 2, keep: 50, fetch: fetchGhsa },
  { key: "ransomware", label: "ransomware.live", ttl: 3600, cost: 2, keep: 40, fetch: fetchRansomware },
  { key: "isc", label: "SANS ISC", ttl: 3600, cost: 1, keep: 0, fetch: fetchPulse },
];
