export type Severity = "critical" | "high" | "medium" | "low";
export type Kind = "vuln" | "news" | "ransomware";

export interface FeedItem {
  id: string;
  kind: Kind;
  title: string;
  summary: string;
  url: string;
  date: string;
  sources: string[];
  severity?: Severity;
  cvss?: number;
  epss?: number;
  epssPercentile?: number;
  kev?: boolean;
  ransomware?: boolean;
  due?: string;
  tags?: string[];
  links?: { label: string; url: string }[];
}

export interface SourceStatus {
  key: string;
  label: string;
  ok: boolean;
  fetchedAt: number;
  count: number;
}

export interface Pulse {
  infocon?: string;
  ports?: { port: number; records: number }[];
}

export interface Feed {
  version: string;
  generatedAt: number;
  pending: number;
  sources: SourceStatus[];
  items: FeedItem[];
  pulse: Pulse;
}

export interface Comment {
  id: number;
  content: string;
  created_at: string;
  username: string;
  mine: boolean;
}

export interface Interaction {
  likes: number;
  liked: boolean;
  comments: Comment[];
}

export interface Session {
  username: string;
  expiresAt: number;
}

export type View = "all" | "vuln" | "exploited" | "news" | "ransomware" | "foryou" | "liked";
export type Sort = "newest" | "severity" | "epss" | "liked";
export type Range = "" | "24h" | "7d" | "30d";

export interface Filters {
  q: string;
  view: View;
  severity: Severity[];
  source: string;
  range: Range;
  sort: Sort;
}
