export type Severity = "critical" | "high" | "medium" | "low";
export type Kind = "vuln" | "news" | "ransomware";

export interface Link {
  label: string;
  url: string;
}

export interface FeedItem {
  // cve or ghsa id for vulnerabilities a stable hash based id otherwise
  id: string;
  kind: Kind;
  title: string;
  summary: string;
  url: string;
  // iso 8601 timestamp used for ordering
  date: string;
  sources: string[];
  severity?: Severity;
  cvss?: number;
  // probability of exploitation in the next 30 days from first epss
  epss?: number;
  epssPercentile?: number;
  // listed in the cisa known exploited vulnerabilities catalog
  kev?: boolean;
  // cisa reports known use in ransomware campaigns
  ransomware?: boolean;
  // cisa remediation due date for kev entries
  due?: string;
  tags?: string[];
  links?: Link[];
}

export interface Pulse {
  // sans internet storm center threat level green yellow orange or red
  infocon?: string;
  ports?: { port: number; records: number }[];
}

export interface SourceStatus {
  key: string;
  label: string;
  ok: boolean;
  fetchedAt: number;
  count: number;
}
