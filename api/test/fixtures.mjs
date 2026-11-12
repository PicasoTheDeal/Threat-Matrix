// sample upstream responses shaped like each providers documented output
const iso = (minutesAgo) => new Date(Date.now() - minutesAgo * 60_000).toISOString();
const day = (daysAgo) => iso(daysAgo * 1440).slice(0, 10);

export const fixtures = {
  "www.cisa.gov/sites": {
    vulnerabilities: [
      { cveID: "CVE-2020-0001", vendorProject: "OldCo", product: "Legacy", vulnerabilityName: "OldCo Legacy RCE", dateAdded: "2021-11-03", shortDescription: "Old entry listed first in the file.", dueDate: "2021-11-17", knownRansomwareCampaignUse: "Unknown" },
      { cveID: "CVE-2026-1111", vendorProject: "Acme", product: "Gateway", vulnerabilityName: "Acme Gateway Command Injection Vulnerability", dateAdded: day(1), shortDescription: "Acme Gateway contains a command injection (CWE-78) in the /admin path; see vendor's \"KB-12\" <advisory>.", dueDate: day(-20), knownRansomwareCampaignUse: "Known" },
    ],
  },
  "services.nvd.nist.gov": {
    totalResults: 3,
    vulnerabilities: [
      { cve: { id: "CVE-2026-1111", published: iso(3000).replace("Z", ""), vulnStatus: "Analyzed", descriptions: [{ lang: "en", value: "A command injection in Acme Gateway allows remote attackers to run code." }], metrics: { cvssMetricV31: [{ type: "Secondary", cvssData: { baseScore: 7.1, baseSeverity: "HIGH" } }, { type: "Primary", cvssData: { baseScore: 9.8, baseSeverity: "CRITICAL" } }] } } },
      { cve: { id: "CVE-2026-2222", published: iso(200).replace("Z", ""), vulnStatus: "Received", descriptions: [{ lang: "es", value: "hola" }, { lang: "en", value: "Improper access control in Foo CMS before 3.2 lets users read drafts." }], metrics: {} } },
      { cve: { id: "CVE-2026-3333", published: iso(100).replace("Z", ""), vulnStatus: "Rejected", descriptions: [{ lang: "en", value: "Rejected reason: duplicate." }] } },
    ],
  },
  "cve.circl.lu/api/vulnerability/last": [
    { cveMetadata: { cveId: "CVE-2026-2222", state: "PUBLISHED", datePublished: iso(210) }, containers: { cna: { title: "Foo CMS draft disclosure", descriptions: [{ lang: "en", value: "Foo CMS exposes drafts." }], metrics: [{ cvssV3_1: { baseScore: 5.3, baseSeverity: "MEDIUM" } }], affected: [{ vendor: "Foo", product: "Foo CMS" }, { vendor: "n/a", product: "n/a" }] } } },
    { cveMetadata: { cveId: "CVE-2026-4444", state: "REJECTED", datePublished: iso(50) }, containers: { cna: {} } },
    { document: { title: "Some CSAF doc" } },
  ],
  "api.github.com/advisories": [
    { ghsa_id: "GHSA-abcd-1234-efgh", cve_id: "CVE-2026-2222", summary: "Foo CMS: drafts readable by any user", description: "### Impact\nAny **authenticated** user can read drafts. See [docs](https://example.com).", severity: "moderate", published_at: iso(180), withdrawn_at: null, cvss: { score: 5.3 }, vulnerabilities: [{ package: { ecosystem: "npm", name: "foo-cms" } }] },
    { ghsa_id: "GHSA-zzzz-9999-yyyy", cve_id: null, summary: "bar-lib prototype pollution", description: "Prototype pollution in `merge()`.", severity: "high", published_at: iso(60), withdrawn_at: null, cvss: null, vulnerabilities: [{ package: { ecosystem: "pip", name: "bar-lib" } }] },
  ],
  "api.ransomware.live": [
    { victim: "Example Hospital Group", group: "lockbit3", discovered: iso(90).replace("T", " ").replace("Z", ""), country: "US", activity: "Healthcare", url: "https://www.ransomware.live/id/RXhhbXBsZQ==", claim_url: "http://abcdefonionaddress.onion/post/1" },
    { post_title: "Legacy Shape Ltd", group_name: "akira", discovered: iso(500), country: "GB", activity: "Not Found", url: "http://evil.onion/leak" },
  ],
  "isc.sans.edu/api/infocon": { status: "green" },
  "isc.sans.edu/api/topports": { 0: { rank: 1, targetport: 23, records: 91234, targets: 10, sources: 20 }, 1: { rank: 2, targetport: 22, records: 50000 }, limit: 8, date: day(0) },
  "api.first.org": { status: "OK", data: [{ cve: "CVE-2026-1111", epss: "0.942310000", percentile: "0.999120000", date: day(0) }] },
};

export const rss = {
  "feeds.feedburner.com": `<?xml version="1.0"?><rss version="2.0"><channel><title>THN</title>
    <item><title><![CDATA[New "Botnet" Hits Routers &amp; Cameras]]></title><link>https://thehackernews.com/2026/11/botnet.html</link>
    <pubDate>${new Date(Date.now() - 30 * 60_000).toUTCString()}</pubDate>
    <description><![CDATA[<p>Researchers found a <b>botnet</b> &#8212; details <a href="x">here</a>.</p><script>alert(1)</script>]]></description></item>
    <item><title>Bad link item</title><link>javascript:alert(1)</link><pubDate>${new Date().toUTCString()}</pubDate></item>
    <item><title>No date item</title><link>https://thehackernews.com/x</link></item></channel></rss>`,
  "krebsonsecurity.com": `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title type="html">Atom &lt;em&gt;entry&lt;/em&gt; title</title>
    <link rel="self" href="https://krebsonsecurity.com/self"/><link rel="alternate" href="https://krebsonsecurity.com/2026/11/post/"/>
    <updated>${new Date(Date.now() - 45 * 60_000).toISOString()}</updated><summary>Short summary.</summary></entry></feed>`,
};
