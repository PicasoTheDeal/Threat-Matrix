export const TOPIC_GROUPS: Record<string, string[]> = {
  "Frameworks and libraries": ["React", "Vue", "Angular", "Svelte", "Laravel", "Django", "Flask", "Spring", "Next.js", "Nuxt", "Vite", "Express", "Ruby on Rails", "ASP.NET", "jQuery", "npm", "WordPress"],
  "Attack types": ["Zero-Day", "Malware", "Phishing", "Ransomware", "RAT", "DDoS", "SQL Injection", "XSS", "CSRF", "Buffer Overflow", "Privilege Escalation", "Supply Chain", "Remote Code Execution"],
  "Software and platforms": ["Google Workspace", "Telegram", "WhatsApp", "Discord", "Slack", "Microsoft 365", "Zoom", "AWS", "Azure", "Cloudflare", "Docker", "Kubernetes", "GitLab", "GitHub", "Oracle", "SAP", "Chrome", "Firefox"],
  "Operating systems": ["Linux", "Windows", "macOS", "Android", "iOS", "FreeBSD", "Ubuntu", "Debian", "Red Hat"],
  "Networking and hardware": ["Cisco", "Juniper", "Fortinet", "Palo Alto", "Ubiquiti", "Ivanti", "SonicWall", "NVIDIA", "Intel", "AMD", "Broadcom"],
};

export const TOPIC_MAX = 60;
const TOPIC_RE = /^[\p{L}\p{N} .+#/_-]{1,40}$/u;

// mirrors the servers rules so the user sees the result before saving
export function normalizeTopic(input: string): string | null {
  const topic = input.trim().replace(/\s+/g, " ").toUpperCase();
  return TOPIC_RE.test(topic) ? topic : null;
}
