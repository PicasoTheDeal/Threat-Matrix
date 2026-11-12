import { useState, type RefObject } from "react";
import { SEVERITY_LABEL } from "../lib/format";
import { countActive } from "../lib/filter";
import type { Filters, Range, Severity, Sort, View } from "../lib/types";

const VIEWS: { key: View; label: string }[] = [
  { key: "all", label: "Everything" },
  { key: "vuln", label: "Vulnerabilities" },
  { key: "exploited", label: "Exploited" },
  { key: "news", label: "News" },
  { key: "ransomware", label: "Ransomware" },
  { key: "foryou", label: "For you" },
  { key: "liked", label: "Liked" },
];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const RANGES: { key: Range; label: string }[] = [
  { key: "", label: "Any time" },
  { key: "24h", label: "24 hours" },
  { key: "7d", label: "7 days" },
  { key: "30d", label: "30 days" },
];
const SORTS: { key: Sort; label: string }[] = [
  { key: "newest", label: "Newest" },
  { key: "severity", label: "Most severe" },
  { key: "epss", label: "Most likely exploited" },
  { key: "liked", label: "Most liked" },
];

interface Props {
  filters: Filters;
  sources: string[];
  counts: Partial<Record<View, number>>;
  searchRef: RefObject<HTMLInputElement | null>;
  onChange: (patch: Partial<Filters>) => void;
  onReset: () => void;
}

export function FilterBar({ filters, sources, counts, searchRef, onChange, onReset }: Props) {
  const active = countActive(filters);
  const [open, setOpen] = useState(active > 0);

  const toggleSeverity = (severity: Severity) =>
    onChange({
      severity: filters.severity.includes(severity)
        ? filters.severity.filter((s) => s !== severity)
        : [...filters.severity, severity],
    });

  return (
    <div className="controls">
      <div className="search" role="search">
        <span className="search-label" aria-hidden="true">Search</span>
        <input
          ref={searchRef}
          type="search"
          value={filters.q}
          onChange={(e) => onChange({ q: e.target.value.slice(0, 120) })}
          placeholder="CVE, product, vendor, headline"
          aria-label="Search the index"
          autoComplete="off"
          spellCheck={false}
        />
        {filters.q ? (
          <button type="button" className="tbtn" onClick={() => onChange({ q: "" })}>Clear</button>
        ) : (
          <span className="search-key" aria-hidden="true">[ / ]</span>
        )}
      </div>

      <div className="controls-row">
        <nav className="views" aria-label="Views">
          {VIEWS.map((view) => (
            <button
              key={view.key}
              type="button"
              className={filters.view === view.key ? "view is-active" : "view"}
              aria-current={filters.view === view.key ? "page" : undefined}
              onClick={() => onChange({ view: view.key })}
            >
              {view.label}
              {counts[view.key] !== undefined && <sup>{String(counts[view.key]).padStart(2, "0")}</sup>}
            </button>
          ))}
        </nav>
        <div className="tools">
          <button type="button" className={open || active ? "tbtn is-active" : "tbtn"} onClick={() => setOpen((v) => !v)} aria-expanded={open}>
            Filters{active > 0 ? ` ${active}` : ""}
          </button>
          <label className="select">
            <span aria-hidden="true">Sort:</span>
            <span className="sr-only">Sort by</span>
            <select value={filters.sort} onChange={(e) => onChange({ sort: e.target.value as Sort })}>
              {SORTS.map((sort) => <option key={sort.key} value={sort.key}>{sort.label}</option>)}
            </select>
          </label>
        </div>
      </div>

      {open && (
        <div className="filter-panel">
          <fieldset>
            <legend>Severity</legend>
            <div className="opts">
              {SEVERITIES.map((severity) => {
                const on = filters.severity.includes(severity);
                return (
                  <button key={severity} type="button" className={on ? "opt is-on" : "opt"} aria-pressed={on} onClick={() => toggleSeverity(severity)}>
                    <span className={`sev-mark sev-${severity}`} aria-hidden="true" /> {SEVERITY_LABEL[severity]}
                  </button>
                );
              })}
            </div>
          </fieldset>
          <fieldset>
            <legend>Published</legend>
            <div className="opts">
              {RANGES.map((range) => (
                <button key={range.key || "any"} type="button" className={filters.range === range.key ? "opt is-on" : "opt"} aria-pressed={filters.range === range.key} onClick={() => onChange({ range: range.key })}>
                  {range.label}
                </button>
              ))}
            </div>
          </fieldset>
          <fieldset>
            <legend>Source</legend>
            <label className="select select-boxed">
              <span className="sr-only">Source</span>
              <select value={filters.source} onChange={(e) => onChange({ source: e.target.value })}>
                <option value="">All sources</option>
                {sources.map((source) => <option key={source} value={source}>{source}</option>)}
              </select>
            </label>
          </fieldset>
          {(active > 0 || filters.q) && <button type="button" className="tbtn filter-clear" onClick={onReset}>Clear all</button>}
        </div>
      )}
    </div>
  );
}
