import { memo, type CSSProperties } from "react";
import { SEVERITY_LABEL, hasHeadline, percent, shortAge } from "../lib/format";
import type { FeedItem } from "../lib/types";
import { Icon } from "./Icon";

const TICKS = 20;

// exploit likelihood drawn as a ruler one tick per five percent
export function Ruler({ value }: { value: number }) {
  const filled = Math.max(value > 0 ? 1 : 0, Math.round(value * TICKS));
  return (
    <span className="ruler-meter" aria-hidden="true">
      {Array.from({ length: TICKS }, (_, i) => <i key={i} className={i < filled ? "on" : undefined} />)}
    </span>
  );
}

export function Severity({ item }: { item: FeedItem }) {
  if (!item.severity) return null;
  return (
    <span className={`sev sev-${item.severity}`}>
      <span className="sev-mark" aria-hidden="true" />
      {SEVERITY_LABEL[item.severity]}
      {item.cvss !== undefined && <span className="sev-score">{item.cvss.toFixed(1)}</span>}
    </span>
  );
}

export function Flags({ item }: { item: FeedItem }) {
  if (!item.kev && !item.ransomware) return null;
  return (
    <>
      {item.kev && <span className="flag flag-solid">Exploited</span>}
      {item.ransomware && <span className="flag">Ransomware</span>}
    </>
  );
}

function reference(item: FeedItem): string {
  if (item.kind === "vuln") return item.id;
  if (item.kind === "ransomware") return "Ransomware claim";
  return item.sources[0] || "News";
}

interface Props {
  item: FeedItem;
  index: number;
  likes: number;
  comments: number;
  liked: boolean;
  onOpen: (id: string) => void;
  onLike: (id: string) => void;
}

export const Row = memo(function Row({ item, index, likes, comments, liked, onOpen, onLike }: Props) {
  const headline = hasHeadline(item);
  return (
    <li className={`row row-${item.kind}`} style={{ "--i": Math.min(index % 60, 24) } as CSSProperties}>
      <button type="button" className="row-main" onClick={() => onOpen(item.id)} aria-label={`Open ${headline ? item.title : item.id}`}>
        <span className="c-no">{String(index + 1).padStart(3, "0")}</span>
        <span className="c-ref">
          <span className="ref">{reference(item)}</span>
          <span className="ref-sub">{item.kind === "vuln" ? item.sources.join(" / ") : item.kind === "ransomware" ? item.tags?.[0] : "News"}</span>
        </span>
        <span className="c-subject">
          <span className="row-title">{headline ? item.title : item.summary}</span>
          {headline && item.summary && <span className="row-summary">{item.summary}</span>}
        </span>
        <span className="c-sev">
          <Severity item={item} />
          <Flags item={item} />
        </span>
        <span className="c-epss">
          {item.epss !== undefined && (
            <>
              <Ruler value={item.epss} />
              <span className="epss-num">{percent(item.epss)}</span>
            </>
          )}
        </span>
        <time className="c-age" dateTime={item.date}>{shortAge(item.date)}</time>
      </button>
      <span className="c-act">
        {comments > 0 && <span className="count" aria-label={`${comments} comment${comments === 1 ? "" : "s"}`}>{comments} <Icon name="comment" size={13} /></span>}
        <button
          type="button"
          className={liked ? "like is-liked" : "like"}
          onClick={() => onLike(item.id)}
          aria-pressed={liked}
          aria-label={liked ? "Remove like" : "Like"}
        >
          {likes > 0 ? likes : ""} <Icon name="heart" size={14} filled={liked} />
        </button>
      </span>
    </li>
  );
});

export function ListHead() {
  return (
    <div className="list-head" aria-hidden="true">
      <span>No.</span>
      <span>Ref</span>
      <span>Subject</span>
      <span>Severity</span>
      <span>Exploit likelihood</span>
      <span className="right">Age</span>
      <span />
    </div>
  );
}

export function SkeletonRows() {
  return (
    <ul className="list" aria-busy="true" aria-label="Loading">
      {[62, 80, 48, 71, 55, 84, 66, 42, 75, 58].map((width, i) => (
        <li key={i} className="row row-skeleton">
          <span className="c-no">{String(i + 1).padStart(3, "0")}</span>
          <span className="sk" style={{ width: "70%" }} />
          <span className="sk" style={{ width: `${width}%` }} />
        </li>
      ))}
    </ul>
  );
}
