import { useEffect, useRef, useState, type ReactNode } from "react";
import type { FeedItem } from "../lib/types";
import { ListHead } from "./Row";

const PAGE = 60;

interface Props {
  items: FeedItem[];
  renderItem: (item: FeedItem, index: number) => ReactNode;
}

// the index one row per item rendered in pages as the reader scrolls
export function List({ items, renderItem }: Props) {
  const sentinel = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(PAGE);

  useEffect(() => {
    const el = sentinel.current;
    if (!el || visible >= items.length) return;
    const observer = new IntersectionObserver(
      (entries) => entries.some((e) => e.isIntersecting) && setVisible((v) => v + PAGE),
      { rootMargin: "800px" },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [visible, items.length]);

  return (
    <>
      <ListHead />
      <ul className="list">{items.slice(0, visible).map(renderItem)}</ul>
      {visible < items.length && <div ref={sentinel} className="list-sentinel" />}
    </>
  );
}
