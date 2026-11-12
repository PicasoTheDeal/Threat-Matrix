import { useMemo, useState } from "react";
import { TOPIC_GROUPS, TOPIC_MAX, normalizeTopic } from "../lib/topics";
import { Dialog } from "./Dialog";

interface Props {
  topics: string[];
  onChange: (topics: string[]) => void;
  onClose: () => void;
}

export function TopicsDialog({ topics, onChange, onClose }: Props) {
  const [query, setQuery] = useState("");
  const selected = useMemo(() => new Set(topics), [topics]);
  const needle = query.trim().toLowerCase();
  const custom = normalizeTopic(query);
  const known = useMemo(() => new Set(Object.values(TOPIC_GROUPS).flat().map((t) => t.toUpperCase())), []);
  const full = topics.length >= TOPIC_MAX;

  const toggle = (label: string) => {
    const topic = normalizeTopic(label);
    if (!topic) return;
    if (selected.has(topic)) onChange(topics.filter((t) => t !== topic));
    else if (!full) onChange([...topics, topic]);
  };

  const addCustom = (event: React.FormEvent) => {
    event.preventDefault();
    if (custom && !selected.has(custom) && !full) {
      onChange([...topics, custom]);
      setQuery("");
    }
  };

  return (
    <Dialog title="Topics you follow" onClose={onClose}>
      <p className="lead">Pick the products and threats you care about. The “For you” view shows only items that mention them.</p>

      <form className="topic-search" onSubmit={addCustom}>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value.slice(0, 40))}
          placeholder="Search, or type your own (for example: Grafana)"
          aria-label="Search or add a topic"
          data-autofocus
        />
        {custom && !known.has(custom) && !selected.has(custom) && (
          <button type="submit" className="btn btn-small" disabled={full}>
            Add “{custom}”
          </button>
        )}
      </form>

      {topics.length > 0 && (
        <div className="topic-group">
          <h3>Following ({topics.length})</h3>
          <div className="opts">
            {topics.map((topic) => (
              <button key={topic} type="button" className="opt is-on" onClick={() => toggle(topic)} aria-label={`Stop following ${topic}`}>
                {topic} ×
              </button>
            ))}
          </div>
        </div>
      )}

      <div className="topic-scroll">
        {Object.entries(TOPIC_GROUPS).map(([group, list]) => {
          const shown = list.filter((t) => t.toLowerCase().includes(needle));
          if (shown.length === 0) return null;
          return (
            <div className="topic-group" key={group}>
              <h3>{group}</h3>
              <div className="opts">
                {shown.map((topic) => {
                  const on = selected.has(topic.toUpperCase());
                  return (
                    <button key={topic} type="button" className={on ? "opt is-on" : "opt"} aria-pressed={on} onClick={() => toggle(topic)} disabled={!on && full}>
                      {topic}
                    </button>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>

      <div className="panel-foot">
        <span className="hint">{full ? `You can follow up to ${TOPIC_MAX} topics.` : "Changes save automatically."}</span>
        <button type="button" className="btn btn-primary" onClick={onClose}>Done</button>
      </div>
    </Dialog>
  );
}
