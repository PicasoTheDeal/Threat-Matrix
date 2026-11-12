import { useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError, FEED_FRESH_MS, cachedFeed, deleteAccount, fetchFeed, fetchSummary, fetchTopics, interact,
  loadSession, logout, saveSession, saveTopics,
} from "./lib/api";
import { DEFAULT_FILTERS, applyFilters, filtersFromUrl, filtersToUrl, topicMatcher } from "./lib/filter";
import { timeAgo } from "./lib/format";
import { KEYS, readJson, remove, writeJson } from "./lib/storage";
import type { Feed, FeedItem, Filters, Interaction, Session, View } from "./lib/types";
import { AuthDialog } from "./components/AuthDialog";
import { Row, SkeletonRows } from "./components/Row";
import { Detail } from "./components/Detail";
import { Dialog } from "./components/Dialog";
import { FilterBar } from "./components/FilterBar";
import { List } from "./components/List";
import { Logo } from "./components/Logo";
import { Header } from "./components/Header";
import { Toasts, type Toast } from "./components/Toasts";
import { TopicsDialog } from "./components/TopicsDialog";
import "./App.css";

const AUTO_REFRESH_MS = 5 * 60_000;
type Theme = "light" | "dark";
type Modal = null | "auth" | "topics" | "delete";
const NO_ITEMS: FeedItem[] = [];
const VIEW_TITLES: Record<View, string> = {
  all: "Index",
  vuln: "Vulnerabilities",
  exploited: "Exploited",
  news: "News",
  ransomware: "Ransomware",
  foryou: "For you",
  liked: "Liked",
};

function initialTheme(): Theme {
  const stored = readJson<Theme>(KEYS.theme);
  if (stored === "light" || stored === "dark") return stored;
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export default function App() {
  // feed paint from the stored copy at once then revalidate in the background
  const stored = useMemo(cachedFeed, []);
  const [feed, setFeed] = useState<Feed | null>(stored?.feed ?? null);
  const [checkedAt, setCheckedAt] = useState(stored?.savedAt ?? 0);
  const [refreshing, setRefreshing] = useState(false);
  const [feedError, setFeedError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const inFlight = useRef(false);
  const warmups = useRef(0);

  const [session, setSession] = useState<Session | null>(loadSession);
  const [topics, setTopics] = useState<string[]>([]);
  const [counts, setCounts] = useState<Record<string, [number, number]>>({});
  const [liked, setLiked] = useState<Set<string>>(new Set());

  const [filters, setFilters] = useState<Filters>(() => filtersFromUrl(window.location.search));
  const [openId, setOpenId] = useState<string | null>(() => new URLSearchParams(window.location.search).get("item"));
  const [modal, setModal] = useState<Modal>(null);
  const [theme, setTheme] = useState<Theme>(initialTheme);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const searchRef = useRef<HTMLInputElement>(null);
  // the session itself lives in an http only cookie and the page only knows who is signed in
  const user = session?.username ?? null;

  const notify = useCallback((message: string, tone: "info" | "error" = "info") => {
    const id = Date.now() + Math.random();
    setToasts((list) => [...list.slice(-2), { id, message, tone }]);
    window.setTimeout(() => setToasts((list) => list.filter((t) => t.id !== id)), tone === "error" ? 6000 : 3500);
  }, []);

  const loadFeed = useCallback(async (force = false) => {
    if (inFlight.current) return;
    inFlight.current = true;
    setRefreshing(true);
    try {
      const next = await fetchFeed(force);
      // keep what is on screen if the server is still warming up and has nothing yet
      setFeed((current) => (next.items.length === 0 && current && current.items.length > 0 ? current : next));
      setCheckedAt(Date.now());
      setFeedError(null);
    } catch (err) {
      setFeedError(err instanceof Error ? err.message : "The feed could not be loaded.");
    } finally {
      inFlight.current = false;
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    KEYS.legacy.forEach(remove);
    if (!stored || Date.now() - stored.savedAt > FEED_FRESH_MS) loadFeed();
  }, [stored, loadFeed]);

  // right after a deploy the server fills its cache source by source poll briefly until it is complete
  useEffect(() => {
    if (!feed || feed.pending === 0 || warmups.current >= 8) return;
    const timer = window.setTimeout(() => {
      warmups.current += 1;
      loadFeed(true);
    }, 6000);
    return () => window.clearTimeout(timer);
  }, [feed, loadFeed]);

  // refresh every few minutes while the tab is visible and when the user comes back to it
  useEffect(() => {
    const tick = () => {
      setNow(Date.now());
      if (document.visibilityState === "visible" && Date.now() - checkedAt > AUTO_REFRESH_MS) loadFeed();
    };
    const timer = window.setInterval(tick, 60_000);
    document.addEventListener("visibilitychange", tick);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", tick);
    };
  }, [checkedAt, loadFeed]);

  // session
  const endSession = useCallback((message?: string) => {
    saveSession(null);
    setSession(null);
    setTopics([]);
    setLiked(new Set());
    setFilters((f) => (f.view === "foryou" || f.view === "liked" ? { ...f, view: "all" } : f));
    if (message) notify(message);
  }, [notify]);

  const expired = useCallback(() => {
    endSession("Your session ended. Please sign in again.");
    setModal("auth");
  }, [endSession]);

  useEffect(() => {
    let cancelled = false;
    fetchSummary()
      .then((summary) => {
        if (cancelled) return;
        setCounts(summary.counts);
        setLiked(new Set(summary.liked));
      })
      .catch((err) => {
        if (!cancelled && err instanceof ApiError && err.status === 401) expired();
      });
    if (user) {
      fetchTopics()
        .then((data) => !cancelled && setTopics(data.tags))
        .catch(() => undefined);
    }
    return () => {
      cancelled = true;
    };
  }, [user, expired]);

  const signOut = () => {
    if (user) logout().catch(() => undefined);
    endSession("Signed out.");
  };

  const changeTopics = (next: string[]) => {
    setTopics(next);
    if (!user) return;
    saveTopics(next).catch((err) => {
      if (err instanceof ApiError && err.status === 401) expired();
      else notify("Topics could not be saved. Try again.", "error");
    });
  };

  // likes
  const onInteraction = useCallback((id: string, interaction: Interaction) => {
    setCounts((c) => ({ ...c, [id]: [interaction.likes, interaction.comments.length] }));
    setLiked((set) => {
      if (set.has(id) === interaction.liked) return set;
      const next = new Set(set);
      if (interaction.liked) next.add(id);
      else next.delete(id);
      return next;
    });
  }, []);

  const likedRef = useRef(liked);
  useEffect(() => {
    likedRef.current = liked;
  }, [liked]);

  const toggleLike = useCallback((id: string) => {
    if (!user) {
      setModal("auth");
      return;
    }
    const wasLiked = likedRef.current.has(id);
    const bump = (delta: number, on: boolean) => {
      setCounts((c) => ({ ...c, [id]: [Math.max(0, (c[id]?.[0] ?? 0) + delta), c[id]?.[1] ?? 0] }));
      setLiked((set) => {
        const next = new Set(set);
        if (on) next.add(id);
        else next.delete(id);
        return next;
      });
    };
    bump(wasLiked ? -1 : 1, !wasLiked); // optimistic
    interact({ action: wasLiked ? "unlike" : "like", log_id: id })
      .then((interaction) => onInteraction(id, interaction))
      .catch((err) => {
        bump(wasLiked ? 1 : -1, wasLiked);
        if (err instanceof ApiError && err.status === 401) expired();
        else notify(err instanceof Error ? err.message : "That didn't work. Try again.", "error");
      });
  }, [user, onInteraction, expired, notify]);

  // filters and url
  const deferredFilters = useDeferredValue(filters);
  const items = feed?.items ?? NO_ITEMS;
  const visibleItems = useMemo(
    () => applyFilters(items, deferredFilters, { topics, liked, likeCounts: counts, now }),
    // like counts only matter for the most liked order skip re sorting on every like otherwise
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, deferredFilters, topics, deferredFilters.view === "liked" ? liked : null, deferredFilters.sort === "liked" ? counts : null, now],
  );

  const viewCounts = useMemo(() => {
    const out: Partial<Record<View, number>> = { exploited: items.filter((i) => i.kev).length };
    if (session && topics.length > 0) out.foryou = items.filter(topicMatcher(topics)).length;
    return out;
  }, [items, session, topics]);

  const sourceNames = useMemo(() => [...new Set(items.flatMap((i) => i.sources))].sort((a, b) => a.localeCompare(b)), [items]);
  const byId = useMemo(() => new Map(items.map((i) => [i.id, i])), [items]);
  const openItem = openId ? byId.get(openId) ?? null : null;

  useEffect(() => {
    const url = filtersToUrl(filters, openId);
    const current = window.location.search || window.location.pathname;
    const state = openId && window.history.state?.item === openId ? window.history.state : null;
    if (url !== current || window.history.state !== state) window.history.replaceState(state, "", url);
  }, [filters, openId]);

  useEffect(() => {
    const onPop = () => {
      setFilters(filtersFromUrl(window.location.search));
      setOpenId(new URLSearchParams(window.location.search).get("item"));
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  const openDetail = useCallback((id: string) => {
    // a history entry per opened item so the browsers back button closes the panel
    window.history.pushState({ item: id }, "", filtersToUrl(filtersFromUrl(window.location.search), id));
    setOpenId(id);
  }, []);

  const closeDetail = useCallback(() => {
    if (window.history.state?.item) window.history.back();
    else setOpenId(null);
  }, []);

  const patchFilters = useCallback((patch: Partial<Filters>) => {
    if ((patch.view === "foryou" || patch.view === "liked") && !loadSession()) {
      setModal("auth");
      return;
    }
    setFilters((f) => ({ ...f, ...patch }));
  }, []);

  // theme and keyboard
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.querySelector('meta[name="theme-color"]')?.setAttribute("content", theme === "dark" ? "#0c0c0b" : "#f1efe9");
  }, [theme]);

  const toggleTheme = () =>
    setTheme((t) => {
      const next = t === "dark" ? "light" : "dark";
      writeJson(KEYS.theme, next);
      return next;
    });

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement;
      const typing = target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT" || target.isContentEditable;
      if (event.key === "/" && !typing && !event.metaKey && !event.ctrlKey && !document.querySelector(".overlay")) {
        event.preventDefault();
        searchRef.current?.focus();
      } else if (event.key === "Escape" && target === searchRef.current) {
        searchRef.current?.blur();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);

  // render helpers
  const renderItem = useCallback(
    (item: FeedItem, index: number) => (
      <Row
        key={item.id}
        item={item}
        index={index}
        likes={counts[item.id]?.[0] ?? 0}
        comments={counts[item.id]?.[1] ?? 0}
        liked={liked.has(item.id)}
        onOpen={openDetail}
        onLike={toggleLike}
      />
    ),
    [counts, liked, openDetail, toggleLike],
  );

  const loading = !feed && !feedError;
  const warming = !!feed && feed.items.length === 0 && feed.pending > 0;
  const filtered = filters.q !== "" || filters.view !== "all" || filters.severity.length > 0 || filters.source !== "" || filters.range !== "";

  let empty: React.ReactNode = null;
  if (feed && !warming && visibleItems.length === 0) {
    if (filters.view === "foryou" && topics.length === 0) {
      empty = (
        <div className="empty">
          <Logo size={56} />
          <h2>Follow a few topics</h2>
          <p>Choose the products and threats you care about, and this view will show only what mentions them.</p>
          <button type="button" className="btn btn-primary" onClick={() => setModal("topics")}>Choose topics</button>
        </div>
      );
    } else if (filters.view === "liked" && liked.size === 0) {
      empty = (
        <div className="empty">
          <Logo size={56} />
          <h2>Nothing liked yet</h2>
          <p>Use the heart on any item to keep it here.</p>
        </div>
      );
    } else if (items.length === 0) {
      empty = (
        <div className="empty">
          <Logo size={56} />
          <h2>No data yet</h2>
          <p>None of the sources have answered so far. This usually clears up within a few minutes.</p>
          <button type="button" className="btn" onClick={() => loadFeed(true)}>Try again</button>
        </div>
      );
    } else {
      empty = (
        <div className="empty">
          <Logo size={56} />
          <h2>No matches</h2>
          <p>Nothing in the feed fits this search and these filters.</p>
          <button type="button" className="btn" onClick={() => setFilters({ ...DEFAULT_FILTERS, view: filters.view })}>Clear search and filters</button>
        </div>
      );
    }
  }

  return (
    <div className="app">
      <Header
        session={session}
        theme={theme}
        onToggleTheme={toggleTheme}
        onSignIn={() => setModal("auth")}
        onSignOut={signOut}
        onTopics={() => setModal("topics")}
        onDeleteAccount={() => setModal("delete")}
        onHome={() => {
          setFilters(DEFAULT_FILTERS);
          window.scrollTo({ top: 0 });
        }}
      />

      <main className="main">
        <section className="mast">
          <h1 className="mast-title">
            {VIEW_TITLES[filters.view]}
            {feed && !warming && <sup>{visibleItems.length}</sup>}
          </h1>
          <div className="mast-side">
            <ol className="legend" aria-label="Sources">
              {(feed?.sources ?? []).map((source, i) => (
                <li key={source.key} className={source.ok ? undefined : "is-down"}>
                  <span>[{i + 1}]</span>
                  <span>{source.label}</span>
                  <span>{source.ok ? "ok" : "no signal"}</span>
                </li>
              ))}
            </ol>
            <p className="mast-meta" aria-live="polite">
              {feedError ? <span className="is-down">Offline, showing saved data</span> : checkedAt > 0 && <span>Updated {timeAgo(checkedAt, now)}</span>}
              <button type="button" className="tbtn" onClick={() => loadFeed(true)} disabled={refreshing}>Refresh</button>
            </p>
          </div>
        </section>

        <FilterBar filters={filters} sources={sourceNames} counts={viewCounts} searchRef={searchRef} onChange={patchFilters} onReset={() => setFilters({ ...DEFAULT_FILTERS, view: filters.view, sort: filters.sort })} />

        {feed && !warming && filtered && (
          <p className="status">
            Showing {visibleItems.length} of {items.length}
            {filters.view === "foryou" && topics.length > 0 && (
              <> / <button type="button" className="tbtn" onClick={() => setModal("topics")}>{topics.length} topic{topics.length === 1 ? "" : "s"}</button></>
            )}
          </p>
        )}

        {feedError && !feed && (
          <div className="empty">
          <Logo size={56} />
            <h2>The index could not be loaded</h2>
            <p>{feedError}</p>
            <button type="button" className="btn btn-primary" onClick={() => loadFeed(true)}>Try again</button>
          </div>
        )}

        {(loading || warming) && (
          <>
            <p className="loading">
              <Logo size={44} flap />
              <span>{warming ? "Collecting the first batch of data from the sources" : "Loading the index"}</span>
            </p>
            <SkeletonRows />
          </>
        )}

        {empty}
        {feed && visibleItems.length > 0 && <List key={JSON.stringify(deferredFilters)} items={visibleItems} renderItem={renderItem} />}
      </main>

      {feed && (
        <footer className="footer">
          <span className="footer-mark"><Logo size={22} /> Threat Matrix</span>
          <span>
            {feed.pulse.infocon && <>SANS ISC threat level: <strong className={`infocon-${feed.pulse.infocon}`}>{feed.pulse.infocon}</strong></>}
            {feed.pulse.ports && feed.pulse.ports.length > 0 && <> / Most probed ports: {feed.pulse.ports.slice(0, 6).map((p) => p.port).join(" ")}</>}
          </span>
          <span>Data: CISA KEV, NVD, CIRCL, GitHub Advisories, FIRST EPSS, ransomware.live, SANS ISC, public news feeds</span>
        </footer>
      )}

      {openItem && (
        <Detail
          key={openItem.id}
          item={openItem}
          session={session}
          likes={counts[openItem.id]?.[0] ?? 0}
          liked={liked.has(openItem.id)}
          onClose={closeDetail}
          onLike={toggleLike}
          onInteraction={onInteraction}
          onRequireSignIn={() => setModal("auth")}
          onSessionExpired={expired}
          onSearchTag={(tag) => {
            setOpenId(null);
            setFilters({ ...DEFAULT_FILTERS, q: tag });
          }}
          notify={notify}
        />
      )}

      {modal === "auth" && (
        <AuthDialog
          onClose={() => setModal(null)}
          onSignedIn={(next, isNew) => {
            saveSession(next);
            setSession(next);
            setModal(isNew ? "topics" : null);
            notify(isNew ? `Welcome, ${next.username}.` : `Signed in as ${next.username}.`);
          }}
        />
      )}
      {modal === "topics" && session && <TopicsDialog topics={topics} onChange={changeTopics} onClose={() => setModal(null)} />}
      {modal === "delete" && session && (
        <DeleteAccountDialog
          session={session}
          onClose={() => setModal(null)}
          onDeleted={() => {
            setModal(null);
            endSession("Your account and everything in it were deleted.");
          }}
        />
      )}

      <Toasts toasts={toasts} onDismiss={(id) => setToasts((list) => list.filter((t) => t.id !== id))} />
    </div>
  );
}

function DeleteAccountDialog({ session, onClose, onDeleted }: { session: Session; onClose: () => void; onDeleted: () => void }) {
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      await deleteAccount(password);
      onDeleted();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
      setBusy(false);
    }
  };

  return (
    <Dialog title="Delete account" onClose={onClose}>
      <form className="form" onSubmit={submit}>
        <p className="lead">
          This permanently removes <strong>{session.username}</strong> along with its topics, likes and comments. It cannot be undone.
        </p>
        {error && <p className="form-error" role="alert">{error}</p>}
        <label className="field">
          <span>Confirm with your password</span>
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" data-autofocus />
        </label>
        <div className="panel-foot">
          <button type="button" className="btn" onClick={onClose}>Keep account</button>
          <button type="submit" className="btn btn-danger" disabled={!password || busy}>{busy ? "Deleting…" : "Delete account"}</button>
        </div>
      </form>
    </Dialog>
  );
}
