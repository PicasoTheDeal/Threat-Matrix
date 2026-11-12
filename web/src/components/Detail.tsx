import { useEffect, useRef, useState } from "react";
import { ApiError, fetchInteraction, interact } from "../lib/api";
import { SEVERITY_LABEL, fullDate, hasHeadline, kindLabel, percent, safeHref, timeAgo } from "../lib/format";
import type { Comment, FeedItem, Interaction, Session } from "../lib/types";
import { Flags, Ruler, Severity } from "./Row";
import { Dialog } from "./Dialog";
import { Icon } from "./Icon";
import { Turnstile, type TurnstileHandle } from "./Turnstile";

const COMMENT_MAX = 1000;

interface Props {
  item: FeedItem;
  session: Session | null;
  likes: number;
  liked: boolean;
  onClose: () => void;
  onLike: (id: string) => void;
  onInteraction: (id: string, interaction: Interaction) => void;
  onRequireSignIn: () => void;
  onSessionExpired: () => void;
  onSearchTag: (tag: string) => void;
  notify: (message: string, tone?: "info" | "error") => void;
}

function Fact({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="fact">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

export function Detail(props: Props) {
  const { item, session, likes, liked, onClose, onLike, onInteraction, notify } = props;
  const [comments, setComments] = useState<Comment[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [editing, setEditing] = useState<{ id: number; text: string } | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);
  const user = session?.username ?? null;
  const headline = hasHeadline(item);

  useEffect(() => {
    let cancelled = false;
    setComments(null);
    setLoadError(false);
    fetchInteraction(item.id)
      .then((data) => {
        if (cancelled) return;
        setComments(data.comments);
        onInteraction(item.id, data);
      })
      .catch(() => !cancelled && setLoadError(true));
    return () => {
      cancelled = true;
    };
    // oninteraction is stable re run only when the item or the signed in user changes
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [item.id, user]);

  const fail = (err: unknown) => {
    if (err instanceof ApiError && err.status === 401) props.onSessionExpired();
    else notify(err instanceof Error ? err.message : "Something went wrong.", "error");
  };

  const apply = (interaction: Interaction) => {
    setComments(interaction.comments);
    onInteraction(item.id, interaction);
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const content = draft.trim();
    if (!user || !content || sending) return;
    setSending(true);
    try {
      const turnstileToken = await turnstile.current!.getToken();
      apply(await interact({ action: "comment", log_id: item.id, content, turnstileToken }));
      setDraft("");
    } catch (err) {
      fail(err);
    } finally {
      turnstile.current?.reset();
      setSending(false);
    }
  };

  const saveEdit = async () => {
    if (!user || !editing || !editing.text.trim()) return;
    try {
      apply(await interact({ action: "edit_comment", log_id: item.id, comment_id: editing.id, content: editing.text.trim() }));
      setEditing(null);
    } catch (err) {
      fail(err);
    }
  };

  const remove = async (id: number) => {
    if (!user) return;
    try {
      apply(await interact({ action: "delete_comment", log_id: item.id, comment_id: id }));
      notify("Comment deleted.");
    } catch (err) {
      fail(err);
    } finally {
      setConfirmDelete(null);
    }
  };

  const copyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      notify("Link copied.");
    } catch {
      notify("Couldn't copy the link.", "error");
    }
  };

  const primary = safeHref(item.url);
  const links = (item.links || []).filter((l) => safeHref(l.url));
  const isCve = item.id.startsWith("CVE-");

  return (
    <Dialog title={headline ? item.title : item.id} variant="sheet" hideTitle onClose={onClose}>
      <div className="detail">
        <p className="detail-kicker">
          <span className={item.kind === "vuln" ? "mono" : undefined}>{kindLabel(item)}</span>
          <span>{timeAgo(item.date)}</span>
        </p>
        <h2 className="detail-title">{headline ? item.title : item.id}</h2>
        <div className="detail-flags">
          <Severity item={item} />
          <Flags item={item} />
        </div>
        {item.summary && <p className="detail-summary">{item.summary}</p>}

        <div className="detail-actions">
          {primary && (
            <a className="btn btn-primary" href={primary} target="_blank" rel="noopener noreferrer" data-autofocus>
              {item.kind === "news" ? "Read article" : "Open source"}
            </a>
          )}
          <button type="button" className={liked ? "btn is-liked" : "btn"} onClick={() => onLike(item.id)} aria-pressed={liked}>
            {liked ? "Liked" : "Like"}
            {likes > 0 && <span className="btn-count">{likes}</span>}
          </button>
          <button type="button" className="btn" onClick={copyLink}>
            Copy link
          </button>
        </div>

        <h3 className="section">Specs</h3>
        <dl className="facts">
          {item.severity && (
            <Fact label="Severity">
              {SEVERITY_LABEL[item.severity]}
              {item.cvss !== undefined && ` · CVSS ${item.cvss.toFixed(1)}`}
            </Fact>
          )}
          {item.epss !== undefined && (
            <Fact label="Exploit likelihood">
              <Ruler value={item.epss} />
              {percent(item.epss)} in the next 30 days
              {item.epssPercentile ? ` (higher than ${Math.floor(item.epssPercentile * 100)}% of CVEs)` : ""}
            </Fact>
          )}
          {item.kev && (
            <Fact label="Exploitation">
              Confirmed in the wild (CISA KEV){item.due ? ` · US agencies must fix by ${fullDate(item.due)}` : ""}
            </Fact>
          )}
          <Fact label={item.kind === "ransomware" ? "Listed" : "Published"}>{fullDate(item.date)}</Fact>
          <Fact label={item.sources.length > 1 ? "Sources" : "Source"}>{item.sources.join(", ")}</Fact>
        </dl>

        {item.tags && item.tags.length > 0 && (
          <div className="detail-tags">
            <h3 className="section">Tags</h3>
            {item.tags.map((tag) => (
              <button key={tag} type="button" className="opt" onClick={() => props.onSearchTag(tag)} title={`Search for ${tag}`}>
                {tag}
              </button>
            ))}
          </div>
        )}

        {(links.length > 0 || isCve) && (
          <ul className="detail-links">
            <li><h3 className="section">References</h3></li>
            {links.map((link) => (
              <li key={link.url}>
                <a href={safeHref(link.url)} target="_blank" rel="noopener noreferrer">
                  {link.label} <Icon name="external" size={14} />
                </a>
              </li>
            ))}
            {isCve && (
              <li>
                <a href={`https://github.com/search?q=${encodeURIComponent(item.id)}&type=repositories`} target="_blank" rel="noopener noreferrer">
                  Search GitHub for {item.id} <Icon name="external" size={14} />
                </a>
              </li>
            )}
          </ul>
        )}

        <section className="comments" aria-label="Comments">
          <h3 className="section">Notes{comments && comments.length > 0 ? ` (${comments.length})` : ""}</h3>

          {session ? (
            <form className="comment-form" onSubmit={submit}>
              <textarea
                value={draft}
                onChange={(e) => setDraft(e.target.value.slice(0, COMMENT_MAX))}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) submit(e);
                }}
                placeholder="Add a note for yourself or others. Links are not allowed."
                rows={3}
                aria-label="Your comment"
              />
              <div className="comment-form-foot">
                <span className="hint">{draft.length > COMMENT_MAX - 200 ? `${COMMENT_MAX - draft.length} left` : "Ctrl+Enter to post"}</span>
                <button type="submit" className="btn btn-primary" disabled={!draft.trim() || sending}>
                  {sending ? "Posting…" : "Post"}
                </button>
              </div>
              <Turnstile ref={turnstile} appearance="interaction-only" />
            </form>
          ) : (
            <p className="note">
              <button type="button" className="link" onClick={props.onRequireSignIn}>Sign in</button> to like items and leave comments.
            </p>
          )}

          {loadError && <p className="note">Comments could not be loaded.</p>}
          {!loadError && comments === null && <p className="note">Loading comments…</p>}
          {comments && comments.length === 0 && <p className="note">No comments yet.</p>}

          <ul className="comment-list">
            {[...(comments || [])].reverse().map((comment) => (
              <li key={comment.id} className="comment">
                <p className="comment-head">
                  <strong>{comment.username}</strong>
                  <span>{timeAgo(`${comment.created_at.replace(" ", "T")}Z`)}</span>
                </p>
                {editing?.id === comment.id ? (
                  <div className="comment-edit">
                    <textarea
                      value={editing.text}
                      onChange={(e) => setEditing({ id: comment.id, text: e.target.value.slice(0, COMMENT_MAX) })}
                      rows={3}
                      aria-label="Edit comment"
                      autoFocus
                    />
                    <div className="row-end">
                      <button type="button" className="btn btn-small" onClick={() => setEditing(null)}>Cancel</button>
                      <button type="button" className="btn btn-small btn-primary" onClick={saveEdit} disabled={!editing.text.trim()}>Save</button>
                    </div>
                  </div>
                ) : (
                  <p className="comment-body">{comment.content}</p>
                )}
                {comment.mine && editing?.id !== comment.id && (
                  <div className="comment-tools">
                    {confirmDelete === comment.id ? (
                      <>
                        <span className="hint">Delete this comment?</span>
                        <button type="button" className="link" onClick={() => remove(comment.id)}>Delete</button>
                        <button type="button" className="link" onClick={() => setConfirmDelete(null)}>Keep</button>
                      </>
                    ) : (
                      <>
                        <button type="button" className="link" onClick={() => setEditing({ id: comment.id, text: comment.content })}>Edit</button>
                        <button type="button" className="link" onClick={() => setConfirmDelete(comment.id)}>Delete</button>
                      </>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        </section>
      </div>
    </Dialog>
  );
}
