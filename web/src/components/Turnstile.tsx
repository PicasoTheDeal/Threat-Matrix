import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from "react";
import { TURNSTILE_SITE_KEY, loadTurnstile } from "../lib/turnstile";

export interface TurnstileHandle {
  // resolves with a fresh token waiting briefly if the check is still running
  getToken: () => Promise<string>;
  // tokens are single use call after every submit
  reset: () => void;
}

interface Props {
  // interaction only keeps the widget hidden unless cloudflare needs the visitor to do something
  appearance?: "always" | "interaction-only";
}

export const Turnstile = forwardRef<TurnstileHandle, Props>(function Turnstile({ appearance = "always" }, ref) {
  const containerRef = useRef<HTMLDivElement>(null);
  const widgetId = useRef<string | null>(null);
  const token = useRef<string | null>(null);
  const waiters = useRef<((token: string) => void)[]>([]);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!TURNSTILE_SITE_KEY) return;
    let cancelled = false;
    loadTurnstile()
      .then((turnstile) => {
        if (cancelled || !containerRef.current) return;
        widgetId.current = turnstile.render(containerRef.current, {
          sitekey: TURNSTILE_SITE_KEY,
          appearance,
          theme: document.documentElement.dataset.theme === "dark" ? "dark" : "light",
          callback: (value: string) => {
            token.current = value;
            waiters.current.splice(0).forEach((resolve) => resolve(value));
          },
          "expired-callback": () => {
            token.current = null;
          },
          "error-callback": () => {
            token.current = null;
          },
        });
      })
      .catch(() => !cancelled && setFailed(true));
    return () => {
      cancelled = true;
      if (widgetId.current && window.turnstile) {
        try {
          window.turnstile.remove(widgetId.current);
        } catch {
          // already gone
        }
      }
      widgetId.current = null;
    };
  }, [appearance]);

  useImperativeHandle(ref, () => ({
    getToken: () =>
      new Promise<string>((resolve, reject) => {
        if (!TURNSTILE_SITE_KEY) return reject(new Error("Human verification is not set up for this site."));
        if (token.current) return resolve(token.current);
        const timer = window.setTimeout(() => {
          waiters.current = waiters.current.filter((w) => w !== done);
          reject(new Error("Please complete the verification first."));
        }, 12000);
        const done = (value: string) => {
          window.clearTimeout(timer);
          resolve(value);
        };
        waiters.current.push(done);
      }),
    reset: () => {
      token.current = null;
      if (widgetId.current && window.turnstile) window.turnstile.reset(widgetId.current);
    },
  }));

  if (!TURNSTILE_SITE_KEY) {
    return <p className="note">Human verification is not set up (PUBLIC_TURNSTILE_SITE_KEY is missing).</p>;
  }
  if (failed) return <p className="note">The verification widget could not load. Check your connection or content blocker.</p>;
  return <div ref={containerRef} className={appearance === "always" ? "turnstile" : "turnstile turnstile-quiet"} />;
});
