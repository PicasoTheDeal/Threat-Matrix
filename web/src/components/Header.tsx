import { useEffect, useRef, useState } from "react";
import type { Session } from "../lib/types";
import { Logo } from "./Logo";

interface Props {
  session: Session | null;
  theme: "light" | "dark";
  onToggleTheme: () => void;
  onSignIn: () => void;
  onSignOut: () => void;
  onTopics: () => void;
  onDeleteAccount: () => void;
  onHome: () => void;
}

export function Header(props: Props) {
  const { session, theme } = props;
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!menuOpen) return;
    const onDown = (event: MouseEvent) => {
      if (!menuRef.current?.contains(event.target as Node)) setMenuOpen(false);
    };
    const onKey = (event: KeyboardEvent) => event.key === "Escape" && setMenuOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [menuOpen]);

  const pick = (action: () => void) => () => {
    setMenuOpen(false);
    action();
  };

  return (
    <header className="top">
      <button type="button" className="wordmark" onClick={props.onHome} aria-label="Threat Matrix, back to the full index">
        <Logo />
        Threat Matrix
      </button>
      <span className="top-rule" aria-hidden="true" />
      <nav className="top-actions" aria-label="Account">
        <button type="button" className="tbtn" onClick={props.onToggleTheme} aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
          {theme === "dark" ? "Light" : "Dark"}
        </button>
        {session ? (
          <div className="menu" ref={menuRef}>
            <button type="button" className="tbtn" onClick={() => setMenuOpen((v) => !v)} aria-haspopup="menu" aria-expanded={menuOpen}>
              {session.username}
            </button>
            {menuOpen && (
              <div className="menu-list" role="menu">
                <button type="button" role="menuitem" onClick={pick(props.onTopics)}><span>[1]</span> Topics you follow</button>
                <button type="button" role="menuitem" onClick={pick(props.onSignOut)}><span>[2]</span> Sign out</button>
                <button type="button" role="menuitem" onClick={pick(props.onDeleteAccount)}><span>[3]</span> Delete account</button>
              </div>
            )}
          </div>
        ) : (
          <button type="button" className="tbtn tbtn-solid" onClick={props.onSignIn}>Sign in</button>
        )}
      </nav>
    </header>
  );
}
