import { useRef, useState } from "react";
import { login, signup } from "../lib/api";
import { PASSWORD_MAX, PASSWORD_MIN, generatePassword, passwordStrength } from "../lib/password";
import type { Session } from "../lib/types";
import { Dialog } from "./Dialog";
import { Logo } from "./Logo";
import { Turnstile, type TurnstileHandle } from "./Turnstile";

interface Props {
  onClose: () => void;
  onSignedIn: (session: Session, isNew: boolean) => void;
}

const USERNAME_RE = /^[a-zA-Z0-9_.-]{3,32}$/;

export function AuthDialog({ onClose, onSignedIn }: Props) {
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const turnstile = useRef<TurnstileHandle>(null);

  const isSignup = mode === "signup";
  const strength = passwordStrength(password);
  const usernameOk = USERNAME_RE.test(username);
  const canSubmit = !busy && username.length > 0 && password.length > 0 && (!isSignup || (usernameOk && strength.score > 0));

  const switchMode = (next: "login" | "signup") => {
    setMode(next);
    setError(null);
    setCopied(false);
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const turnstileToken = await turnstile.current!.getToken();
      const session = await (isSignup ? signup : login)({ username: username.trim(), password, turnstileToken });
      onSignedIn(session, isSignup);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
      turnstile.current?.reset();
    } finally {
      setBusy(false);
    }
  };

  const generate = async () => {
    const value = generatePassword();
    setPassword(value);
    setShowPassword(true);
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <Dialog title={isSignup ? "Create your account" : "Sign in"} onClose={onClose}>
      <div className="dialog-mark"><Logo size={52} /></div>
      <div className="tabs" role="tablist" aria-label="Account">
        <button type="button" role="tab" aria-selected={!isSignup} className={!isSignup ? "is-active" : ""} onClick={() => switchMode("login")}>
          Sign in
        </button>
        <button type="button" role="tab" aria-selected={isSignup} className={isSignup ? "is-active" : ""} onClick={() => switchMode("signup")}>
          Create account
        </button>
      </div>

      <form className="form" onSubmit={submit} noValidate>
        {error && <p className="form-error" role="alert">{error}</p>}

        <label className="field">
          <span>Username</span>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value.replace(/[^a-zA-Z0-9_.-]/g, "").slice(0, 32))}
            autoComplete="username"
            autoCapitalize="none"
            spellCheck={false}
            required
            data-autofocus
          />
          {isSignup && <small>3 to 32 characters. Letters, numbers, dot, dash and underscore.</small>}
        </label>

        <label className="field">
          <span>Password</span>
          <span className="input-wrap">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
                setCopied(false);
              }}
              autoComplete={isSignup ? "new-password" : "current-password"}
              maxLength={isSignup ? PASSWORD_MAX : 4096}
              required
            />
            <button type="button" className="tbtn" onClick={() => setShowPassword((v) => !v)} aria-label={showPassword ? "Hide password" : "Show password"}>
              {showPassword ? "Hide" : "Show"}
            </button>
          </span>
        </label>

        {isSignup && (
          <div className="strength">
            <div className="strength-bar" data-score={strength.score} aria-hidden="true">
              <span /><span /><span /><span />
            </div>
            <div className="strength-row">
              <span className="hint" aria-live="polite">
                {password ? strength.label : `At least ${PASSWORD_MIN} characters. A long phrase works well.`}
                {copied && " · Copied. Save it in your password manager."}
              </span>
              <button type="button" className="link" onClick={generate}>Generate one</button>
            </div>
          </div>
        )}

        <Turnstile ref={turnstile} key={mode} />

        <button type="submit" className="btn btn-primary btn-block" disabled={!canSubmit}>
          {busy ? "One moment…" : isSignup ? "Create account" : "Sign in"}
        </button>
        <p className="hint center">
          {isSignup
            ? "No email needed. That also means a lost password cannot be recovered."
            : "An account lets you follow topics, like items and leave comments."}
        </p>
      </form>
    </Dialog>
  );
}
