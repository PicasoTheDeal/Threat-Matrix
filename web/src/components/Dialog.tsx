import { useEffect, useRef, type ReactNode } from "react";

interface Props {
  title: string;
  variant?: "modal" | "sheet";
  // hide the visible heading when the content brings its own
  hideTitle?: boolean;
  onClose: () => void;
  children: ReactNode;
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
let openCount = 0;

// accessible modal labelled closes on escape or backdrop click keeps focus inside and restores it
export function Dialog({ title, variant = "modal", hideTitle = false, onClose, children }: Props) {
  const panelRef = useRef<HTMLDivElement>(null);
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const panel = panelRef.current!;
    (panel.querySelector<HTMLElement>("[data-autofocus]") || panel).focus({ preventScroll: true });
    openCount += 1;
    document.documentElement.classList.add("no-scroll");

    const onKey = (event: KeyboardEvent) => {
      // only the top most dialog reacts
      if (panel.closest(".overlay") !== [...document.querySelectorAll(".overlay")].pop()) return;
      if (event.key === "Escape") {
        event.stopPropagation();
        onCloseRef.current();
      } else if (event.key === "Tab") {
        const items = [...panel.querySelectorAll<HTMLElement>(FOCUSABLE)].filter((el) => el.offsetParent !== null);
        if (items.length === 0) return;
        const first = items[0];
        const last = items[items.length - 1];
        if (event.shiftKey && (document.activeElement === first || document.activeElement === panel)) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      openCount -= 1;
      if (openCount === 0) document.documentElement.classList.remove("no-scroll");
      previous?.focus?.({ preventScroll: true });
    };
  }, []);

  return (
    <div
      className={`overlay overlay-${variant}`}
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div ref={panelRef} className={`panel panel-${variant}`} role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}>
        <div className="panel-head">
          {hideTitle ? <span /> : <h2 className="panel-title">{title}</h2>}
          <button type="button" className="tbtn" onClick={onClose}>Close</button>
        </div>
        {children}
      </div>
    </div>
  );
}
