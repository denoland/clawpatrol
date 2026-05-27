import { useEffect, useRef, useState } from "react";
import { copyText } from "../lib/clipboard";

// CopyButton is the small icon button rendered in section headers
// on the request detail page. `text` is resolved lazily so callers
// can avoid serialising large bodies until the user clicks. Feedback
// is a check icon that replaces the clipboard glyph for ~1.5s after
// a successful copy; failure flashes red briefly with the error in
// the tooltip.
export function CopyButton({
  text,
  label,
  disabled,
}: {
  text: () => string;
  label: string;
  disabled?: boolean;
}) {
  const [state, setState] = useState<"idle" | "copied" | "error">("idle");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, []);

  const flash = (next: "copied" | "error") => {
    if (timer.current) clearTimeout(timer.current);
    setState(next);
    timer.current = setTimeout(() => setState("idle"), 1500);
  };

  const title =
    state === "copied"
      ? `Copied ${label}`
      : state === "error"
        ? `Failed to copy ${label}`
        : `Copy ${label}`;

  return (
    <button
      type="button"
      // Section is a <details><summary>; without stopPropagation
      // the click would also toggle the section collapse.
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        if (disabled) return;
        copyText(text()).then((ok) => flash(ok ? "copied" : "error"));
      }}
      disabled={disabled}
      aria-label={title}
      title={title}
      className={
        "inline-flex items-center justify-center w-6 h-6 cursor-pointer " +
        "text-text-muted hover:text-text " +
        "disabled:cursor-not-allowed disabled:text-text-subtle disabled:hover:text-text-subtle " +
        (state === "error" ? "text-danger-500 hover:text-danger-500 " : "") +
        (state === "copied" ? "text-success-600 hover:text-success-600 " : "")
      }
    >
      {state === "copied" ? <CheckIcon /> : <ClipboardIcon />}
    </button>
  );
}

function ClipboardIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <rect x="9" y="9" width="10" height="11" rx="1" />
      <path d="M5 15V5a1 1 0 0 1 1-1h10" />
    </svg>
  );
}

function CheckIcon() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="m5 12 5 5L20 7" />
    </svg>
  );
}
