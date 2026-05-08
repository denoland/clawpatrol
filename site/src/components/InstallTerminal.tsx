import { useState } from "preact/hooks";

export const INSTALL_CMD =
  "curl -fsSL https://clawpatrol.dev/install.sh | sh";

// Flat install pill for the hero. The dramatic CRT lives in the CTA
// section at the bottom; up here we want a single-line code line with
// a copy button, sized to its contents and matching the cream/dark
// page palette rather than competing with the heading.
export function InstallTerminal() {
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(INSTALL_CMD);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard unavailable (insecure context); leave the text
      // selectable so the operator can still copy by hand.
    }
  }

  return (
    <div
      class="squircle-lg bg-console-dark inline-flex items-center
        gap-3 pl-4 pr-3 py-3 max-w-full shadow-sm"
    >
      <pre
        class="font-mono text-sm text-canvas flex-1 min-w-0
          overflow-x-auto whitespace-nowrap leading-none
          [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      >
        <span class="text-crt-dim">$ </span>{INSTALL_CMD}
      </pre>
      <button
        type="button"
        onClick={copy}
        aria-label="Copy install command"
        class="font-mono text-[11px] uppercase tracking-wider
          shrink-0 transition-colors px-2 py-1
          text-rust-300 hover:text-rust-200
          focus:outline-none focus-visible:text-rust-200"
      >
        {copied ? "copied" : "copy"}
      </button>
    </div>
  );
}
