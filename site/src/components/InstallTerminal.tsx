import { useState } from "preact/hooks";

export const INSTALL_CMD = "curl -fsSL https://clawpatrol.dev/install.sh | sh";

type Variant = "compact" | "expanded";

// Navy install pill with a copy button. Two sizes:
//   • compact — used inline (e.g. hero column).
//   • expanded — bigger padding and type for standalone use as a
//     section's primary install affordance.
export function InstallTerminal({ variant = "compact" }: { variant?: Variant }) {
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

  const expanded = variant === "expanded";
  const surface = expanded ? "pl-10 pr-8 py-8" : "pl-6 pr-4 py-5";
  const codeSize = expanded ? "text-base" : "text-[12px]";

  return (
    <div
      class={`squircle-lg bg-navy inline-flex items-center
        gap-4 max-w-full shadow-sm ${surface}`}
    >
      <pre
        class={`font-mono ${codeSize} text-canvas flex-1 min-w-0
          overflow-x-auto whitespace-nowrap leading-none
          [scrollbar-width:none] [&::-webkit-scrollbar]:hidden`}
      >
        {INSTALL_CMD}
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
