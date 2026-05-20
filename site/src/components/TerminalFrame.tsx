import type { ComponentChildren } from "preact";

type Props = {
  children: ComponentChildren;
  /** Extra classes applied to the navy surface — typically padding,
   *  display mode (block vs. flex), and any layout-specific tweaks. */
  class?: string;
};

// Navy terminal surface for code/command blocks.
export function TerminalFrame({ children, class: cls = "" }: Props) {
  return (
    <div class={`bg-navy relative max-w-full shadow-sm ${cls}`}>{children}</div>
  );
}
