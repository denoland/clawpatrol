import type { ComponentChildren } from "preact";

type Props = {
  children: ComponentChildren;
  /** Extra classes applied to the navy surface — typically padding,
   *  display mode (block vs. flex), and any layout-specific tweaks. */
  class?: string;
};

// Navy terminal surface with crosshair-style border marks that extend
// 1rem past each edge (architectural-drawing convention). The parent
// container must not clip overflow within ~1rem of the frame, or the
// crosshair extensions will be cut off.
export function TerminalFrame({ children, class: cls = "" }: Props) {
  return (
    <div
      class={`bg-navy relative max-w-full shadow-sm
        before:absolute before:top-0 before:-left-4 before:h-full before:w-[calc(100%+2rem)]
        before:border-y before:border-navy-100
        after:absolute after:-top-4 after:left-0 after:h-[calc(100%+2rem)] after:w-full
        after:border-x after:border-navy-100
        ${cls}`}
    >
      {children}
    </div>
  );
}
