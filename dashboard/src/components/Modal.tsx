import { useEffect, useId, useRef, type ReactNode } from "react";

// Thin wrapper around the native <dialog> element. Opening with
// `.showModal()` gives us role="dialog" + aria-modal="true",
// trapped focus, ESC-to-close, body scroll lock, and a real
// backdrop — for free, no library.
//
// Visual chrome (bg-canvas, navy border, rounded corners,
// shadow, overflow-clip for the rounded edges), the navy-100 header
// strip with title + close ✕, and the size scale all live on this
// component so every modal looks the same. Callers only supply:
//   - title    — the uppercase-navy header label (required)
//   - subtitle — optional secondary line under the title
//   - size     — sm | md | lg (defaults to md)
//   - children — the modal body (header + footer strips are owned here)
type Size = "sm" | "md" | "lg";

const sizes: Record<Size, string> = {
  // sm — narrow forms: connect/credential secret entry.
  sm: "w-full max-w-md",
  // md — single-purpose action modals: scope picker, add-device steps.
  md: "w-full max-w-xl",
  // lg — editor/diff/scrollable-list modals; flex column so an inner
  // body can flex-1 and a header/footer pin top/bottom.
  lg: "w-full max-w-4xl max-h-[85vh] flex flex-col",
};

export function Modal({
  title,
  subtitle,
  size = "md",
  onClose,
  className,
  children,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  size?: Size;
  onClose: () => void;
  className?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();

  useEffect(() => {
    const dlg = ref.current;
    if (!dlg) return;
    if (!dlg.open) dlg.showModal();
    // No cleanup: when the parent unmounts us, React removes the
    // <dialog> from the DOM and the browser tears it down. Calling
    // .close() here would re-fire the close event during unmount and
    // try to setState on an unmounted parent.
  }, []);

  return (
    <dialog
      ref={ref}
      aria-labelledby={titleId}
      onClose={onClose}
      onClick={(e) => {
        // The dialog element itself is only the event target when the
        // user clicks the ::backdrop. Clicks on inner content land on
        // a child, so this only fires for "outside the box" clicks.
        if (e.target === ref.current) ref.current?.close();
      }}
      className={
        "m-auto p-0 text-text bg-canvas border-1.5 border-navy  " +
        "shadow-2xl overflow-hidden backdrop:bg-navy/40 backdrop:backdrop-blur-xs " +
        sizes[size] +
        " " +
        (className ?? "")
      }
    >
      <div className="flex items-center px-4 py-2 bg-navy-100 border-b border-navy">
        <div>
          <h2
            id={titleId}
            className="text-sm uppercase tracking-wider text-navy font-bold font-mono"
          >
            {title}
          </h2>
          {subtitle && (
            <div className="text-xs text-navy/70 mt-1 normal-case tracking-normal font-normal">
              {subtitle}
            </div>
          )}
        </div>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close"
          className="ml-auto text-2xl squircle-md leading-none px-2 aspect-square py-1 pt-0.5 text-navy hover:bg-navy-200 transition-colors cursor-pointer"
        >
          <span aria-hidden="true">✕</span>
          <span className="sr-only">Close modal</span>
        </button>
      </div>
      {children}
    </dialog>
  );
}
