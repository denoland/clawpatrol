import { useEffect, useRef, type ReactNode } from "react";

// Thin wrapper around the native <dialog> element. Opening with
// `.showModal()` gives us role="dialog" + aria-modal="true",
// trapped focus, ESC-to-close, body scroll lock, and a real
// backdrop — for free, no library.
//
// Caller responsibility:
//  - pass `onClose` to unmount the modal when the dialog closes
//    (fires on ESC, .close(), or click outside the inner box).
//  - pass `labelledBy` matching an id on the header title for
//    screen readers to announce the modal name.
//  - bring the visual chrome (bg, border, padding, sizing) on the
//    child element — this wrapper resets the UA <dialog> styles to
//    transparent so it doesn't paint twice.
export function Modal({
  onClose,
  labelledBy,
  className,
  children,
}: {
  onClose: () => void;
  labelledBy?: string;
  className?: string;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);

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
      aria-labelledby={labelledBy}
      onClose={onClose}
      onClick={(e) => {
        // The dialog element itself is only the event target when the
        // user clicks the ::backdrop. Clicks on inner content land on
        // a child, so this only fires for "outside the box" clicks.
        if (e.target === ref.current) ref.current?.close();
      }}
      className={`m-auto p-0 bg-transparent text-text backdrop:bg-navy/40 ${className ?? ""}`}
    >
      {children}
    </dialog>
  );
}
