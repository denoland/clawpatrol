/// <reference lib="dom" />

// headersToJSON serialises a header map as a pretty-printed JSON
// object string. Single-value entries serialise as plain strings;
// array entries serialise as JSON arrays of strings, preserving
// multi-value headers verbatim. Key order is the input's insertion
// order — matches the dashboard's on-screen rendering.
export function headersToJSON(headers: Record<string, string | string[]>): string {
  const obj: Record<string, string | string[]> = {};
  for (const [k, v] of Object.entries(headers)) {
    if (Array.isArray(v)) {
      obj[k] = v.length === 1 ? v[0] : v.slice();
    } else {
      obj[k] = v;
    }
  }
  return JSON.stringify(obj, null, 2);
}

// copyText writes text to the system clipboard. Returns true on
// success, false otherwise (denied permission, or both the async and
// legacy paths unavailable). Callers use the return value to decide
// whether to flash a confirmation indicator.
//
// The async Clipboard API only exists in a secure context (https or
// localhost). The dashboard is routinely reached over plain http on a
// tailnet hostname, where navigator.clipboard is undefined — so we
// fall through to the legacy execCommand path rather than silently
// failing.
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Focus/permission/policy rejection — fall through to the
      // legacy path, which works in more situations than its
      // reputation suggests.
    }
  }
  return legacyCopy(text);
}

// legacyCopy copies via a temporary <textarea> + document.execCommand.
// Deprecated but still implemented everywhere and the only option in a
// non-secure context.
function legacyCopy(text: string): boolean {
  if (typeof document === "undefined") return false;
  const ta = document.createElement("textarea");
  ta.value = text;
  // readonly stops the mobile keyboard from popping; selection still
  // works. Off-screen + transparent so it never flashes visibly.
  ta.setAttribute("readonly", "");
  ta.style.position = "fixed";
  ta.style.top = "0";
  ta.style.left = "0";
  ta.style.opacity = "0";
  // A modal <dialog> opened via showModal() puts everything outside it
  // in the inert, top-layer-blocked subtree. A textarea appended to
  // <body> would be inert — unselectable — so execCommand copies an
  // empty selection. Mount inside the topmost open dialog when there is
  // one so the node is live and selectable; otherwise <body> is fine.
  const dialogs = document.querySelectorAll<HTMLDialogElement>("dialog[open]");
  const host = dialogs.length ? dialogs[dialogs.length - 1] : document.body;
  const prevFocus = document.activeElement as HTMLElement | null;
  host.appendChild(ta);
  try {
    ta.focus();
    ta.select();
    ta.setSelectionRange(0, ta.value.length);
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    ta.remove();
    // Restore focus to whatever the user had (the copy button), so the
    // transient textarea doesn't steal it.
    prevFocus?.focus?.();
  }
}
