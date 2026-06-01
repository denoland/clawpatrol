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
// success, false otherwise (insecure context, denied permission,
// or no Clipboard API). Callers use the return value to decide
// whether to flash a confirmation indicator.
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator === "undefined" || !navigator.clipboard) return false;
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}
