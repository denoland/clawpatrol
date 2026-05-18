// Strip the harness portion from an HCL example file.
// Files in site/examples/ contain a display snippet followed by a
// "# ===== harness =====" marker and config scaffolding that makes
// the file pass `clawpatrol validate`. Landing page sections render
// only what's above the marker.

export function snippet(source: string): string {
  const i = source.indexOf("# ===== harness =====");
  return (i === -1 ? source : source.slice(0, i)).trim();
}
