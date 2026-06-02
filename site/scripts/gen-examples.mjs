// Read examples/*.hcl and emit site/src/lib/examples.ts with one
// string export per landing-page snippet. The section files import
// from there.
// .hcl?raw worked under Vite but not under the tsx-based prerender step
// (Node has no idea how to load .hcl), so this pre-step bridges the gap.
//
// Only files containing the "# ===== harness =====" marker are
// emitted — that's how a landing-page snippet is distinguished from
// standalone examples (e.g. gateway.example.hcl) that live alongside
// them in the same directory.

import { readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const examplesDir = join(here, "..", "..", "examples");
const out = join(here, "..", "src", "lib", "examples.ts");

const all = (await readdir(examplesDir)).filter((f) => f.endsWith(".hcl")).sort();
const files = [];
const contents = new Map();
for (const f of all) {
  const content = await readFile(join(examplesDir, f), "utf-8");
  if (!content.includes("# ===== harness =====")) continue;
  files.push(f);
  contents.set(f, content);
}

const lines = [
  "// AUTO-GENERATED from examples/*.hcl by site/scripts/gen-examples.mjs.",
  "// Do not edit by hand — change the .hcl file and regenerate.",
  "",
];

for (const f of files) {
  const ident = f.replace(/\.hcl$/, "").replace(/-/g, "_");
  lines.push(`export const ${ident} = ${JSON.stringify(contents.get(f))};`);
}

await writeFile(out, lines.join("\n") + "\n");
console.error(`gen-examples: wrote ${out} (${files.length} file(s))`);
