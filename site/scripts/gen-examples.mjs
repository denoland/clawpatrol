// Read site/examples/*.hcl and emit site/src/lib/examples.ts with one
// string export per file. The section files import from there.
// .hcl?raw worked under Vite but not under the tsx-based prerender step
// (Node has no idea how to load .hcl), so this pre-step bridges the gap.

import { readdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const examplesDir = join(here, "..", "examples");
const out = join(here, "..", "src", "lib", "examples.ts");

const files = (await readdir(examplesDir))
  .filter((f) => f.endsWith(".hcl"))
  .sort();

const lines = [
  "// AUTO-GENERATED from site/examples/*.hcl by scripts/gen-examples.mjs.",
  "// Do not edit by hand — change the .hcl file and regenerate.",
  "",
];

for (const f of files) {
  const ident = f.replace(/\.hcl$/, "").replace(/-/g, "_");
  const content = await readFile(join(examplesDir, f), "utf-8");
  lines.push(`export const ${ident} = ${JSON.stringify(content)};`);
}

await writeFile(out, lines.join("\n") + "\n");
console.error(`gen-examples: wrote ${out} (${files.length} file(s))`);
