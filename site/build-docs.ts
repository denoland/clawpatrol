// Renders doc/*.md into dist/docs/<slug>/index.html, and also copies
// the raw markdown to dist/docs/<slug>.md.
// Run after `vite build`.

import { readFileSync, mkdirSync, writeFileSync }
  from "node:fs";
import { resolve, join } from "node:path";
import { loadDocs, renderDocPage } from "./docs-render.ts";

const docsDir = resolve(import.meta.dirname, "doc");
const distDir = resolve(import.meta.dirname, "dist", "docs");

const docs = loadDocs(docsDir);

// Extract <link> tags for CSS from vite's output
const shell = readFileSync(
  resolve(import.meta.dirname, "dist", "index.html"),
  "utf-8",
);
const cssLinks = shell.match(
  /<link[^>]+stylesheet[^>]*>/g,
)?.join("\n") ?? "";

// Index redirects to first doc
mkdirSync(distDir, { recursive: true });
writeFileSync(join(distDir, "index.html"),
  `<!doctype html><meta http-equiv="refresh"
    content="0;url=/docs/${docs[0].slug}/" />`);

for (const doc of docs) {
  const dir = join(distDir, doc.slug);
  mkdirSync(dir, { recursive: true });
  writeFileSync(
    join(dir, "index.html"),
    renderDocPage(doc, docs, cssLinks),
  );
  writeFileSync(join(distDir, `${doc.slug}.md`), doc.raw);
}

console.log(`Built ${docs.length} doc pages`);
