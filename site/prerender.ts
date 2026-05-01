// Build-time prerender script.
// Renders the Landing component to static HTML
// and injects it into the Vite-built index.html.
// Also generates static docs pages from clawpatrol/doc/*.md.

import {
  readFileSync,
  writeFileSync,
  readdirSync,
  mkdirSync,
  existsSync,
  statSync,
} from "node:fs";
import { resolve, dirname, basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import renderToString from "preact-render-to-string";
import { h } from "preact";
import { marked } from "./src/docs/markdown";
import { Landing } from "./src/Landing";
import { Download } from "./src/Download";
import { type DocEntry } from "./src/docs/DocsIndex";
import { DocsPage } from "./src/docs/DocsPage";

const __dirname = dirname(fileURLToPath(import.meta.url));
const dist = resolve(__dirname, "..", "dist");
const htmlPath = resolve(dist, "index.html");

// --- Landing page ---

let html = readFileSync(htmlPath, "utf-8");
// Snapshot the empty-root shell before Landing is injected, so docs pages
// can reuse it without inheriting any Landing markup.
const shellHtml = html;
const body = renderToString(h(Landing, null));
html = html.replace(
  '<div id="root"></div>',
  `<div id="root">${body}</div>`,
);

// Replace the main app script (not needed after SSR) with
// the chart script + inline demo data.
const chartAsset = readdirSync(resolve(dist, "a"))
  .find((f) => f.startsWith("chart") && f.endsWith(".js"));
const demoData = readFileSync(
  resolve(__dirname, "..", "public", "demo-analytics.json"),
  "utf-8",
);
html = html.replace(
  /<script type="module"[^>]*><\/script>\n?/,
  chartAsset
    ? `<script>window.__DEMO_DATA__=${demoData}</script>\n` +
      `<script type="module" src="/s/a/${chartAsset}"></script>\n`
    : "",
);

writeFileSync(htmlPath, html);
console.log("Prerendered dist/index.html");

// --- Download page ---
// Reuses the Vite-built shell (no Landing markup, no chart bundle) so the
// page only ships the static download UI.

function makeShellHtml(title: string, bodyHtml: string): string {
  return shellHtml
    .replace(/<title>[^<]*<\/title>/, `<title>${title}</title>`)
    .replace(
      /<div id="root">[\s\S]*?<\/div>/,
      `<div id="root">${bodyHtml}</div>`,
    )
    .replace(/<script type="module"[^>]*><\/script>\n?/, "");
}

const downloadDir = resolve(dist, "download");
mkdirSync(downloadDir, { recursive: true });
const downloadBody = renderToString(h(Download, null));
writeFileSync(
  resolve(downloadDir, "index.html"),
  makeShellHtml("Download — Claw Patrol", downloadBody),
);
console.log("Prerendered dist/download/index.html");

// --- Docs pages ---

// When esbuild bundles this, __dirname is site/dist-prerender.
// The clawpatrol submodule is at the repo root.
const repoRoot = resolve(__dirname, "..", "..");
const docsDir = resolve(repoRoot, "clawpatrol", "doc");
const mdFiles = readdirSync(docsDir)
  .filter((f) => f.endsWith(".md"))
  .sort();

function makeDocHtml(title: string, bodyHtml: string): string {
  return shellHtml
    .replace(
      /<title>[^<]*<\/title>/,
      `<title>${title} — Claw Patrol Docs</title>`,
    )
    .replace(
      /<\/head>/,
      `  <link rel="stylesheet" href="/docs.css" />\n</head>`,
    )
    .replace(
      /<div id="root">[\s\S]*?<\/div>/,
      `<div id="root">${bodyHtml}</div>`,
    );
}

// Derive a clean slug and title from each file.
function parseDoc(filename: string): { slug: string; title: string; html: string } {
  const raw = readFileSync(resolve(docsDir, filename), "utf-8");

  // Slug: strip leading numbers and dashes, drop extension
  const slug = basename(filename, ".md");

  // Title: use the first H1 if present, otherwise derive from slug
  const h1Match = raw.match(/^#\s+(.+)$/m);
  const title = h1Match ? h1Match[1] : slug.replace(/-/g, " ");

  const rendered = marked.parse(raw, { async: false }) as string;
  return { slug, title, html: rendered };
}

const docs: (DocEntry & { html: string })[] = mdFiles.map((f) => parseDoc(f));
const docEntries: DocEntry[] = docs.map(({ slug, title }) => ({ slug, title }));

const docsDistDir = resolve(dist, "docs");
mkdirSync(docsDistDir, { recursive: true });

// /docs/ lands on the first doc (introduction)
const introBody = renderToString(
  h(DocsPage, {
    title: docs[0].title,
    html: docs[0].html,
    docs: docEntries,
    currentSlug: docs[0].slug,
  }),
);
writeFileSync(
  resolve(docsDistDir, "index.html"),
  makeDocHtml(docs[0].title, introBody),
);
console.log("Prerendered dist/docs/index.html (introduction)");

// Write individual doc pages
for (const doc of docs) {
  const pageDir = resolve(docsDistDir, doc.slug);
  mkdirSync(pageDir, { recursive: true });

  const pageBody = renderToString(
    h(DocsPage, {
      title: doc.title,
      html: doc.html,
      docs: docEntries,
      currentSlug: doc.slug,
    }),
  );
  writeFileSync(
    resolve(pageDir, "index.html"),
    makeDocHtml(doc.title, pageBody),
  );
  console.log(`Prerendered dist/docs/${doc.slug}/index.html`);
}

// --- Internal link check ---
// Walk built HTML and verify `/docs/*` links resolve to a real page.
// We scope to `/docs/*` because that's the namespace the static build
// owns — other paths (`/s/...` assets, `/auth/login`, etc.) are served
// by the backend/reverse proxy, not by files in `dist/`. Fails the
// build (throws) if anything is broken.

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (entry.endsWith(".html")) out.push(full);
  }
  return out;
}

function docsHrefResolves(href: string): boolean {
  const path = href.replace(/[?#].*$/, "").replace(/^\/+/, "");
  return existsSync(resolve(dist, path, "index.html"));
}

const broken: { file: string; href: string }[] = [];
for (const file of walk(dist)) {
  const text = readFileSync(file, "utf-8");
  const rel = file.slice(dist.length + 1);
  for (const m of text.matchAll(/href="(\/docs\/[^"]+)"/g)) {
    const href = m[1];
    if (!docsHrefResolves(href)) broken.push({ file: rel, href });
  }
}

if (broken.length) {
  console.error(`\n${broken.length} broken docs link(s):`);
  for (const b of broken) console.error(`  ${b.file} -> ${b.href}`);
  throw new Error("Link check failed");
}
console.log("Link check: all /docs/* links resolve.");
