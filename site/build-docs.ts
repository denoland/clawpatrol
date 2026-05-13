// Static post-processing for `vite build`:
//   1. Prerender the landing page into dist/index.html with full SEO meta.
//   2. Render each doc/*.md into dist/docs/<slug>/index.html, plus a raw
//      .md copy at dist/docs/<slug>.md for LLM / MCP consumption.
//   3. Emit sitemap.xml, robots.txt, llms.txt, llms-full.txt.

import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";
import {
  loadDocs,
  prerenderLandingHtml,
  renderDocPage,
  SITE_ORIGIN,
} from "./docs-render.ts";

const docsDir = resolve(import.meta.dirname, "doc");
const distDir = resolve(import.meta.dirname, "dist");
const distDocsDir = join(distDir, "docs");

const docs = loadDocs(docsDir);

// 1) Prerender landing into dist/index.html ─────────────────────────
const viteIndex = readFileSync(join(distDir, "index.html"), "utf-8");
const prerendered = prerenderLandingHtml(viteIndex);
writeFileSync(join(distDir, "index.html"), prerendered);

// Extract <link> tags for CSS from vite's output so the doc pages
// pull in the same hashed bundle as the landing.
const cssLinks = viteIndex.match(/<link[^>]+stylesheet[^>]*>/g)?.join("\n") ??
  "";

// 2) Doc pages ──────────────────────────────────────────────────────
mkdirSync(distDocsDir, { recursive: true });
writeFileSync(
  join(distDocsDir, "index.html"),
  `<!doctype html><meta http-equiv="refresh"
    content="0;url=/docs/${docs[0].slug}/" />`,
);

for (const doc of docs) {
  const dir = join(distDocsDir, doc.slug);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, "index.html"), renderDocPage(doc, docs, cssLinks));
  writeFileSync(join(distDocsDir, `${doc.slug}.md`), doc.raw);
}

// 3) Sitemap, robots, llms.txt ──────────────────────────────────────
const sitemapUrls = [
  `${SITE_ORIGIN}/`,
  ...docs.map((d) => `${SITE_ORIGIN}/docs/${d.slug}/`),
];
const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${
  sitemapUrls
    .map((u) => `  <url><loc>${u}</loc></url>`)
    .join("\n")
}
</urlset>
`;
writeFileSync(join(distDir, "sitemap.xml"), sitemap);

const robots = `User-agent: *
Allow: /

Sitemap: ${SITE_ORIGIN}/sitemap.xml
`;
writeFileSync(join(distDir, "robots.txt"), robots);

// llmstxt.org format: index of pages an LLM can fetch. We point at the
// raw .md variants so models get clean prose without the page chrome.
const llmsTxt = `# Claw Patrol

> Open-source security proxy for AI agents. Sits between your agent
> and the network, injects credentials the agent never sees, and
> enforces HCL approval rules — with humans or LLM judges in the loop
> for risky actions.

## Docs

${
  docs
    .map(
      (d) =>
        `- [${d.title}](${SITE_ORIGIN}/docs/${d.slug}.md): ${d.description}`,
    )
    .join("\n")
}
`;
writeFileSync(join(distDir, "llms.txt"), llmsTxt);

const llmsFull = `# Claw Patrol — Full Documentation

> Concatenated source of every doc page. The canonical HTML versions
> live under ${SITE_ORIGIN}/docs/.

${
  docs
    .map(
      (d) =>
        `\n\n<!-- Source: ${SITE_ORIGIN}/docs/${d.slug}.md -->\n\n${d.raw}`,
    )
    .join("\n---\n")
}
`;
writeFileSync(join(distDir, "llms-full.txt"), llmsFull);

console.log(
  `Built landing + ${docs.length} doc pages, sitemap, robots, llms.txt`,
);
