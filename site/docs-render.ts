// Shared docs rendering used by both vite dev and build.

import hljs from "highlight.js";
import { marked } from "marked";
import { markedHighlight } from "marked-highlight";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

marked.use(
  markedHighlight({
    langPrefix: "hljs language-",
    highlight(code, lang) {
      if (lang && hljs.getLanguage(lang)) {
        return hljs.highlight(code, { language: lang }).value;
      }
      return code;
    },
  }),
);

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .trim();
}

marked.use({
  renderer: {
    heading({ text, depth }: { text: string; depth: number }) {
      const id = slugify(text);
      return `<h${depth} id="${id}">
        <a href="#${id}" class="anchor">#</a>
        ${text}
      </h${depth}>`;
    },
  },
});

export interface Doc {
  slug: string;
  title: string;
  html: string;
}

export function loadDocs(docsDir: string): Doc[] {
  return readdirSync(docsDir)
    .filter((f) => f.endsWith(".md"))
    .sort()
    .map((f) => {
      const raw = readFileSync(join(docsDir, f), "utf-8");
      const slug = f.replace(/\.md$/, "");
      const h1 = raw.match(/^#\s+(.+)$/m);
      const title = h1 ? h1[1] : slug.replace(/-/g, " ");
      const html = marked.parse(raw, { async: false }) as string;
      return { slug, title, html };
    });
}

function sidebar(docs: Doc[], current: string): string {
  return docs
    .map((d) => {
      const cls =
        d.slug === current
          ? "font-semibold text-accent"
          : "text-text-muted hover:text-text";
      return `<a href="/docs/${d.slug}/"
      class="${cls} block py-1 text-sm font-mono
        underline-offset-4 transition-colors"
    >${d.title}</a>`;
    })
    .join("\n");
}

export function renderDocPage(doc: Doc, docs: Doc[], extraHead = ""): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport"
    content="width=device-width, initial-scale=1.0" />
  <title>${doc.title} — Claw Patrol Docs</title>
  <link rel="preload" as="font" type="font/woff2"
    href="/fonts/overpass-latin.woff2" crossorigin />
  <link rel="preload" as="font" type="font/woff2"
    href="/fonts/jetbrains-mono-latin.woff2" crossorigin />
  <link rel="stylesheet" href="/docs.css" />
  ${extraHead}
</head>
<body class="bg-cream-light text-text min-h-screen">
  <nav class="max-w-6xl mx-auto px-8 py-8 flex items-center
    justify-between">
    <a href="/" style="font-family:'Overpass',sans-serif;
      color:#2a342f; font-size:1.125rem; letter-spacing:0.25em;
      text-transform:uppercase; font-weight:600;
      text-decoration:none;">Claw Patrol</a>
    <a href="/docs/"
      class="font-mono text-sm text-text-muted
        underline underline-offset-4">Docs</a>
  </nav>
  <div class="max-w-6xl mx-auto px-8 pb-20
    flex flex-col md:flex-row gap-10">
    <aside class="md:w-56 shrink-0 md:sticky md:top-8
      md:self-start">
      ${sidebar(docs, doc.slug)}
    </aside>
    <main class="docs-content min-w-0 flex-1">
      ${doc.html}
    </main>
  </div>
</body>
</html>`;
}
