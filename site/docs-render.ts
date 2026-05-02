// Shared docs rendering used by both vite dev and build.

import { readdirSync, readFileSync } from "node:fs";
import { resolve, join } from "node:path";
import { marked } from "marked";
import { markedHighlight } from "marked-highlight";
import hljs from "highlight.js";

marked.use(markedHighlight({
  langPrefix: "hljs language-",
  highlight(code, lang) {
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value;
    }
    return code;
  },
}));

function slugify(text: string): string {
  return text.toLowerCase()
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
    .filter(f => f.endsWith(".md"))
    .sort()
    .map(f => {
      const raw = readFileSync(join(docsDir, f), "utf-8");
      const slug = f.replace(/\.md$/, "");
      const h1 = raw.match(/^#\s+(.+)$/m);
      const title = h1 ? h1[1] : slug.replace(/-/g, " ");
      const html = marked.parse(raw, { async: false }) as string;
      return { slug, title, html };
    });
}

function sidebar(docs: Doc[], current: string): string {
  return docs.map(d => {
    const cls = d.slug === current
      ? "font-semibold text-accent"
      : "text-text-muted hover:text-text";
    return `<a href="/docs/${d.slug}/"
      class="${cls} block py-1 text-sm font-mono
        underline-offset-4 transition-colors"
    >${d.title}</a>`;
  }).join("\n");
}

const DOCS_STYLE = `
.docs-content h1,
.docs-content h2,
.docs-content h3 {
  position: relative;
}
.docs-content .anchor {
  text-decoration: none; opacity: 0;
  font-weight: 400; margin-right: 0.3em;
  color: var(--color-text-muted, #6b7770);
  transition: opacity 0.15s;
}
.docs-content h1:hover .anchor,
.docs-content h2:hover .anchor,
.docs-content h3:hover .anchor {
  opacity: 1;
}
.docs-content h1 {
  font-size: 2rem; font-weight: 700; margin-bottom: 1rem;
}
.docs-content h2 {
  font-size: 1.5rem; font-weight: 600;
  margin-top: 2.5rem; margin-bottom: 0.75rem;
}
.docs-content h3 {
  font-size: 1.17rem; font-weight: 600;
  margin-top: 2rem; margin-bottom: 0.5rem;
}
.docs-content p { margin-bottom: 1rem; line-height: 1.7; }
.docs-content ul, .docs-content ol {
  margin-bottom: 1rem; padding-left: 1.5rem;
}
.docs-content li { margin-bottom: 0.25rem; }
.docs-content pre {
  background: #1a1f1c; color: #b8c4be;
  padding: 1rem; border-radius: 0.5rem;
  overflow-x: auto; margin-bottom: 1rem; font-size: 0.875rem;
}
.docs-content code {
  font-family: 'JetBrains Mono', monospace; font-size: 0.9em;
}
.docs-content :not(pre) > code {
  background: #e8e3db; padding: 0.15em 0.4em;
  border-radius: 0.25rem;
}
.docs-content a {
  color: var(--color-console-dark, #2a342f);
  text-decoration: underline; text-underline-offset: 3px;
  font-weight: 500;
}
.docs-content blockquote {
  border-left: 3px solid #ccc; padding-left: 1rem;
  margin-bottom: 1rem; color: #6b7770;
}
.docs-content table {
  border-collapse: collapse; margin-bottom: 1rem; width: 100%;
}
.docs-content th, .docs-content td {
  border: 1px solid #d0cbc3;
  padding: 0.5rem 0.75rem; text-align: left;
}
.docs-content th { background: #e8e3db; font-weight: 600; }
.docs-content strong { font-weight: 600; }
`;

export function renderDocPage(
  doc: Doc,
  docs: Doc[],
  extraHead = "",
): string {
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
  ${extraHead}
  <style>${DOCS_STYLE}</style>
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
