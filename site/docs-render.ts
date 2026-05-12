// Shared docs rendering used by both vite dev and build.

import hljs from "highlight.js";
import { Marked } from "marked";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { h } from "preact";
import { renderToString } from "preact-render-to-string";
import { Footer } from "./src/components/Footer";
import { Header } from "./src/components/Header";
import { Stripe } from "./src/components/Stripe";

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, "")
    .replace(/\s+/g, "-")
    .replace(/-+/g, "-")
    .trim();
}

// A fresh Marked instance scoped to this module. Avoids accumulating
// duplicate extensions onto the global singleton across Vite SSR module
// reloads, which previously caused old `markedHighlight` calls to keep
// running alongside our custom code renderer.
const marked = new Marked();

marked.use({
  renderer: {
    heading(
      this: { parser: { parseInline: (t: unknown[]) => string } },
      { text, tokens, depth }: {
        text: string;
        tokens: unknown[];
        depth: number;
      },
    ) {
      // `text` is the raw markdown source — backticks, asterisks, etc. are
      // still literal. Use the inline parser on `tokens` to get the HTML
      // (so `` `Foo` `` becomes <code>Foo</code> inside the heading).
      const id = slugify(text);
      const html = this.parser.parseInline(tokens);
      return `<h${depth} id="${id}">
        <a href="#${id}" class="anchor">#</a>
        ${html}
      </h${depth}>`;
    },
    // Render code fences ourselves so hljs runs exactly once and we emit
    // already-HTML output — no `marked-highlight` involved (its escape
    // behavior was double-rendering hljs spans as text in marked v18).
    // Untagged fences fall through to plain escaped text — no auto-detect.
    code({ text, lang }: { text: string; lang?: string }) {
      const requested = (lang || "").trim().toLowerCase();
      if (requested && hljs.getLanguage(requested)) {
        const html = hljs.highlight(text, { language: requested }).value;
        return `<pre><code class="hljs language-${requested}">${html}</code></pre>\n`;
      }
      return `<pre><code>${escapeHtml(text)}</code></pre>\n`;
    },
    // Wrap tables in a horizontally-scrolling div so wide tables don't
    // blow out the page width on narrow viewports.
    table(
      this: { parser: { parseInline: (t: unknown[]) => string } },
      { header, align, rows }: {
        header: Array<{ tokens: unknown[] }>;
        align: Array<"left" | "right" | "center" | null>;
        rows: Array<Array<{ tokens: unknown[] }>>;
      },
    ) {
      const alignAttr = (i: number) =>
        align[i] ? ` align="${align[i]}"` : "";
      const thead = `<thead><tr>${
        header
          .map(
            (cell, i) =>
              `<th${alignAttr(i)}>${
                this.parser.parseInline(cell.tokens)
              }</th>`,
          )
          .join("")
      }</tr></thead>`;
      const tbody = `<tbody>${
        rows
          .map(
            (row) =>
              `<tr>${
                row
                  .map(
                    (cell, i) =>
                      `<td${alignAttr(i)}>${
                        this.parser.parseInline(cell.tokens)
                      }</td>`,
                  )
                  .join("")
              }</tr>`,
          )
          .join("")
      }</tbody>`;
      return `<div class="table-wrap"><table>${thead}${tbody}</table></div>\n`;
    },
  },
});

export interface Doc {
  slug: string;
  title: string;
  html: string;
  raw: string;
}

export function loadDocs(docsDir: string): Doc[] {
  const toc = JSON.parse(
    readFileSync(join(docsDir, "toc.json"), "utf-8"),
  ) as string[];
  return toc.map((slug) => {
    const raw = readFileSync(join(docsDir, `${slug}.md`), "utf-8");
    const h1 = raw.match(/^#\s+(.+)$/m);
    const title = h1 ? h1[1] : slug.replace(/-/g, " ");
    const html = marked.parse(raw, { async: false }) as string;
    return { slug, title, html, raw };
  });
}

function sidebar(docs: Doc[], current: string): string {
  return docs
    .map((d) => {
      const cls =
        d.slug === current
          ? "font-semibold text-rust"
          : "text-text-muted hover:text-text";
      return `<a href="/docs/${d.slug}/"
      class="${cls} block py-1 text-sm font-mono
        underline-offset-4 transition-colors"
    >${d.title}</a>`;
    })
    .join("\n");
}

/** Render a Preact component to an HTML string (server-side). */
function renderHtml(
  component: Parameters<typeof h>[0],
  props: Record<string, unknown> = {},
): string {
  return renderToString(h(component, props));
}

export function renderDocPage(doc: Doc, docs: Doc[], extraHead = ""): string {
  const headerHtml = renderHtml(Header);
  const topStripeHtml = renderHtml(Stripe, { color1: "var(--color-navy-100)" });
  const bottomStripeHtml = renderHtml(Stripe, { color1: "var(--color-navy)" });
  const footerHtml = renderHtml(Footer);

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport"
    content="width=device-width, initial-scale=1.0" />
  <title>${doc.title} — Claw Patrol Docs</title>
  ${extraHead}
</head>
<body class="min-h-screen bg-canvas text-text font-sans">
  ${headerHtml}
  ${topStripeHtml}
  <div class="max-w-6xl mx-auto px-8 py-20
    flex flex-col md:flex-row gap-10">
    <aside class="md:w-56 shrink-0 md:sticky md:top-[calc(var(--header-height)+1rem)]
      md:self-start">
      ${sidebar(docs, doc.slug)}
    </aside>
    <main class="docs-content min-w-0 flex-1">
      ${doc.html}
    </main>
  </div>
  ${bottomStripeHtml}
  ${footerHtml}
</body>
</html>`;
}
