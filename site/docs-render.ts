// Shared rendering used by both vite dev and build for the docs pages,
// and by build-docs.ts to prerender the landing page.

import hljs, { type HLJSApi, type LanguageFn } from "highlight.js";
import { Marked } from "marked";

// highlight.js doesn't ship an HCL grammar, so docs that use `hcl`
// fences fall back to plain text. Register a minimal one — enough
// to colourise the operator-facing examples in skill.md and friends.
const hclLang: LanguageFn = (h: HLJSApi) => ({
  name: "HCL",
  aliases: ["terraform", "tf"],
  case_insensitive: false,
  keywords: {
    keyword:
      "approver credential endpoint policy profile rule tunnel " +
      "device defaults",
    literal: "true false null",
    built_in: "var local module data resource",
  },
  contains: [
    h.HASH_COMMENT_MODE,
    h.C_LINE_COMMENT_MODE,
    h.C_BLOCK_COMMENT_MODE,
    h.QUOTE_STRING_MODE,
    h.NUMBER_MODE,
    {
      // Heredoc: <<EOT … EOT  or  <<-EOT … EOT
      className: "string",
      begin: /<<-?\s*([A-Za-z_]\w*)/,
      end: /^\s*\w+$/,
    },
    {
      // Block label string (after a known keyword + space).
      className: "type",
      begin: /\b[a-z_][a-z0-9_]*\b(?=\s+"[^"]+"\s*"[^"]+"\s*\{)/,
    },
  ],
});
hljs.registerLanguage("hcl", hclLang);
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { h } from "preact";
import { renderToString } from "preact-render-to-string";
import { Footer } from "./src/components/Footer";
import { Header } from "./src/components/Header";
import { Landing } from "./src/Landing";
import { Stripe } from "./src/components/Stripe";
import { SITE_TITLE } from "./src/sections/HeroSection";

export const SITE_ORIGIN = "https://clawpatrol.dev";
export const DEFAULT_OG_IMAGE = `${SITE_ORIGIN}/clawpatrol.png`;

const LANDING_DESCRIPTION =
  "Claw Patrol is an open-source security proxy for AI agents. " +
  "It sits between your agent and the network, injects credentials " +
  "the agent never sees, and enforces HCL approval rules — with " +
  "humans or LLM judges in the loop for risky actions.";

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

// Pull the first meaningful paragraph out of a markdown source, strip
// the most common inline syntax, and clip to ~200 chars at a word
// boundary. Used as the page's <meta description>.
function extractDescription(raw: string, fallback: string): string {
  const lines = raw.split("\n");
  let inFence = false;
  const paragraphs: string[] = [];
  let current: string[] = [];
  const flush = () => {
    if (current.length) paragraphs.push(current.join(" ").trim());
    current = [];
  };
  for (const line of lines) {
    if (line.startsWith("```")) {
      inFence = !inFence;
      flush();
      continue;
    }
    if (inFence) continue;
    if (line.trim() === "") {
      flush();
      continue;
    }
    if (line.startsWith("#") || line.startsWith(">")) continue;
    current.push(line.trim());
  }
  flush();
  const first = paragraphs.find((p) => p.length > 0);
  if (!first) return fallback;
  let plain = first
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");
  if (plain.length > 200) {
    plain = plain.slice(0, 197).replace(/\s+\S*$/, "") + "…";
  }
  return plain;
}

interface PageMeta {
  title: string;
  description: string;
  url: string;
  type?: "website" | "article";
  ogImage?: string;
  jsonLd?: unknown;
  extraLinks?: string;
}

function renderMetaTags(m: PageMeta): string {
  const desc = escapeHtml(m.description);
  const title = escapeHtml(m.title);
  const img = m.ogImage ?? DEFAULT_OG_IMAGE;
  const type = m.type ?? "website";
  const jsonLd = m.jsonLd
    ? `<script type="application/ld+json">${
      JSON.stringify(m.jsonLd).replace(/</g, "\\u003c")
    }</script>`
    : "";
  return `
  <meta name="description" content="${desc}" />
  <link rel="canonical" href="${m.url}" />
  <link rel="icon" type="image/svg+xml" href="/claw-patrol-icon.svg" />
  <meta property="og:title" content="${title}" />
  <meta property="og:description" content="${desc}" />
  <meta property="og:url" content="${m.url}" />
  <meta property="og:type" content="${type}" />
  <meta property="og:image" content="${img}" />
  <meta property="og:site_name" content="Claw Patrol" />
  <meta name="twitter:card" content="summary_large_image" />
  <meta name="twitter:title" content="${title}" />
  <meta name="twitter:description" content="${desc}" />
  <meta name="twitter:image" content="${img}" />
  ${m.extraLinks ?? ""}
  ${jsonLd}
`;
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
      const label = escapeHtml(`Permalink to ${text}`);
      return `<h${depth} id="${id}">
        <a href="#${id}" class="anchor" aria-label="${label}">#</a>
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
  description: string;
}

// Strip a leading `---\n...\n---\n` YAML frontmatter block off a
// markdown source. Only the simple SKILL.md shape is supported:
// `key: value` lines, one per key, no nested structures. That's the
// shape Anthropic's Agent Skills spec mandates, which is all we need
// here — pulling in a real YAML parser for two fields would be
// overkill.
function parseFrontmatter(
  raw: string,
): { meta: Record<string, string>; body: string } {
  if (!raw.startsWith("---\n")) return { meta: {}, body: raw };
  const end = raw.indexOf("\n---\n", 4);
  if (end < 0) return { meta: {}, body: raw };
  const block = raw.slice(4, end);
  const body = raw.slice(end + 5);
  const meta: Record<string, string> = {};
  for (const line of block.split("\n")) {
    const m = line.match(/^([a-zA-Z_][\w-]*):\s*(.+)$/);
    if (m) meta[m[1]] = m[2].trim();
  }
  return { meta, body };
}

export function loadDocs(docsDir: string): Doc[] {
  const toc = JSON.parse(
    readFileSync(join(docsDir, "toc.json"), "utf-8"),
  ) as string[];
  return toc.map((slug) => {
    const raw = readFileSync(join(docsDir, `${slug}.md`), "utf-8");
    const { meta, body } = parseFrontmatter(raw);
    const h1 = body.match(/^#\s+(.+)$/m);
    const title = meta.title ?? (h1 ? h1[1] : slug.replace(/-/g, " "));
    const html = marked.parse(body, { async: false }) as string;
    const description = meta.description ?? extractDescription(
      body,
      `${title} — Claw Patrol documentation.`,
    );
    return { slug, title, html, raw, description };
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

export function renderDocPage(
  doc: Doc,
  docs: Doc[],
  extraHead = "",
): string {
  const headerHtml = renderHtml(Header);
  const topStripeHtml = renderHtml(Stripe, { color1: "var(--color-navy-100)" });
  const bottomStripeHtml = renderHtml(Stripe, { color1: "var(--color-navy)" });
  const footerHtml = renderHtml(Footer);

  const url = `${SITE_ORIGIN}/docs/${doc.slug}/`;
  const mdUrl = `${SITE_ORIGIN}/docs/${doc.slug}.md`;
  const meta = renderMetaTags({
    title: `${doc.title} — Claw Patrol Docs`,
    description: doc.description,
    url,
    type: "article",
    extraLinks:
      `<link rel="alternate" type="text/markdown" href="${mdUrl}" />`,
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "TechArticle",
      headline: doc.title,
      description: doc.description,
      url,
      mainEntityOfPage: url,
      isPartOf: {
        "@type": "WebSite",
        name: "Claw Patrol",
        url: SITE_ORIGIN,
      },
    },
  });

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport"
    content="width=device-width, initial-scale=1.0" />
  <title>${escapeHtml(doc.title)} — Claw Patrol Docs</title>
  ${meta}
  ${extraHead}
</head>
<body class="min-h-screen bg-canvas text-text font-sans">
  ${headerHtml}
  ${topStripeHtml}
  <div class="max-w-6xl mx-auto px-8 py-20
    flex flex-col md:flex-row gap-10">
    <aside class="md:w-56 shrink-0 md:sticky md:top-[calc(var(--header-height)+1rem)]
      md:self-start">
      <nav aria-label="Documentation">
        ${sidebar(docs, doc.slug)}
      </nav>
    </aside>
    <main class="docs-content min-w-0 flex-1">
      <p class="text-xs font-mono text-text-muted mb-6 text-right">
        <a href="/docs/${doc.slug}.md"
          class="underline underline-offset-4 hover:text-rust"
        >View as markdown</a>
      </p>
      ${doc.html}
    </main>
  </div>
  ${bottomStripeHtml}
  ${footerHtml}
</body>
</html>`;
}

/**
 * Take the index.html that vite emits (which contains only an empty
 * `<div id="root"></div>`) and rewrite it with the landing page
 * prerendered into the root div, plus full SEO metadata. The client
 * bundle that vite injected is left untouched and will hydrate the
 * prerendered tree on load.
 */
export function prerenderLandingHtml(viteIndexHtml: string): string {
  const landingHtml = renderHtml(Landing);
  const meta = renderMetaTags({
    title: SITE_TITLE,
    description: LANDING_DESCRIPTION,
    url: `${SITE_ORIGIN}/`,
    type: "website",
    jsonLd: {
      "@context": "https://schema.org",
      "@type": "SoftwareApplication",
      name: "Claw Patrol",
      description: LANDING_DESCRIPTION,
      url: SITE_ORIGIN,
      applicationCategory: "DeveloperApplication",
      operatingSystem: "macOS, Linux",
      offers: {
        "@type": "Offer",
        price: "0",
        priceCurrency: "USD",
      },
      license: "https://opensource.org/licenses/MIT",
      author: {
        "@type": "Organization",
        name: "Deno",
        url: "https://deno.com",
      },
    },
  });

  let out = viteIndexHtml;
  // Inject metadata immediately before </head>. Vite already wrote
  // the title and font preload tags, so we only add what's missing.
  out = out.replace("</head>", `${meta}\n</head>`);
  // Replace the empty root div with the SSR'd Landing tree.
  out = out.replace(
    /<div id="root">\s*<\/div>/,
    `<div id="root">${landingHtml}</div>`,
  );
  return out;
}
