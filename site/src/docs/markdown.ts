import hljs from "highlight.js";
import { Marked } from "marked";
import { markedHighlight } from "marked-highlight";

const escapeAttr = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/"/g, "&quot;");

export const marked = new Marked(
  markedHighlight({
    langPrefix: "hljs language-",
    highlight(code, lang) {
      const language = lang && hljs.getLanguage(lang) ? lang : "plaintext";
      return hljs.highlight(code, { language }).value;
    },
  }),
  {
    hooks: {
      // Wrap every rendered table in a scroll container so wide
      // tables (e.g. Environment Variables) don't break the page
      // layout on narrow viewports.
      postprocess(html) {
        return html
          .replaceAll(
            "<table>",
            '<div class="table-wrap"><div class="table-wrap__inner"><table>',
          )
          .replaceAll("</table>", "</table></div></div>");
      },
    },
    renderer: {
      // Rewrite relative sibling links (`02-getting-started`,
      // `06-gateway.md`) to the site's `/docs/<slug>/` URL. Absolute,
      // protocol, and fragment-only hrefs pass through untouched so
      // the same .md files still render correctly on GitHub.
      link({ href, title, tokens }) {
        const isAbsolute = /^([a-z][a-z0-9+.-]*:|\/|#)/i.test(href);
        const resolved = isAbsolute
          ? href
          : `/docs/${href.replace(/\.md$/i, "")}/`;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const text = (this as any).parser.parseInline(tokens);
        const titleAttr = title ? ` title="${escapeAttr(title)}"` : "";
        return `<a href="${escapeAttr(resolved)}"${titleAttr}>${text}</a>`;
      },
    },
  },
);
