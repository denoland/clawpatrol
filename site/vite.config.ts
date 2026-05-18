import { defineConfig, type Plugin } from "vite";
import preact from "@preact/preset-vite";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";
import { SITE_TITLE } from "./src/sections/HeroSection";

// Keep <title> in sync with HeroSection's H1. The constant lives in
// src/copy.ts so HeroSection imports it directly; this plugin rewrites
// index.html's <title> at dev-server time and at build time so static
// crawlers see the same string.
function injectTitle(): Plugin {
  return {
    name: "inject-title",
    transformIndexHtml(html) {
      return html.replace(
        /<title>.*?<\/title>/,
        `<title>${SITE_TITLE}</title>`,
      );
    },
  };
}

function serveDocsInDev(): Plugin {
  return {
    name: "serve-docs-in-dev",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith("/docs")) return next();
        try {
          const { loadDocs, renderDocPage } =
            await server.ssrLoadModule("/docs-render.ts");
          const docsDir = resolve(__dirname, "doc");
          const docs = loadDocs(docsDir);
          const rawPath = req.url.split("?")[0];
          const isMarkdown = rawPath.endsWith(".md");
          const path = (isMarkdown
            ? rawPath
            : rawPath.replace(/\/$/, "")) || "/docs";

          let doc;
          if (path === "/docs") {
            doc = docs[0];
          } else {
            const slug = path.replace("/docs/", "")
              .replace(/\.md$/, "")
              .replace(/\/$/, "");
            doc = docs.find(
              (d: any) => d.slug === slug,
            );
          }
          if (!doc) return next();

          if (isMarkdown) {
            res.setHeader("Content-Type", "text/markdown; charset=utf-8");
            res.end(doc.raw);
            return;
          }

          const css = `<script type="module"
            src="/@vite/client"></script>
            <script type="module">
              import "/src/index.css";
            </script>`;
          const html = renderDocPage(doc, docs, css);
          res.setHeader("Content-Type", "text/html");
          res.end(html);
        } catch (e) {
          console.error("Docs error:", e);
          next(e);
        }
      });
    },
  };
}

/**
 * Docs HTML is server-rendered via middleware, so Vite's normal HMR doesn't
 * apply. Watch the docs template, the components it embeds, and the markdown
 * sources; trigger a full browser reload when any of them change. (CSS still
 * hot-reloads through the normal Vite path since docs.css is now imported
 * from index.css.)
 */
function reloadDocsOnChange(): Plugin {
  const docsTemplate = resolve(__dirname, "docs-render.ts");
  const docDir = resolve(__dirname, "doc");
  const sharedComponents = [
    resolve(__dirname, "src/components/Header.tsx"),
    resolve(__dirname, "src/components/Footer.tsx"),
    resolve(__dirname, "src/components/Stripe.tsx"),
  ];

  return {
    name: "reload-docs-on-change",
    configureServer(server) {
      server.watcher.add(docDir);
      server.watcher.on("change", (file) => {
        const triggers =
          file === docsTemplate ||
          sharedComponents.includes(file) ||
          (file.startsWith(docDir) && file.endsWith(".md"));
        if (triggers) {
          server.ws.send({ type: "full-reload", path: "*" });
        }
      });
    },
  };
}

export default defineConfig({
  plugins: [
    preact(),
    tailwindcss(),
    injectTitle(),
    serveDocsInDev(),
    reloadDocsOnChange(),
  ],
});
