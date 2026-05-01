import { defineConfig, type Plugin } from "vite";
import preact from "@preact/preset-vite";
import tailwindcss from "@tailwindcss/vite";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

// The landing page is served at "/" in production, so its images use
// root-absolute paths like /screenshots/... and /icons/....  But Vite's
// base "/s/" causes public/ assets to be served under /s/ during dev.
// This plugin adds a fallback that serves public/ at the root too.
function servePublicAtRoot(): Plugin {
  return {
    name: "serve-public-at-root",
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        if (req.url && !req.url.startsWith("/s/")) {
          const filePath = join(__dirname, "public", req.url);
          if (existsSync(filePath)) {
            req.url = "/s" + req.url;
          }
        }
        next();
      });
    },
  };
}

// During dev, serve /docs/ routes by SSR-rendering the actual Preact
// components so the layout stays in sync with the homepage automatically.
function serveDocsInDev(): Plugin {
  return {
    name: "serve-docs-in-dev",
    configureServer(server) {
      server.middlewares.use(async (req, res, next) => {
        if (!req.url || !req.url.startsWith("/docs")) return next();

        try {
          const { readdirSync } = await import("node:fs");
          const { marked } = await server.ssrLoadModule(
            "/src/docs/markdown.ts",
          ) as { marked: { parse(src: string, opts?: unknown): string } };
          const { default: renderToString } = await server.ssrLoadModule(
            "preact-render-to-string",
          ) as { default: (vnode: any) => string };
          const { h } = await server.ssrLoadModule("preact") as {
            h: typeof import("preact").h;
          };
          const { DocsPage } = await server.ssrLoadModule(
            "/src/docs/DocsPage.tsx",
          ) as { DocsPage: any };

          const docsDir = resolve(__dirname, "..", "clawpatrol", "doc");
          const files = readdirSync(docsDir)
            .filter((f: string) => f.endsWith(".md"))
            .sort();

          function parseDoc(filename: string) {
            const raw = readFileSync(resolve(docsDir, filename), "utf-8");
            const slug = filename.replace(/\.md$/, "");
            const h1Match = raw.match(/^#\s+(.+)$/m);
            const title = h1Match ? h1Match[1] : slug.replace(/-/g, " ");
            const html = marked.parse(raw, { async: false }) as string;
            return { slug, title, html };
          }

          const docs = files.map(parseDoc);
          const docEntries = docs.map(({ slug, title }) => ({ slug, title }));
          const urlPath = req.url.replace(/\/$/, "") || "/docs";

          let body: string;
          let doc;

          if (urlPath === "/docs") {
            // Land on the first doc (introduction)
            doc = docs[0];
          } else {
            const slug = urlPath.replace("/docs/", "").replace(/\/$/, "");
            doc = docs.find((d) => d.slug === slug);
          }

          if (!doc) return next();
          body = renderToString(
            h(DocsPage, {
              title: doc.title,
              html: doc.html,
              docs: docEntries,
              currentSlug: doc.slug,
            }),
          );

          const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Claw Patrol Docs</title>
  <link rel="preload" as="font" type="font/woff2" href="/fonts/overpass-latin.woff2" crossorigin />
  <link rel="preload" as="font" type="font/woff2" href="/fonts/jetbrains-mono-latin.woff2" crossorigin />
  <link rel="stylesheet" href="/docs.css" />
  <script type="module" src="/s/@vite/client"></script>
  <script type="module">import "/s/src/index.css";</script>
</head>
<body>
  <div id="root">${body}</div>
</body>
</html>`;

          res.setHeader("Content-Type", "text/html");
          res.end(html);
        } catch (e) {
          console.error("Docs SSR error:", e);
          next(e);
        }
      });
    },
  };
}

export default defineConfig({
  plugins: [preact(), tailwindcss(), servePublicAtRoot(), serveDocsInDev()],
  base: "/s/",
  build: {
    assetsDir: "a",
    rollupOptions: {
      input: {
        main: resolve(__dirname, "index.html"),
        chart: resolve(__dirname, "src/chart.ts"),
      },
    },
  },
  server: {
    proxy: {
      "/api": "http://localhost:8080",
      "/auth": {
        target: "http://localhost:8080",
        changeOrigin: false,
      },
    },
  },
});
