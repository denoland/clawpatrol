import { defineConfig, type Plugin } from "vite";
import preact from "@preact/preset-vite";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "node:path";

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
          const path = req.url.replace(/\/$/, "") || "/docs";

          let doc;
          if (path === "/docs") {
            doc = docs[0];
          } else {
            const slug = path.replace("/docs/", "")
              .replace(/\/$/, "");
            doc = docs.find(
              (d: any) => d.slug === slug,
            );
          }
          if (!doc) return next();

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

export default defineConfig({
  plugins: [preact(), tailwindcss(), serveDocsInDev()],
});
