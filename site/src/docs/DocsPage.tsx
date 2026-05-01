import { Layout } from "../Layout";
import type { DocEntry } from "./DocsIndex";

export function DocsPage({
  title,
  html,
  docs,
  currentSlug,
}: {
  title: string;
  html: string;
  docs: DocEntry[];
  currentSlug: string;
}) {
  return (
    <Layout>
      <div class="max-w-5xl mx-auto px-4 xs:px-8 pt-20 pb-28 md:flex md:gap-12">
        {/* Sidebar — doc nav */}
        <nav class="hidden md:block shrink-0 w-56">
          <p class="text-xs uppercase tracking-[0.35em] mb-4 text-text-muted font-display font-medium">
            Documentation
          </p>
          <ul class="space-y-1">
            {docs.map((doc) => (
              <li key={doc.slug}>
                <a
                  href={`/docs/${doc.slug}/`}
                  class={`block px-3 py-1.5 text-sm rounded transition-colors font-sans ${
                    doc.slug === currentSlug
                      ? "bg-green-light text-console-dark font-medium"
                      : "text-text-muted hover:text-console-dark"
                  }`}
                >
                  {doc.title}
                </a>
              </li>
            ))}
          </ul>
        </nav>

        {/* Main content */}
        <article class="flex-1 min-w-0">
          {/* Mobile nav — collapsible, shown above content */}
          <details class="md:hidden mb-8 group border border-green-dark squircle-md">
            <summary class="flex items-center justify-between px-4 py-3 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
              <span class="text-xs uppercase tracking-[0.35em] text-text-muted font-display font-medium">
                Documentation
              </span>
              <span class="text-text-muted text-xs group-open:rotate-180 transition-transform">
                ▾
              </span>
            </summary>
            <ul class="p-2 space-y-1 border-t border-green-dark">
              {docs.map((doc) => (
                <li key={doc.slug}>
                  <a
                    href={`/docs/${doc.slug}/`}
                    class={`block px-3 py-2 text-sm rounded transition-colors font-sans ${
                      doc.slug === currentSlug
                        ? "bg-green-light text-console-dark font-medium"
                        : "text-text-muted"
                    }`}
                  >
                    {doc.title}
                  </a>
                </li>
              ))}
            </ul>
          </details>

          <div
            class="docs-content"
            dangerouslySetInnerHTML={{ __html: html }}
          />
        </article>
      </div>
    </Layout>
  );
}
