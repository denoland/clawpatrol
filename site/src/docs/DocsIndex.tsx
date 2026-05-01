import { Layout } from "../Layout";

export interface DocEntry {
  slug: string;
  title: string;
}

export function DocsIndex({ docs }: { docs: DocEntry[] }) {
  return (
    <Layout>
      <section class="max-w-3xl mx-auto px-8 pt-20 pb-28">
        <p class="text-xs uppercase tracking-[0.35em] mb-6 text-text-muted font-display font-medium">
          Documentation
        </p>
        <h1 class="text-4xl font-normal tracking-tight leading-tight mb-12 font-display text-console-dark">
          Unclaw Docs
        </h1>
        <nav>
          <ul class="space-y-4">
            {docs.map((doc) => (
              <li key={doc.slug}>
                <a
                  href={`/docs/${doc.slug}/`}
                  class="block px-6 py-4 squircle-md neu-raised
                    transition-colors text-console-dark
                    font-display font-medium tracking-wide
                    [--bg-highlight-opacity:30%]"
                >
                  {doc.title}
                  <span class="text-text-muted ml-2">&rarr;</span>
                </a>
              </li>
            ))}
          </ul>
        </nav>
      </section>
    </Layout>
  );
}
