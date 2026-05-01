import { Layout } from "./Layout";
import { SectionLabel } from "./components/SectionLabel";

// tools/deploy `gh release download`s the latest binaries from
// denoland/unclaw on each deploy and uploads them to
// /opt/unclaw/static/dl/<TAG>/, with /dl/latest -> <TAG> as the
// stable symlink. Caddy serves the tree at /dl/. Linking
// /dl/latest/<asset> means each tile always resolves to the binary
// from the most recently mirrored upstream release.
const RELEASE_BASE = "/dl/latest";

const PLATFORMS: { label: string; sub: string; asset: string }[] = [
  {
    label: "macOS",
    sub: "Apple Silicon (arm64)",
    asset: "unclaw-darwin-arm64",
  },
  {
    label: "Linux",
    sub: "x86_64 (gnu)",
    asset: "unclaw-linux-x64-gnu",
  },
  {
    label: "Linux",
    sub: "arm64 (gnu)",
    asset: "unclaw-linux-arm64-gnu",
  },
];

export function Download() {
  return (
    <Layout>
      <section class="max-w-5xl mx-auto px-6 sm:px-8 pt-20 sm:pt-28 pb-20 sm:pb-32 text-center">
        <SectionLabel>Download</SectionLabel>
        <h1
          class="text-3xl sm:text-4xl md:text-5xl
            font-normal tracking-tight leading-[1.1] mb-8
            font-display text-console-dark"
        >
          Get Unclaw
        </h1>
        <p class="max-w-xl mx-auto text-base sm:text-lg leading-relaxed mb-12 text-text-muted">
          Standalone binaries built from source on every release. No
          dependencies — drop the file on your <code class="font-mono text-sm">PATH</code> and
          run <code class="font-mono text-sm">unclaw</code>. Prefer npm?{" "}
          <code class="font-mono text-sm">npm install -g unclaw</code> ships
          the same release.
        </p>

        <div class="max-w-2xl mx-auto mb-16">
          <p class="text-xs uppercase tracking-[0.2em] text-text-muted font-mono mb-3">
            One-liner
          </p>
          <pre class="px-5 py-4 squircle-md neu-inset bg-cream-light text-left overflow-x-auto">
            <code class="font-mono text-sm text-console-dark">
              curl -fsSL https://unclaw.dev/install.sh | sh
            </code>
          </pre>
          <p class="text-xs text-text-muted mt-3">
            Auto-detects your platform and installs to{" "}
            <code class="font-mono">~/.local/bin/unclaw</code>. Override with{" "}
            <code class="font-mono">UNCLAW_INSTALL_DIR</code> or pin a release
            with <code class="font-mono">UNCLAW_VERSION</code>.
          </p>
        </div>

        <ul class="grid sm:grid-cols-3 gap-6 sm:gap-8 max-w-3xl mx-auto mb-16 list-none p-0">
          {PLATFORMS.map((p) => (
            <li
              key={p.asset}
              class="flex flex-col items-center gap-4 p-6 squircle-md neu-raised bg-cream-light"
            >
              <div>
                <p class="text-lg font-display font-medium text-console-dark">
                  {p.label}
                </p>
                <p class="text-xs uppercase tracking-[0.2em] text-text-muted font-mono mt-1">
                  {p.sub}
                </p>
              </div>
              <a
                href={`${RELEASE_BASE}/${p.asset}`}
                class="px-6 py-3 text-sm uppercase
                  tracking-wider font-semibold
                  transition-colors squircle-full neu-raised
                  [--neu-face:var(--color-accent)] [--face-highlight-opacity:50%]
                  bg-accent text-console-dark font-display isolate hover:bg-accent-light"
              >
                Download
              </a>
              <p class="text-xs font-mono text-text-muted break-all">
                {p.asset}
              </p>
            </li>
          ))}
        </ul>

        <p class="text-sm text-text-muted">
          Source and release notes:{" "}
          <a
            href="https://github.com/denoland/unclaw/releases"
            class="underline underline-offset-2 transition-colors text-text"
          >
            github.com/denoland/unclaw/releases
          </a>
        </p>
      </section>
    </Layout>
  );
}
