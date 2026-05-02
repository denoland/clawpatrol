export function Footer() {
  return (
    <footer
      class="px-8 py-16 text-xs
        font-mono text-cream bg-slate-dark"
    >
      <div
        className="w-full max-w-6xl mx-auto flex flex-col
        sm:flex-row gap-6 sm:gap-8
        sm:items-center sm:justify-between"
      >
        <div className="space-y-4">
          <p>
            Open-source under the{" "}
            <a
              href="https://github.com/denoland/clawpatrol/blob/main/LICENSE"
              class="underline underline-offset-4
                hover:text-accent"
            >
              MIT license
            </a>
            .
          </p>
          <p class="max-w-sm leading-relaxed">
            Made by the folks at{" "}
            <a
              href="https://deno.com"
              class="underline underline-offset-4
                hover:text-accent"
            >
              Deno
            </a>
            .
          </p>
        </div>
        <nav
          aria-label="Footer"
          class="flex flex-wrap gap-x-6 gap-y-2"
        >
          <a
            href="/docs/"
            class="underline underline-offset-4
              hover:text-accent"
          >
            Docs
          </a>
          <a
            href="https://github.com/denoland/clawpatrol"
            class="underline underline-offset-4
              hover:text-accent"
          >
            GitHub
          </a>
          <a
            href="https://github.com/denoland/clawpatrol/blob/main/LICENSE"
            class="underline underline-offset-4
              hover:text-accent"
          >
            License
          </a>
        </nav>
      </div>
    </footer>
  );
}
