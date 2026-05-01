export function Header() {
  return (
    <nav
      class="max-w-6xl mx-auto px-8 py-8 flex flex-wrap gap-y-2
      items-center justify-between"
    >
      <div
        class="text-xl tracking-[0.3em]
          uppercase font-semibold font-display text-console-dark"
      >
        <a href="/" class="isolate">
          <img src="/unclaw-logo.svg" alt="Unclaw Logo" class="h-8 w-auto" />
        </a>
      </div>
      <div class="flex items-center gap-4 sm:gap-8 text-sm">
        <a
          href="/docs/"
          class="transition-colors font-mono text-text-muted underline underline-offset-4"
        >
          Docs
        </a>
        <a
          href="/download/"
          class="transition-colors font-mono text-text-muted underline underline-offset-4"
        >
          Download
        </a>
        <a
          href="https://github.com/denoland/unclaw"
          class="transition-colors font-mono text-text-muted underline underline-offset-4 hidden sm:inline"
        >
          GitHub
        </a>
        {/* Removed for now */}
        {/* <a
          href="/auth/login"
          class="px-5 py-2 squircle-full neu-raised [--neu-face:var(--color-accent)] [--face-highlight-opacity:50%]
            font-semibold transition-colors bg-accent text-console-dark font-display text-sm tracking-wide hover:bg-accent-light"
        >
          Sign in
        </a> */}
      </div>
    </nav>
  );
}
