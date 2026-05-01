export function Header() {
  return (
    <nav
      class="max-w-6xl mx-auto px-8 py-8 flex flex-wrap
      gap-y-2 items-center justify-between"
    >
      <a href="/" class="flex items-center gap-3 isolate">
        <img
          src="/clawpatrol-logo.svg"
          alt=""
          class="h-7 w-auto"
        />
        <span
          class="text-lg tracking-[0.25em] uppercase
            font-semibold font-display text-console-dark"
        >
          Claw Patrol
        </span>
      </a>
      <div class="flex items-center gap-4 sm:gap-8 text-sm">
        <a
          href="/docs/"
          class="transition-colors font-mono
            text-text-muted underline underline-offset-4"
        >
          Docs
        </a>
        <a
          href="https://github.com/denoland/clawpatrol-go"
          class="transition-colors font-mono
            text-text-muted underline underline-offset-4"
        >
          GitHub
        </a>
      </div>
    </nav>
  );
}
