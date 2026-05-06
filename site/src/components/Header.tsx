export function Header() {
  return (
    <nav class="w-full px-8 py-8 bg-navy text-canvas">
      <div className="max-w-6xl mx-auto flex flex-wrap justify-between gap-y-2 items-center">
        <a
          href="/"
          class="text-2xl
        font-black font-display hover:text-rust"
        >
          Claw Patrol
        </a>
        <div class="flex items-center gap-4 sm:gap-8 text-sm">
          <a
            href="/docs/"
            class="transition-colors font-mono
          underline underline-offset-4 hover:text-rust"
          >
            Docs
          </a>
          <a
            href="https://github.com/denoland/clawpatrol"
            class="transition-colors font-mono
          underline underline-offset-4 hover:text-rust"
          >
            GitHub
          </a>
        </div>
      </div>
    </nav>
  );
}
