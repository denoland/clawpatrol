export function Header() {
  return (
    <nav class="w-full px-6 py-5 sm:px-8 sm:py-8 bg-navy-100">
      <div className="max-w-6xl mx-auto flex flex-wrap justify-between gap-y-2 items-center">
        <a
          href="/"
          class="text-2xl
        font-black font-display hover:text-rust"
        >
          <img src="cp-logo-test.svg" alt="" class="h-9 sm:h-12 w-auto" />
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
          <a
            href="/docs/02-getting-started/"
            class="squircle-sm bg-console-dark text-canvas px-3 py-2 sm:px-4 sm:py-2.5 inline-flex items-center gap-2 font-mono hover:bg-rust transition-colors"
          >
            <svg
              width="14"
              height="14"
              viewBox="0 0 14 14"
              fill="none"
              aria-hidden="true"
            >
              <path
                d="M7 1.5v7.25m0 0L4 5.75m3 3 3-3M2.25 12h9.5"
                stroke="currentColor"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
              />
            </svg>
            Download
          </a>
        </div>
      </div>
    </nav>
  );
}
