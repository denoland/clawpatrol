import { Button } from "./Button";

export function Header() {
  return (
    <header class="sticky top-0 z-40 w-full py-5 bg-navy-100">
      <nav className="max-w-6xl mx-auto px-6 sm:px-8 flex flex-wrap justify-between gap-y-2 items-center">
        <a
          href="/"
          class="text-2xl
        font-black font-display hover:text-rust"
        >
          <img src="/claw-patrol-logo.svg" alt="" class="h-9 sm:h-12 w-auto" />
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
          <Button
            href="/docs/getting-started/"
            size="sm"
            class="inline-flex items-center gap-2"
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
          </Button>
        </div>
      </nav>
    </header>
  );
}
