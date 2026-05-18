import type { ComponentChildren } from "preact";
import { DotField } from "./components/DotField";
import { Footer } from "./components/Footer";
import { Header } from "./components/Header";
import { Stripe } from "./components/Stripe";

export function Layout({ children }: { children: ComponentChildren }) {
  return (
    <div class="min-h-screen bg-canvas text-text font-sans">
      <a
        href="#main"
        class="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:px-4 focus:py-2 focus:bg-console-dark focus:text-canvas focus:rounded focus:outline-2 focus:outline-rust focus:font-display"
      >
        Skip to main content
      </a>
      <Header />
      <DotField />
      <main
        id="main"
        tabindex={-1}
        class="focus:outline-none focus-visible:outline-none"
      >
        {children}
      </main>
      <Stripe color1="var(--color-navy)" />
      <Footer />
    </div>
  );
}
