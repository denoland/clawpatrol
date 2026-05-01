import type { ComponentChildren } from "preact";
import { Header } from "./components/Header";
import { Footer } from "./components/Footer";
import { Stripe } from "./components/Stripe";

export function Layout({ children }: { children: ComponentChildren }) {
  return (
    <div class="min-h-screen bg-cream text-text font-sans font-normal">
      <a
        href="#main"
        class="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:px-4 focus:py-2 focus:bg-console-dark focus:text-cream focus:rounded focus:outline-2 focus:outline-accent focus:font-display"
      >
        Skip to main content
      </a>
      <Stripe />
      <Header />
      <main
        id="main"
        tabindex={-1}
        class="focus:outline-none focus-visible:outline-none"
      >
        {children}
      </main>
      <Stripe />
      <Footer />
    </div>
  );
}
