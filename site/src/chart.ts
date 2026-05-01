// Client-side chart hydration for the landing page.
// Loaded as a separate script tag so it survives
// the prerender step that strips the main app script.

import { renderChart } from "./components/DemoChart";

async function init() {
  // Wait for DOM to be ready (Preact may not have
  // rendered yet when this module loads).
  await new Promise<void>((r) => {
    if (document.getElementById("demo-chart")) return r();
    const obs = new MutationObserver(() => {
      if (document.getElementById("demo-chart")) {
        obs.disconnect();
        r();
      }
    });
    obs.observe(document.body, {
      childList: true,
      subtree: true,
    });
  });

  const el = document.getElementById("demo-chart")!;

  let data = (window as any).__DEMO_DATA__;
  if (!data) {
    // Dev mode: fetch the JSON
    const res = await fetch("/s/demo-analytics.json");
    data = await res.json();
  }
  renderChart(el, data);
}

init();
