// Interactive analytics chart for the landing page.
// Renders scatter plot + histogram with Observable Plot.
// Supports tooltips, host filtering, and color-by toggle.

import * as Plot from "@observablehq/plot";

const MS_TICKS = [0.1, 1, 10, 100, 1000, 10000];
const PALETTE = [
  "#4269d0", "#efb118", "#ff725c", "#6cc5b0",
  "#3ca951", "#ff8ab7", "#a463f2", "#97bbf5",
  "#9c6b4e", "#9498a0",
];
const STATUS_COLORS = {
  domain: ["2xx", "3xx", "4xx", "5xx"],
  range: ["#2fa850", "#026beb", "#f59e0b", "#e90807"],
};

function fmtMs(v: number): string {
  if (v >= 1000) return `${v / 1000}k`;
  if (v < 1) return `${v}`;
  return `${Math.round(v)}`;
}

function statusCls(s: number): string {
  if (s < 300) return "2xx";
  if (s < 400) return "3xx";
  if (s < 500) return "4xx";
  return "5xx";
}

type ColorBy = "host" | "agent" | "status";

type Dot = {
  t: Date;
  ms: number;
  host: string;
  status: string;
  logMs: number;
};

export function renderChart(
  container: HTMLElement,
  rawData: [string, number, number, string][],
) {
  const allDots: Dot[] = rawData.map(
    ([t, us, status, host]) => {
      const ms = Math.max(us / 1000, 0.1);
      return {
        t: new Date(t),
        ms,
        host,
        status: statusCls(status),
        logMs: Math.log10(ms),
      };
    },
  );

  const allHosts = [...new Set(allDots.map((d) => d.host))]
    .sort();

  let colorBy: ColorBy = "host";
  const activeHosts = new Set<string>();

  function getColors(by: ColorBy) {
    if (by === "status") return STATUS_COLORS;
    const domain = allHosts;
    return {
      domain,
      range: PALETTE.slice(0, domain.length),
    };
  }

  function render() {
    // When one or more hosts are active, dim the others instead of filtering
    // them out — the dataset stays intact, only the highlight shifts.
    const hasSelection = activeHosts.size > 0;
    const dotOpacity = (d: Dot) =>
      !hasSelection || activeHosts.has(d.host) ? 0.75 : 0.22;
    const colors = getColors(colorBy);
    const w = container.clientWidth || 800;

    container.innerHTML = "";

    // --- Toolbar ---
    const toolbar = el("div",
      "flex items-center gap-3 mb-2 flex-wrap");

    const title = el("span",
      "text-[11px] font-semibold uppercase " +
      "tracking-wider text-navy-200");
    title.textContent = "RESPONSE LATENCY";
    toolbar.appendChild(title);

    // Log/linear toggle
    toolbar.appendChild(
      btnGroup(["log", "linear"], logScale ? "log" : "linear", (v) => {
        logScale = v === "log";
        render();
      }),
    );

    container.appendChild(toolbar);

    // --- Active host filter pills ---
    if (hasSelection) {
      const pills = el("div", "flex flex-wrap gap-1.5 mb-2");
      for (const host of activeHosts) {
        const pill = el("button",
          "inline-flex items-center gap-1 px-2 py-0.5 " +
          "text-xs bg-navy-200/20 text-navy-200 " +
          "rounded cursor-pointer");
        pill.textContent = `${host} ✕`;
        (pill as HTMLButtonElement).onclick = () => {
          activeHosts.delete(host);
          render();
        };
        pills.appendChild(pill);
      }
      if (activeHosts.size > 1) {
        const clear = el("button",
          "inline-flex items-center px-2 py-0.5 " +
          "text-xs text-navy-200/60 hover:text-navy-200 cursor-pointer");
        clear.textContent = "clear all";
        (clear as HTMLButtonElement).onclick = () => {
          activeHosts.clear();
          render();
        };
        pills.appendChild(clear);
      }
      container.appendChild(pills);
    }

    // --- Scatter plot ---
    const scatter = Plot.dot(allDots, {
      x: "t",
      y: "ms",
      fill: colorBy,
      r: 2.5,
      fillOpacity: dotOpacity,
      tip: {
        format: {
          x: (d: Date) => d.toLocaleTimeString(),
          y: (v: number) => `${fmtMs(v)} ms`,
        },
      },
    }).plot({
      width: w,
      height: 300,
      x: { label: null },
      y: {
        type: logScale ? "log" : "linear",
        label: "\u2191 Duration (ms)",
        grid: true,
        nice: true,
        ...(logScale
          ? { ticks: MS_TICKS, tickFormat: fmtMs }
          : {}),
      },
      color: { ...colors, legend: true },
      style: {
        background: "transparent",
        color: "#8a9990",
      },
    });

    // Click legend swatches to highlight a host. Plot auto-generates classes
    // like "plot-abc123-swatch" on each <span>; use [class$="-swatch"] so we
    // don't also match the container ("-swatches") or wrap ("-swatches-wrap"),
    // which would yank in the injected <style> block and every label.
    const swatches = scatter.querySelectorAll<HTMLElement>(
      '[class$="-swatch"]',
    );
    swatches.forEach((swatch) => {
      const label = swatch.textContent?.trim() ?? "";
      swatch.style.cursor = "pointer";
      swatch.style.transition = "opacity 150ms";
      if (hasSelection && !activeHosts.has(label)) {
        swatch.style.opacity = "0.4";
      }
      swatch.addEventListener("click", () => {
        if (!label) return;
        if (activeHosts.has(label)) {
          activeHosts.delete(label);
        } else {
          activeHosts.add(label);
        }
        render();
      });
    });

    container.appendChild(scatter);

    // --- Histogram ---
    const histTitle = el("div",
      "text-[11px] font-semibold uppercase " +
      "tracking-wider text-navy-200 mt-4 mb-1");
    histTitle.textContent = "LATENCY HISTOGRAM";
    container.appendChild(histTitle);

    // When a selection is active, layer two marks: a dimmed one for
    // non-active hosts and a bright one for active hosts. binX doesn't
    // honor per-datum fillOpacity accessors the way Plot.dot does.
    const xField = logScale ? "logMs" : "ms";
    const thresholds = logScale ? 60 : 40;
    const binOpts = (extra: Record<string, unknown>) => ({
      x: xField,
      fill: colorBy,
      thresholds,
      inset: 0,
      ...extra,
    });

    const histMarks = hasSelection
      ? [
          Plot.rectY(
            allDots.filter((d) => !activeHosts.has(d.host)),
            Plot.binX({ y: "count" }, binOpts({ fillOpacity: 0.3 })),
          ),
          Plot.rectY(
            allDots.filter((d) => activeHosts.has(d.host)),
            Plot.binX({ y: "count" }, binOpts({ tip: true })),
          ),
        ]
      : [
          Plot.rectY(
            allDots,
            Plot.binX({ y: "count" }, binOpts({ tip: true })),
          ),
        ];

    const hist = Plot.plot({
      marks: histMarks,
      width: w,
      height: 180,
      x: logScale
        ? {
            label: "Duration (ms) \u2192",
            ticks: MS_TICKS.map(Math.log10),
            tickFormat: (d: number) => fmtMs(Math.round(Math.pow(10, d))),
          }
        : { label: "Duration (ms) \u2192" },
      y: { label: null, grid: true },
      color: { ...colors, legend: false },
      style: {
        background: "transparent",
        color: "#8a9990",
      },
    });

    container.appendChild(hist);
  }

  let logScale = true;
  render();

  // Re-render on resize
  let resizeTimer: ReturnType<typeof setTimeout>;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(render, 150);
  });
}

// --- Helpers ---

function el(tag: string, className: string) {
  const e = document.createElement(tag);
  e.className = className;
  return e;
}

function btnGroup(
  options: string[],
  active: string,
  onChange: (v: string) => void,
) {
  const group = el("div", "flex gap-0.5");
  for (const opt of options) {
    const btn = el("button",
      `px-2 py-0.5 text-[10px] font-medium ${
        opt === active
          ? "bg-navy-200 text-console-dark"
          : "bg-console-dark/50 text-navy-200/60 " +
            "hover:text-navy-200"
      }`);
    btn.textContent = opt;
    (btn as HTMLButtonElement).onclick = () =>
      onChange(opt);
    group.appendChild(btn);
  }
  return group;
}
