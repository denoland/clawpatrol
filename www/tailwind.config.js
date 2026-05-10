/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        mono: ["ui-monospace", '"SF Mono"', "Menlo", "monospace"],
      },
      letterSpacing: {
        tight12: ".12em",
        tight09: ".09em",
        tight08: ".08em",
      },
    },
  },
  plugins: [],
};
