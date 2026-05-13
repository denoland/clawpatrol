import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "_a",
    sourcemap: false,
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        headers: {
          // Local dev only: the gateway's tailnet gate trusts this
          // header when the request comes from loopback, which lets
          // `npm run dev` talk to the gateway without onboarding a
          // real wg/tailnet device.
          "Tailscale-User-Login": "dev@local",
        },
      },
    },
  },
});
