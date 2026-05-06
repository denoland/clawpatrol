import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { mockApi } from "./mock-api";

const demo = process.env.DEMO === "1";

export default defineConfig({
  plugins: [react(), ...(demo ? [mockApi()] : [])],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsDir: "_a",
    sourcemap: false,
  },
  server: demo ? {} : {
    proxy: {
      "/api": "http://localhost:8080",
    },
  },
});
