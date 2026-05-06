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
      "/api": "http://localhost:8080",
    },
  },
});
