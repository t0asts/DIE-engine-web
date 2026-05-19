import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    fs: {
      
      strict: false,
    },
  },
  worker: {
    format: "es",
  },
  build: {
    target: "esnext",
    sourcemap: true,
  },
  
  assetsInclude: ["**/*.wasm"],
});
