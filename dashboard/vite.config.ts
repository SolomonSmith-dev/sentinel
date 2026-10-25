import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { mockApi } from "./mock/plugin.ts";

// Dev modes:
//   npm run dev                                      -> /api served by the fixture mock
//   VITE_API_PROXY=http://127.0.0.1:8787 npm run dev -> /api proxied to `wrangler dev`
export default defineConfig(({ mode }) => {
  const env = { ...loadEnv(mode, process.cwd(), "VITE_"), ...process.env };
  const proxyTarget = env.VITE_API_PROXY;

  return {
    plugins: [react(), tailwindcss(), ...(proxyTarget ? [] : [mockApi()])],
    server: proxyTarget
      ? { proxy: { "/api": { target: proxyTarget, changeOrigin: true } } }
      : undefined,
    build: { outDir: "dist", sourcemap: false, chunkSizeWarningLimit: 700 },
  };
});
