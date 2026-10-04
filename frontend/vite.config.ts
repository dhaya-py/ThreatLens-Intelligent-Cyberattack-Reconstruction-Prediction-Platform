import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    // In development the API runs on the host; in Docker, nginx proxies /api.
    proxy: { "/api": "http://localhost:8000" },
  },
});
