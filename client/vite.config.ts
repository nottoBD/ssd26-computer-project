import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import fs from "fs";
import { tanstackRouter } from "@tanstack/router-plugin/vite";

export default defineConfig({
  plugins: [
    tanstackRouter({
      routesDirectory: "./src/routes",
      generatedRouteTree: "./src/routeTree.gen.ts",
      routeFileIgnorePrefix: "-",
      quoteStyle: "single",
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
  ],
  server: {
    host: true,
    port: 5173,
    watch: {
      ignored: ["**/.pnpm-store/**"], // Stops Vite watcher from entering symlink loops
    },
    strictPort: true,
    https: (() => {
      const keyPath = process.env.TLS_KEY_PATH;
      const certPath = process.env.TLS_CERT_PATH;
      if (fs.existsSync(keyPath) && fs.existsSync(certPath)) {
        return {
          key: fs.readFileSync(keyPath),
          cert: fs.readFileSync(certPath),
        };
      }
      return undefined;
    })(),
    proxy: {
      "/api": {
        target: "https://server:8000",
        changeOrigin: true,
        secure: false, // Disable internal cert verification for dev (self-signed chain)
      },
    },
    hmr: {
      protocol: "wss",
      host: "healthsecure.local",
      port: 5173,
      clientPort: 3443,
      timeout: 6,
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
