import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";
import path from "path";
import fs from "fs";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: true,
    port: 5173,
    https: (() => {
      const keyPath = process.env.TLS_KEY_PATH ?? "./localhost-key.pem";
      const certPath = process.env.TLS_CERT_PATH ?? "./localhost.pem";
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
        target: "http://server:8000",
        changeOrigin: true,
      },
    },
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
