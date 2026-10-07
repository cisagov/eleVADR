import { copyFileSync, existsSync, readdirSync, rmSync } from "node:fs";
import { resolve } from "node:path";
import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

const projectRoot = process.cwd();
const rootIndexHtml = resolve(projectRoot, "index.html");
const sourceIndexHtml = resolve(projectRoot, "src/index.html");

// The production Dockerfile copies src/index.html to /app/index.html and
// src/app/* to /app/src/*. Local development keeps the repository layout
// intact, where the HTML entry is src/index.html and the React entry is
// src/app/index.tsx. Detect the layout so both workflows continue to work.
const usesRepositoryLayout =
  !existsSync(rootIndexHtml) && existsSync(sourceIndexHtml);

export default defineConfig({
  base: process.env.VITE_BASE_PATH || "/",
  server: { host: "127.0.0.1", port: Number(process.env.VITE_PORT || 5173) },
  preview: {
    host: "127.0.0.1",
    port: Number(process.env.VITE_PREVIEW_PORT || 4173),
  },
  plugins: [
    react(),
    {
      name: "elevadr-local-layout",

      // Keep src/index.html unchanged on disk. In the repository layout,
      // rewrite its legacy paths in memory so Vite can resolve them.
      transformIndexHtml: {
        order: "pre",
        handler(html) {
          if (!usesRepositoryLayout) return html;

          return html
            .replace(
              'href="./node_modules/@uswds/uswds/dist/css/uswds.min.css"',
              'href="/node_modules/@uswds/uswds/dist/css/uswds.min.css"',
            )
            .replace(
              'src="%BASE_URL%src/index.tsx"',
              'src="/src/app/index.tsx"',
            );
        },
      },

      // In local development, make http://localhost:5173/ serve the
      // repository's existing src/index.html. HMR still watches src/app/*.
      configureServer(server) {
        if (!usesRepositoryLayout) return;

        server.middlewares.use((req, _res, next) => {
          if (req.url === "/") {
            req.url = "/src/index.html";
          }
          next();
        });
      },

      // A nested HTML build entry may be emitted as dist/src/index.html.
      // Normalize it to dist/index.html so the local production build has
      // the same output shape expected by nginx and the Docker image.
      closeBundle() {
        if (!usesRepositoryLayout) return;

        const nestedIndex = resolve(projectRoot, "dist/src/index.html");
        const outputIndex = resolve(projectRoot, "dist/index.html");

        if (!existsSync(nestedIndex)) return;

        copyFileSync(nestedIndex, outputIndex);
        rmSync(nestedIndex);

        const nestedDir = resolve(projectRoot, "dist/src");
        if (existsSync(nestedDir) && readdirSync(nestedDir).length === 0) {
          rmSync(nestedDir, { recursive: true, force: true });
        }
      },
    },
  ],

  // Local builds use src/index.html directly. Docker builds continue to use
  // /app/index.html exactly as before.
  build: {
    rollupOptions: {
      input: usesRepositoryLayout ? sourceIndexHtml : rootIndexHtml,
    },
  },

  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./src/setupTests.ts",
  },
});
