import { defineConfig, loadEnv, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// fills the site address into the share tags and leaves the paths relative when it is not set
function siteUrl(url: string): Plugin {
  return {
    name: "site-url",
    transformIndexHtml: (html) => html.replaceAll("__SITE_URL__", url.replace(/\/+$/, "")),
  };
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "PUBLIC_");
  return {
    // only variables that start with this prefix are built into the page
    envPrefix: "PUBLIC_",
    plugins: [react(), siteUrl(env.PUBLIC_SITE_URL || "")],
    server: {
      // in development the api worker runs on its own port and is reached through the same origin
      proxy: { "/api": "http://localhost:8787" },
    },
    preview: {
      proxy: { "/api": "http://localhost:8787" },
    },
  };
});
