# Threat Matrix: web app

React 19 + Vite + TypeScript. No UI framework; styles are plain CSS in `src/index.css` (tokens) and `src/App.css` (components).

```
cp .env.example .env.local   # Turnstile site key
npm install
npm run dev                  # http://localhost:5173
npm run build                # type-check and build into dist/
npm run lint
```

The app calls the API on its own origin under `/api`. In development Vite proxies that path to the
Worker on `http://localhost:8787`; in production `functions/api/[[path]].ts` forwards it through a
service binding named `API`.

`public/_headers` sets the Content-Security-Policy and other security headers on Cloudflare Pages.

## Layout

| Path | What it holds |
| --- | --- |
| `src/App.tsx` | State, data loading, URL sync, page layout |
| `src/components/` | Header, search and filters, the index (rows), detail sheet, dialogs, toasts |
| `src/lib/api.ts` | API client, feed cache, session storage |
| `src/lib/filter.ts` | Search, filters, sorting, topic matching, query-string state |
| `src/lib/turnstile.ts` | Loads Cloudflare Turnstile only when a form needs it |
