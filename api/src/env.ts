export interface Env {
  DB?: D1Database;
  // cloudflare turnstile secret set with wrangler secret put
  TURNSTILE_SECRET_KEY?: string;
  // other sites allowed to call the api directly as a comma separated list and usually empty
  ALLOWED_ORIGINS?: string;
  // optional and raises the nvd rate limit
  NVD_API_KEY?: string;
  // optional and raises the github advisories rate limit
  GITHUB_TOKEN?: string;
}
