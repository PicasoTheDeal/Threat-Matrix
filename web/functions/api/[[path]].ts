// cloudflare pages function that passes every /api request to the api worker
// this keeps the site and the api on one origin so the session cookie is first party
// it needs a service binding named API that points at the api worker

interface Env {
  API?: { fetch(request: Request): Promise<Response> };
}

export const onRequest = async ({ request, env }: { request: Request; env: Env }): Promise<Response> => {
  if (!env.API) {
    return new Response(JSON.stringify({ error: "The API service binding is not configured." }), {
      status: 503,
      headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
    });
  }
  return env.API.fetch(request);
};
