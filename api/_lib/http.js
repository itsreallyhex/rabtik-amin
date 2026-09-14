// Helpers shared by the API proxies. Files under api/_lib are not exposed as routes by Vercel.

export class HttpError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export function getKey(name) {
  const key = process.env[name];
  if (!key) throw new HttpError(500, `missing_env_${name}`);
  return key;
}

// Turns a non-2xx upstream response into an HttpError (429 stays 429 so rate limits are visible in logs).
export async function ensureOk(res, provider) {
  if (res.ok) return;
  const detail = await res.text().catch(() => '');
  console.error(`[${provider}] upstream ${res.status}: ${detail.slice(0, 300)}`);
  if (res.status === 429) throw new HttpError(429, 'rate_limited');
  throw new HttpError(502, `upstream_${res.status}`);
}

// Wraps a proxy: parses the JSON body, honours the test-only `simulateFail` flag,
// and converts any thrown error into a small JSON error response (never leaks details).
export function proxy(provider, handler) {
  return async function POST(request) {
    try {
      const text = await request.text();
      if (text.length > 20_000) throw new HttpError(413, 'body_too_large');
      let body;
      try {
        body = JSON.parse(text);
      } catch {
        throw new HttpError(400, 'invalid_json');
      }
      if (!body || typeof body !== 'object') throw new HttpError(400, 'invalid_json');
      if (body.simulateFail === true) throw new HttpError(503, 'simulated_failure');

      return Response.json(await handler(body), { headers: { 'Cache-Control': 'no-store' } });
    } catch (err) {
      const known = err instanceof HttpError;
      if (known) console.warn(`[${provider}] ${err.status} ${err.code}`);
      else console.error(`[${provider}]`, err);
      return Response.json(
        { error: known ? err.code : 'upstream_error' },
        { status: known ? err.status : 502, headers: { 'Cache-Control': 'no-store' } },
      );
    }
  };
}
