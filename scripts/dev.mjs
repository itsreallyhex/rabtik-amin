// Local preview without the Vercel CLI: serves the static files and runs the /api functions.
// Usage: npm run dev   (reads keys from .env.local)
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { extname, join, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const port = Number(process.env.PORT) || 3000;
const envFile = join(root, '.env.local');
if (existsSync(envFile)) process.loadEnvFile(envFile);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
};

// Apply the same headers (incl. CSP) as production so problems show up locally.
const vercelConfig = JSON.parse(await readFile(join(root, 'vercel.json'), 'utf8'));
const securityHeaders = vercelConfig.headers[0].headers;

createServer(async (req, res) => {
  for (const { key, value } of securityHeaders) res.setHeader(key, value);
  const { pathname } = new URL(req.url, 'http://localhost');

  try {
    const api = pathname.match(/^\/api\/([a-z]+)$/);
    if (api) return await runFunction(api[1], req, res);

    const segments = decodeURIComponent(pathname).split('/').filter(Boolean);
    const blocked = segments.some((s) => s.startsWith('.') || s.startsWith('_')) || ['api', 'scripts'].includes(segments[0]);
    const file = join(root, ...(segments.length ? segments : ['index.html']));
    if (blocked || !file.startsWith(root.endsWith(sep) ? root : root + sep)) throw new Error('blocked');

    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] || 'application/octet-stream' }).end(data);
  } catch {
    if (!res.headersSent) res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found');
  }
}).listen(port, () => console.log(`Local preview: http://localhost:${port}`));

async function runFunction(name, req, res) {
  const path = join(root, 'api', `${name}.js`);
  if (!existsSync(path)) return res.writeHead(404).end();
  const handler = (await import(pathToFileURL(path).href))[req.method];
  if (!handler) return res.writeHead(405).end();

  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const request = new Request(`http://localhost${req.url}`, {
    method: req.method,
    headers: { 'content-type': req.headers['content-type'] || 'application/json' },
    body: chunks.length ? Buffer.concat(chunks) : undefined,
  });
  const response = await handler(request);
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}
