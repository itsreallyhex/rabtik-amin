// Primary URL scanner. POST { url } -> normalized scan result.
import { HttpError, ensureOk, getKey, proxy } from './_lib/http.js';
import { normalizeUrl } from './_lib/url.js';

const VT_API = 'https://www.virustotal.com/api/v3';
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// malicious >= 3 -> dangerous; any malicious or 2+ suspicious -> suspicious (single "suspicious" flags are common noise).
function verdictFor(malicious, suspicious) {
  if (malicious >= 3) return 'dangerous';
  if (malicious >= 1 || suspicious >= 2) return 'suspicious';
  return 'safe';
}

function summarize(url, stats = {}, results = {}) {
  const count = (key) => Number(stats[key]) || 0;
  const malicious = count('malicious');
  const suspicious = count('suspicious');
  const total = malicious + suspicious + count('harmless') + count('undetected');
  if (total === 0) throw new HttpError(502, 'vt_empty_result');

  const engines = Object.values(results)
    .filter((r) => r.category === 'malicious' || r.category === 'suspicious')
    .map((r) => ({ name: r.engine_name, category: r.category, result: r.result || r.category }))
    .sort((a, b) => (a.category === b.category ? 0 : a.category === 'malicious' ? -1 : 1));

  return {
    source: 'virustotal',
    url,
    verdict: verdictFor(malicious, suspicious),
    stats: { flagged: malicious + suspicious, total, malicious, suspicious },
    engines,
    threats: [],
  };
}

export const POST = proxy('virustotal', async (body) => {
  const url = normalizeUrl(body.url);
  const headers = { 'x-apikey': getKey('VirusToolKey'), accept: 'application/json' };
  const timeout = () => AbortSignal.timeout(10_000);

  // 1) Reuse the existing report if VirusTotal already knows this URL (costs 1 request).
  const urlId = Buffer.from(url).toString('base64url');
  const lookup = await fetch(`${VT_API}/urls/${urlId}`, { headers, signal: timeout() });
  if (lookup.ok) {
    const attrs = (await lookup.json())?.data?.attributes;
    if (attrs?.last_analysis_results && Object.keys(attrs.last_analysis_results).length) {
      return summarize(url, attrs.last_analysis_stats, attrs.last_analysis_results);
    }
  } else if (lookup.status !== 404) {
    await ensureOk(lookup, 'virustotal');
  }

  // 2) Unknown URL: submit it and poll twice. Free tier is 4 requests/min, so this path uses at most 4.
  const submit = await fetch(`${VT_API}/urls`, {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ url }),
    signal: timeout(),
  });
  await ensureOk(submit, 'virustotal');
  const analysisId = (await submit.json())?.data?.id;
  if (!analysisId) throw new HttpError(502, 'vt_no_analysis_id');

  for (const waitMs of [8_000, 10_000]) {
    await sleep(waitMs);
    const res = await fetch(`${VT_API}/analyses/${encodeURIComponent(analysisId)}`, { headers, signal: timeout() });
    await ensureOk(res, 'virustotal');
    const attrs = (await res.json())?.data?.attributes;
    if (attrs?.status === 'completed') return summarize(url, attrs.stats, attrs.results);
  }

  // Still queued: treat as a failure so the client falls back to Safe Browsing.
  throw new HttpError(504, 'vt_analysis_pending');
});
