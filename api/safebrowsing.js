// Fallback URL scanner (basic listed / not listed). POST { url } -> normalized scan result.
import { ensureOk, getKey, proxy } from './_lib/http.js';
import { normalizeUrl } from './_lib/url.js';

const THREAT_TYPES = ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'];

export const POST = proxy('safebrowsing', async (body) => {
  const url = normalizeUrl(body.url);
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(getKey('SafeBrowsingKey'))}`;

  const res = await fetch(endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      client: { clientId: 'rabetak-aman-school-project', clientVersion: '1.0.0' },
      threatInfo: {
        threatTypes: THREAT_TYPES,
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ url }],
      },
    }),
    signal: AbortSignal.timeout(10_000),
  });
  await ensureOk(res, 'safebrowsing');

  const data = await res.json();
  const threats = [...new Set((data.matches ?? []).map((m) => m.threatType))];
  return {
    source: 'safebrowsing',
    url,
    verdict: threats.length ? 'dangerous' : 'safe',
    stats: null,
    engines: [],
    threats,
  };
});
