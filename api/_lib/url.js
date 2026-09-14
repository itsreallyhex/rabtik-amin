import { HttpError } from './http.js';

// Accepts "example.com" or "https://example.com/path"; only http(s) links with a real hostname.
// Returns the URL as the user typed it (plus a scheme) so VirusTotal lookups match existing reports.
export function normalizeUrl(input) {
  let raw = typeof input === 'string' ? input.trim() : '';
  if (!raw || raw.length > 2048) throw new HttpError(400, 'invalid_url');
  if (!/^[a-z][a-z\d+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new HttpError(400, 'invalid_url');
  }
  if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname.includes('.')) {
    throw new HttpError(400, 'invalid_url');
  }
  return raw;
}
