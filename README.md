# رابطك آمن؟ — URL safety checker

Paste a link, get a verdict (safe / suspicious / dangerous), and a short explanation in Saudi dialect with a limited follow-up chat.
Static frontend + Vercel serverless proxies. No database, no accounts, free tiers only.

## How it works

```text
Browser (index.html, Style.css, main.js)
  │
  ├─ Scan:  /api/virustotal ──fails?──► /api/safebrowsing ──fails?──► "ما قدرنا نكمل الفحص الحين، جرب بعد شوي."
  │
  └─ Explain / chat:  /api/gemini ──fails?──► /api/groq ──fails?──► "الشرح مو متوفر حالياً، جرب بعد شوي"
```

- Both fallback pairs use the same `withFallback(primary, secondary)` helper in `main.js`.
- API keys live only in the serverless functions (`api/*.js`), never in the browser.
- The AI system prompt is built server-side (`api/_lib/chat.js`), so the chat stays scoped to the current scan.
- Limits: 5 follow-up questions per scan (server also rejects more than 6) and 3 messages per minute (tracked in localStorage).

## Environment variables

Exactly these four names (case-sensitive):

| Variable          | Service                                   |
| ----------------- | ----------------------------------------- |
| `VirusToolKey`    | VirusTotal: primary scanner               |
| `SafeBrowsingKey` | Google Safe Browsing: fallback scanner    |
| `GeminiKey`       | Google Gemini: primary AI                 |
| `Groqkey`         | Groq: fallback AI                         |

`.env.example` is the template. Your real keys go in `.env.local`, which is git-ignored.

## Run locally

Requires Node 20.12+ (tested on Node 24).

```bash
# paste your keys into .env.local first
npm run dev
# open http://localhost:3000
```

`npm run dev` is a small built-in server (`scripts/dev.mjs`). No install or Vercel CLI is needed.
`npx vercel dev` also works if you prefer.

## Deploy to Vercel

1. Push this repo to GitHub.
2. In Vercel, click **Add New… → Project** and import the repo.
3. Set **Framework Preset** to **Other**. Leave Build Command and Output Directory empty.
4. Before clicking Deploy, open **Environment Variables** and add the 4 variables above. Tick all environments (Production, Preview, Development).
5. Click **Deploy**.

If you add or change a key after deploying, go to **Deployments → ⋯ → Redeploy**. Env var changes only apply to new deployments.

In Google Cloud, restrict the Safe Browsing key by **API** (Safe Browsing API), **not** by HTTP referrer. The call comes from Vercel's servers, not the browser.

## Testing the fallbacks

Add `?fail=` to the page URL with any of `virustotal`, `safebrowsing`, `gemini`, `groq`. The named proxy returns a real `503`, just like an outage or rate limit would.

| URL                                  | Expected                                                        |
| ------------------------------------ | --------------------------------------------------------------- |
| `/?fail=virustotal`                  | Result comes from Safe Browsing (no engine ratio, "فحص سريع" note) |
| `/?fail=gemini`                      | Explanation still appears (served by Groq)                      |
| `/?fail=virustotal,safebrowsing`     | Friendly "couldn't complete the check" message                  |
| `/?fail=gemini,groq`                 | Scan result shows; the explanation shows the friendly message plus a retry button |

The browser console (F12) logs which primary failed, e.g. `[fallback] gemini failed, trying groq`.
The page itself never shows which service answered.

For a "real" failure test, remove a key in Vercel and redeploy. The fallback handles a missing key the same way.

## Notes

- VirusTotal free tier allows 4 requests/min and 500/day.
  - Known URLs cost 1 request.
  - New URLs are submitted and polled (up to 4 requests, about 20 seconds).
  - If the analysis isn't ready in time, the scan falls back to Safe Browsing.
- Model names are constants at the top of `api/gemini.js` (`gemini-2.5-flash`) and `api/groq.js` (`openai/gpt-oss-120b`). Change them there if a model is retired.
- VirusTotal verdict thresholds are in `verdictFor()` in `api/virustotal.js`:
  - 3 or more malicious → dangerous
  - any malicious, or 2 or more suspicious → suspicious
