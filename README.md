# رابطك آمن؟

A school project that checks links for phishing and malware. You paste a link, the site says whether it's safe, suspicious, or dangerous, and an AI explains the result in simple Saudi dialect. After that you can ask up to 10 follow-up questions about the link.

Live site: <https://rabtik-amin.netlify.app/>

The frontend is plain HTML, CSS, and JavaScript. Four small serverless functions talk to the outside services, so the API keys never reach the browser. There's no database and no login, and every service is on a free tier.

## How it works

```text
Browser (index.html, Style.css, main.js)
  │
  ├─ Scan:  /api/virustotal ──fails?──► /api/safebrowsing ──fails?──► "ما قدرنا نكمل الفحص الحين، جرب بعد شوي."
  │
  └─ Explain / chat:  /api/gemini ──fails?──► /api/groq ──fails?──► "الشرح مو متوفر حالياً، جرب بعد شوي"
```

Both chains use the same `withFallback(primary, secondary)` helper in `main.js`. It tries the first service, and if that errors, times out, or hits a rate limit, it tries the second. If the second one fails too, the page shows a friendly message. When the AI fails, the scan result still shows.

The server builds the AI instructions in `api/_lib/chat.js`, so the browser can't change them. They tell the model to:

- reply in casual Saudi dialect, in 2 or 3 short sentences
- skip technical words and explain things for someone who doesn't know tech
- answer only questions about the scanned link or link safety, and give a fixed refusal for anything else

Each scan allows 10 follow-up questions and 5 messages a minute. The browser enforces both (the per-minute count is kept in localStorage). The server also rejects any conversation longer than 11 questions.

## Example links

Under the scan box are 10 example links for people who don't have one to try. Clicking one fills in the box and runs a normal scan. It never opens the site.

| Safe          | Dangerous (harmless test pages)                   |
| ------------- | ------------------------------------------------- |
| google.com    | `secure.eicar.org/eicar.com`                      |
| youtube.com   | `secure.eicar.org/eicar.com.txt`                  |
| wikipedia.org | `secure.eicar.org/eicarcom2.zip`                  |
| apple.com     | `malware.wicar.org/data/eicar.com`                |
| github.com    | `testsafebrowsing.appspot.com/s/phishing.html`    |

The dangerous ones are pages that security companies publish so scanners will flag them. All 10 links got the expected verdict when checked against the live site. The three eicar.org links aren't on Google's list, though, so if VirusTotal is down they come back as safe. The list is `EXAMPLES` at the top of `main.js`.

## Environment variables

These names are case-sensitive:

| Variable          | Service                                   |
| ----------------- | ----------------------------------------- |
| `VirusToolKey`    | VirusTotal (main scanner)                 |
| `SafeBrowsingKey` | Google Safe Browsing (backup scanner)     |
| `GeminiKey`       | Google Gemini (main AI)                   |
| `Groqkey`         | Groq (backup AI)                          |

For local runs, put the keys in `.env.local`, which git ignores. `.env.example` is the template. For the live site, add the same four names in the hosting dashboard. Don't put keys in `vercel.json` or `netlify.toml`, since both files are committed.

In Google Cloud, restrict the Safe Browsing key by API, not by HTTP referrer, because the request comes from the server.

## Run locally

You need Node 20.12 or newer (it was tested on Node 24).

```bash
npm run dev
```

Then open <http://localhost:3000>. The command runs `scripts/dev.mjs`, a small server that serves the page, runs the functions in `api/`, and reads keys from `.env.local`. There's nothing to install.

## Deploy

The same code deploys to Netlify or Vercel. The logic lives in `api/`, and `netlify/functions/` holds one-line wrappers that serve those handlers at the same `/api/...` paths.

### Netlify (the live site)

1. Import the GitHub repo into Netlify. It doesn't need a build command.
2. Add the four keys under Project configuration → Environment variables.
3. Deploy. Every push to `main` redeploys the site.

Netlify gives functions less time to run than Vercel does. A link VirusTotal already knows comes back in a second or two, but a new link takes about 20 seconds and can get cut off. If that happens, the scan falls back to Safe Browsing.

### Vercel

1. Import the repo, set Framework Preset to Other, and leave Build Command and Output Directory empty.
2. Add the four keys under Environment Variables for all environments, then deploy.
3. If you change a key later, redeploy. Env var changes only reach new deployments.

## Testing the fallbacks

Add `?fail=` to the page URL with one or more of `virustotal`, `safebrowsing`, `gemini`, and `groq`. Each named function then returns a real 503, the same response an outage would give.

| URL                                  | What you should see                                                  |
| ------------------------------------ | -------------------------------------------------------------------- |
| `/?fail=virustotal`                  | A result from Safe Browsing, with no engine count                   |
| `/?fail=gemini`                      | An explanation, answered by Groq                                     |
| `/?fail=virustotal,safebrowsing`     | The "couldn't complete the check" message                            |
| `/?fail=gemini,groq`                 | The scan result, plus the "explanation unavailable" message and a retry button |

The browser console (F12) logs each fallback, for example `[fallback] gemini failed, trying groq`. The page itself never says which service answered.

## Notes

- VirusTotal's free tier allows 4 requests a minute and 500 a day. A link it already knows costs 1 request. A new link is submitted and then checked twice, which uses up to 4 requests and takes about 20 seconds. If the result still isn't ready, the scan falls back to Safe Browsing.
- VirusTotal won't scan its own domain (it returns 403), so `virustotal.com` always gets the Safe Browsing result.
- The AI models are `gemini-2.5-flash` (set in `api/gemini.js`) and `openai/gpt-oss-120b` (set in `api/groq.js`). Groq's Llama models are Enterprise-only now, and free keys get a 404 for them.
- `verdictFor()` in `api/virustotal.js` decides the verdict. Three or more "malicious" flags make a link dangerous. One "malicious" flag or two "suspicious" flags make it suspicious. Anything less is safe.
