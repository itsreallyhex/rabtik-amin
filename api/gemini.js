// Primary AI explainer. POST { scan, messages } -> { reply }.
import { ensureOk, getKey, proxy } from './_lib/http.js';
import { cleanReply, parseChatRequest } from './_lib/chat.js';

// "-latest" alias tracks Google's current Flash model so the project doesn't break when a version is retired.
const MODEL = 'gemini-flash-latest';

export const POST = proxy('gemini', async (body) => {
  const { system, turns } = parseChatRequest(body);

  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': getKey('GeminiKey') },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: turns.map((t) => ({ role: t.role === 'assistant' ? 'model' : 'user', parts: [{ text: t.content }] })),
      // Generous token cap: on thinking models, reasoning tokens count against it too.
      generationConfig: { temperature: 0.5, maxOutputTokens: 2048 },
    }),
    signal: AbortSignal.timeout(20_000),
  });
  await ensureOk(res, 'gemini');

  const data = await res.json();
  const parts = data?.candidates?.[0]?.content?.parts ?? [];
  const text = parts.filter((p) => !p.thought).map((p) => p.text ?? '').join('');
  return { reply: cleanReply(text) };
});
