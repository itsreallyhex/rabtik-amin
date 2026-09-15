// Primary AI explainer. POST { scan, messages } -> { reply, suggestions }.
import { ensureOk, getKey, proxy } from './_lib/http.js';
import { parseChatRequest, parseReply } from './_lib/chat.js';

// gemini-2.5-flash now returns 404 ("no longer available to new users").
const MODEL = 'gemini-3.6-flash';

const REPLY_SCHEMA = {
  type: 'OBJECT',
  properties: {
    reply: { type: 'STRING' },
    suggestions: { type: 'ARRAY', items: { type: 'STRING' } },
  },
  required: ['reply', 'suggestions'],
  propertyOrdering: ['reply', 'suggestions'],
};

export const POST = proxy('gemini', async (body) => {
  const { system, turns } = parseChatRequest(body);

  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': getKey('GeminiKey') },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: turns.map((t) => ({ role: t.role === 'assistant' ? 'model' : 'user', parts: [{ text: t.content }] })),
      // Minimal thinking: short explanations don't need it, and it keeps replies well under Netlify's ~10s function limit.
      generationConfig: {
        temperature: 1,
        maxOutputTokens: 900,
        thinkingConfig: { thinkingLevel: 'minimal' },
        responseMimeType: 'application/json',
        responseSchema: REPLY_SCHEMA,
      },
    }),
    signal: AbortSignal.timeout(20_000),
  });
  await ensureOk(res, 'gemini');

  const data = await res.json();
  const parts = data?.candidates?.[0]?.content?.parts ?? [];
  const text = parts.filter((p) => !p.thought).map((p) => p.text ?? '').join('');
  return parseReply(text);
});
