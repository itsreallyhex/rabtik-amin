// Primary AI explainer. POST { scan, messages } -> { reply, suggestions }.
import { ensureOk, getKey, proxy } from './_lib/http.js';
import { parseChatRequest, parseReply } from './_lib/chat.js';

// Tried in order on the same key; each model has its own free quota.
// Gemini 3.6 Flash writes the best replies but allows only 20 requests a day, so Gemma 4 takes over after that.
// (gemini-2.5-flash returns 404 for new users; gemma-4-31b-it kept returning 500s.)
const MODELS = ['gemini-3.6-flash', 'gemma-4-26b-a4b-it'];

const REPLY_SCHEMA = {
  type: 'OBJECT',
  properties: {
    reply: { type: 'STRING' },
    suggestions: { type: 'ARRAY', items: { type: 'STRING' } },
  },
  required: ['reply', 'suggestions'],
  propertyOrdering: ['reply', 'suggestions'],
};

async function generate(model, system, turns) {
  const res = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-goog-api-key': getKey('GeminiKey') },
    body: JSON.stringify({
      systemInstruction: { parts: [{ text: system }] },
      contents: turns.map((t) => ({ role: t.role === 'assistant' ? 'model' : 'user', parts: [{ text: t.content }] })),
      generationConfig: {
        temperature: 1,
        maxOutputTokens: 900,
        // Minimal thinking keeps replies fast (Netlify's function limit is ~10s). Gemma rejects thinkingBudget, so use thinkingLevel.
        thinkingConfig: { thinkingLevel: 'minimal' },
        responseMimeType: 'application/json',
        responseSchema: REPLY_SCHEMA,
      },
    }),
    signal: AbortSignal.timeout(8_000),
  });
  await ensureOk(res, `gemini ${model}`);

  const data = await res.json();
  const parts = data?.candidates?.[0]?.content?.parts ?? [];
  const text = parts.filter((p) => !p.thought).map((p) => p.text ?? '').join('');
  return parseReply(text);
}

export const POST = proxy('gemini', async (body) => {
  const { system, turns } = parseChatRequest(body);

  let lastError;
  for (const model of MODELS) {
    try {
      return await generate(model, system, turns);
    } catch (err) {
      lastError = err;
      console.warn(`[gemini] ${model} failed (${err.code ?? err.message}), trying the next model`);
    }
  }
  throw lastError;
});
