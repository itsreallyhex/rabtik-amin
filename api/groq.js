// Fallback AI explainer on Groq. POST { scan, messages } -> { reply }.
import { ensureOk, getKey, proxy } from './_lib/http.js';
import { cleanReply, parseChatRequest } from './_lib/chat.js';

// Groq's Llama models are Enterprise-only now (free keys get a 404), so use their free production model.
const MODEL = 'openai/gpt-oss-120b';

export const POST = proxy('groq', async (body) => {
  const { system, turns } = parseChatRequest(body);

  const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${getKey('Groqkey')}` },
    body: JSON.stringify({
      model: MODEL,
      messages: [{ role: 'system', content: system }, ...turns],
      temperature: 0.5,
      // Reasoning model: keep reasoning light; its tokens count toward max_tokens.
      reasoning_effort: 'low',
      max_tokens: 1024,
    }),
    signal: AbortSignal.timeout(20_000),
  });
  await ensureOk(res, 'groq');

  const data = await res.json();
  return { reply: cleanReply(data?.choices?.[0]?.message?.content) };
});
