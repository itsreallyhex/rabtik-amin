// ===== Settings =====
const MAX_FOLLOWUPS = 10;                             // user questions per scan
const RATE_LIMIT = { max: 5, windowMs: 60_000 };      // user messages per minute (saves free API quota)
const RATE_KEY = 'rabet:message-times';

// Test the fallbacks: open the site with ?fail=virustotal,gemini (any of: virustotal, safebrowsing, gemini, groq).
// The named proxy then returns a real 503, exactly like an outage or rate limit would.
const SIMULATED_FAILURES = new Set(
  (new URLSearchParams(location.search).get('fail') || '').split(',').map((s) => s.trim()).filter(Boolean),
);

// ===== Copy (Saudi dialect) =====
const T = {
  aiName: 'أمين',
  scanBtn: 'افحص',
  scanningBtn: 'نفحص...',
  emptyUrl: 'الصق الرابط أول وبعدين اضغط افحص.',
  invalidUrl: 'الرابط هذا مو صحيح، تأكد منه وجرب مرة ثانية.',
  scanFailed: 'ما قدرنا نكمل الفحص الحين، جرب بعد شوي.',
  aiUnavailable: 'الشرح مو متوفر حالياً، جرب بعد شوي',
  retry: 'جرب مرة ثانية',
  typing: 'يكتب...',
  limitReached: 'خلصت أسئلتك لهذا الرابط. افحص رابط ثاني لو تبي تسأل أكثر.',
  cooldown: (s) => `على هونك! استنى ${s} ثانية وبعدين أرسل.`,
  remaining: (n) => (n === 1 ? 'باقي لك سؤال واحد' : n === 2 ? 'باقي لك سؤالين' : `باقي لك ${n} أسئلة`),
  engineBadge: { malicious: 'ضار', suspicious: 'مشبوه' },
  sourceVT: (total) => `فحصناه بـ ${total} برنامج حماية عن طريق VirusTotal.`,
  sourceGSB: 'هذا فحص سريع من قائمة Google للمواقع الضارة، فما فيه تفاصيل عن برامج الحماية.',
  ratioNone: 'ولا برنامج حماية لقى فيه شي',
  ratioSome: (flagged, total) => `${flagged} من ${total} برنامج حماية علّموا عليه`,
};

// Used when the AI reply comes without its own suggestions.
const FALLBACK_SUGGESTIONS = {
  safe: ['ليش طلعت النتيجة كذا؟', 'كيف أعرف إنه الموقع الأصلي؟', 'كيف أعرف الروابط المزيفة؟'],
  suspicious: ['وش اللي خلاه مشبوه؟', 'وش أسوي لو فتحته؟', 'كيف أتأكد منه؟'],
  dangerous: ['وش اللي لقوه فيه؟', 'وش أسوي لو فتحته؟', 'كيف أعرف الروابط المزيفة؟'],
};

const VERDICT_UI = {
  safe: {
    icon: '#i-shield-check',
    title: 'الرابط هذا آمن',
    text: 'ما لقينا فيه شي يخوّف. بس خلك منتبه دايم قبل لا تحط بياناتك في أي موقع.',
  },
  suspicious: {
    icon: '#i-shield-alert',
    title: 'الرابط هذا مشبوه، انتبه',
    text: 'فيه أشياء مو مريحة. الأحسن لا تفتحه إلا إذا كنت متأكد من مصدره.',
  },
  dangerous: {
    icon: '#i-shield-x',
    title: 'الرابط هذا خطير، لا تفتحه!',
    text: 'طلع ضار. لا تفتحه ولا تحط فيه أي بيانات، ولو أحد أرسله لك نبّهه.',
  },
};

const THREAT_LABELS = {
  MALWARE: 'فيه برامج ضارة (فيروسات)',
  SOCIAL_ENGINEERING: 'موقع نصب يحاول يسرق بياناتك',
  UNWANTED_SOFTWARE: 'ينزّل برامج مزعجة ما تبيها',
  POTENTIALLY_HARMFUL_APPLICATION: 'فيه تطبيقات ممكن تضر جهازك',
};

// Example links for people without a link to test.
// "danger" entries are harmless test pages that security companies publish so scanners flag them.
const EXAMPLES = {
  safe: [
    { label: 'google.com', url: 'https://www.google.com/' },
    { label: 'youtube.com', url: 'https://www.youtube.com/' },
    { label: 'wikipedia.org', url: 'https://www.wikipedia.org/' },
    { label: 'apple.com', url: 'https://www.apple.com/' },
    { label: 'github.com', url: 'https://github.com/' },
  ],
  danger: [
    { label: 'eicar.org/eicar.com', url: 'https://secure.eicar.org/eicar.com' },
    { label: 'eicar.org/eicar.com.txt', url: 'https://secure.eicar.org/eicar.com.txt' },
    { label: 'eicar.org/eicarcom2.zip', url: 'https://secure.eicar.org/eicarcom2.zip' },
    { label: 'wicar.org/eicar.com', url: 'http://malware.wicar.org/data/eicar.com' },
    { label: 'testsafebrowsing/phishing', url: 'https://testsafebrowsing.appspot.com/s/phishing.html' },
  ],
};

// ===== API calls & the fallback pattern =====

async function callApi(name, body, timeoutMs) {
  const res = await fetch(`/api/${name}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...body, simulateFail: SIMULATED_FAILURES.has(name) || undefined }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`/api/${name} responded ${res.status}`);
  return res.json();
}

// Try the primary service; on ANY failure (error, rate limit, timeout, bad data) try the secondary.
// If the secondary fails too, the error propagates and the caller shows a friendly message.
async function withFallback(primary, secondary) {
  try {
    return await primary.run();
  } catch (err) {
    console.warn(`[fallback] ${primary.name} failed, trying ${secondary.name}:`, err.message);
  }
  return secondary.run();
}

function assertScan(data) {
  if (!data || !VERDICT_UI[data.verdict]) throw new Error('invalid scan response');
  return data;
}

function assertReply(data) {
  if (typeof data?.reply !== 'string' || !data.reply.trim()) throw new Error('empty reply');
  const suggestions = Array.isArray(data.suggestions)
    ? data.suggestions.filter((s) => typeof s === 'string' && s.trim()).map((s) => s.trim())
    : [];
  return { reply: data.reply.trim(), suggestions };
}

const scanUrl = (url) =>
  withFallback(
    { name: 'virustotal', run: () => callApi('virustotal', { url }, 45_000).then(assertScan) },
    { name: 'safebrowsing', run: () => callApi('safebrowsing', { url }, 15_000).then(assertScan) },
  );

const askAi = (scan, messages) =>
  withFallback(
    { name: 'gemini', run: () => callApi('gemini', { scan, messages }, 25_000).then(assertReply) },
    { name: 'groq', run: () => callApi('groq', { scan, messages }, 25_000).then(assertReply) },
  );

// ===== Client-side rate limit (localStorage, falls back to memory) =====

const rateLimiter = {
  memory: [],
  recent() {
    let times;
    try {
      times = JSON.parse(localStorage.getItem(RATE_KEY));
    } catch {}
    if (!Array.isArray(times)) times = this.memory;
    const cutoff = Date.now() - RATE_LIMIT.windowMs;
    return times.filter((t) => typeof t === 'number' && t > cutoff).sort((a, b) => a - b);
  },
  secondsToWait() {
    const recent = this.recent();
    if (recent.length < RATE_LIMIT.max) return 0;
    return Math.max(1, Math.ceil((recent[0] + RATE_LIMIT.windowMs - Date.now()) / 1000));
  },
  record() {
    this.memory = [...this.recent(), Date.now()];
    try {
      localStorage.setItem(RATE_KEY, JSON.stringify(this.memory));
    } catch {}
  },
};

// ===== URL validation (mirrors api/_lib/url.js) =====

function normalizeUrl(input) {
  let raw = input.trim();
  if (!raw || raw.length > 2048) return null;
  if (!/^[a-z][a-z\d+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;
  try {
    const { protocol, hostname } = new URL(raw);
    return ['http:', 'https:'].includes(protocol) && hostname.includes('.') ? raw : null;
  } catch {
    return null;
  }
}

// ===== DOM =====

const $ = (id) => document.getElementById(id);
const el = {
  scanForm: $('scan-form'), urlInput: $('url-input'), scanBtn: $('scan-btn'), scanBtnLabel: $('scan-btn-label'),
  scanError: $('scan-error'), loading: $('loading'),
  result: $('result'), verdictIcon: $('verdict-icon'), verdictTitle: $('verdict-title'), verdictText: $('verdict-text'),
  scannedUrl: $('scanned-url'), ratio: $('ratio'), ratioText: $('ratio-text'), ratioNum: $('ratio-num'),
  meterFill: $('meter-fill'), engines: $('engines'), engineList: $('engine-list'), threats: $('threats'),
  sourceNote: $('source-note'),
  chat: $('chat'), messages: $('messages'), suggestions: $('suggestions'), chatForm: $('chat-form'),
  chatInput: $('chat-input'), chatSend: $('chat-send'), chatStatus: $('chat-status'),
  againWrap: $('again-wrap'), againBtn: $('again-btn'),
  examples: $('examples'), examplesSafe: $('examples-safe'), examplesDanger: $('examples-danger'),
};

const prefersReducedMotion = () => matchMedia('(prefers-reduced-motion: reduce)').matches;
const reveal = (node, block = 'start') =>
  node.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block });

function h(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

// ===== Session state (in memory only; gone on reload) =====

// { scan, history: [{role, content}], followups, busy }
let session = null;

// ===== Scan flow =====

function showScanError(message) {
  el.scanError.textContent = message;
  el.scanError.hidden = false;
  el.urlInput.setAttribute('aria-invalid', 'true');
}

function clearScanError() {
  el.scanError.hidden = true;
  el.urlInput.removeAttribute('aria-invalid');
}

function setScanning(on) {
  el.loading.hidden = !on;
  el.scanBtn.disabled = on;
  el.urlInput.readOnly = on;
  el.scanBtnLabel.textContent = on ? T.scanningBtn : T.scanBtn;
  for (const chip of el.examples.querySelectorAll('.example-chip')) chip.disabled = on;
}

function renderExamples() {
  const chips = (list, kind) =>
    list.map(({ label, url }) => {
      const chip = h('button', `example-chip is-${kind}`);
      chip.type = 'button';
      chip.dataset.url = url;
      chip.setAttribute('aria-label', `افحص ${label}`);
      const text = h('bdi', null, label);
      text.dir = 'ltr';
      chip.append(text);
      return chip;
    });
  el.examplesSafe.replaceChildren(...chips(EXAMPLES.safe, 'safe'));
  el.examplesDanger.replaceChildren(...chips(EXAMPLES.danger, 'danger'));
}

// Clicking an example fills the box and runs the normal scan (it never opens the site).
el.examples.addEventListener('click', (event) => {
  const chip = event.target.closest('.example-chip');
  if (!chip || el.scanBtn.disabled) return;
  el.urlInput.value = chip.dataset.url;
  el.scanForm.requestSubmit();
});

renderExamples();

function resetResults() {
  session = null;
  el.result.hidden = true;
  el.chat.hidden = true;
  el.againWrap.hidden = true;
  el.messages.replaceChildren();
  el.suggestions.replaceChildren();
  el.chatForm.hidden = true;
  el.suggestions.hidden = true;
  setStatus('');
}

el.scanForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  clearScanError();
  if (!el.urlInput.value.trim()) return showScanError(T.emptyUrl);
  const url = normalizeUrl(el.urlInput.value);
  if (!url) return showScanError(T.invalidUrl);

  resetResults();
  setScanning(true);
  let scan;
  try {
    scan = await scanUrl(url);
  } catch (err) {
    console.warn('[scan] both scanners failed:', err.message);
    setScanning(false);
    showScanError(T.scanFailed);
    return;
  }
  setScanning(false);

  session = { scan, history: [], followups: 0, busy: false };
  renderResult(scan);
  el.chat.hidden = false;
  el.againWrap.hidden = false;
  el.result.focus({ preventScroll: true });
  reveal(el.result);
  explainResult();
});

function renderResult(scan) {
  const ui = VERDICT_UI[scan.verdict];
  el.result.className = `card result-card is-${scan.verdict}`;
  el.verdictIcon.setAttribute('href', ui.icon);
  el.verdictTitle.textContent = ui.title;
  el.verdictText.textContent = ui.text;
  el.scannedUrl.textContent = scan.url;

  const isVT = scan.source === 'virustotal' && scan.stats;
  el.ratio.hidden = !isVT;
  el.engines.hidden = true;
  el.engines.open = false;
  el.threats.hidden = true;

  if (isVT) {
    const { flagged, total } = scan.stats;
    el.ratioText.textContent = flagged ? T.ratioSome(flagged, total) : T.ratioNone;
    el.ratioNum.textContent = `${flagged}/${total}`;
    el.meterFill.style.width = '0';
    requestAnimationFrame(() => {
      el.meterFill.style.width = flagged ? `${Math.max(3, (flagged / total) * 100)}%` : '0';
    });

    const engines = Array.isArray(scan.engines) ? scan.engines : [];
    el.engineList.replaceChildren(
      ...engines.map((engine) => {
        const li = h('li');
        const info = h('div', 'engine-info');
        const name = h('bdi', 'engine-name', engine.name);
        name.dir = 'ltr';
        const result = h('bdi', 'engine-result', engine.result);
        result.dir = 'ltr';
        info.append(name, result);
        li.append(info, h('span', `badge badge-${engine.category}`, T.engineBadge[engine.category] || engine.category));
        return li;
      }),
    );
    el.engines.hidden = engines.length === 0;
    el.sourceNote.textContent = T.sourceVT(total);
  } else {
    const threats = Array.isArray(scan.threats) ? scan.threats : [];
    el.threats.replaceChildren(...threats.map((t) => h('li', null, THREAT_LABELS[t] || t)));
    el.threats.hidden = threats.length === 0;
    el.sourceNote.textContent = T.sourceGSB;
  }

  el.result.hidden = false;
}

el.againBtn.addEventListener('click', () => {
  resetResults();
  clearScanError();
  el.urlInput.value = '';
  window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
  el.urlInput.focus({ preventScroll: true });
});

// ===== AI explanation & follow-up chat =====

function addMessage(role, text, { error = false } = {}) {
  // AI replies are signed by أمين; site error messages aren't AI-written, so they stay unsigned.
  if (role === 'assistant' && !error) el.messages.append(h('div', 'msg-name', T.aiName));
  const bubble = h('div', `msg msg-${role}${error ? ' msg-error' : ''}`, text);
  el.messages.append(bubble);
  // Only follow the conversation once the user is chatting; the first explanation shouldn't pull focus off the verdict.
  if (session?.followups) reveal(bubble, 'nearest');
  return bubble;
}

function setStatus(text, warn = false) {
  el.chatStatus.textContent = text;
  el.chatStatus.classList.toggle('is-warn', warn);
}

function setBusy(busy) {
  session.busy = busy;
  $('typing')?.remove();
  if (busy) {
    const bubble = h('div', 'msg msg-assistant');
    bubble.id = 'typing';
    const dots = h('span', 'typing');
    dots.setAttribute('role', 'status');
    dots.setAttribute('aria-label', T.typing);
    dots.append(h('span'), h('span'), h('span'));
    bubble.append(dots);
    el.messages.append(bubble);
  }
  updateChatControls();
}

function updateChatControls() {
  const s = session;
  const ready = Boolean(s && s.history.length);
  const left = s ? MAX_FOLLOWUPS - s.followups : 0;
  const canSend = ready && !s.busy && left > 0;

  el.chatForm.hidden = !ready || left <= 0;
  el.suggestions.hidden = !ready || s.busy || left <= 0 || !el.suggestions.children.length;
  el.chatInput.disabled = !canSend;
  el.chatSend.disabled = !canSend;
  for (const chip of el.suggestions.children) chip.disabled = !canSend;

  if (ready) setStatus(left > 0 ? T.remaining(left) : T.limitReached);
}

// Returns false (and shows the cooldown) when the user is sending too fast.
function passesRateLimit() {
  const wait = rateLimiter.secondsToWait();
  if (wait) {
    setStatus(T.cooldown(wait), true);
    return false;
  }
  rateLimiter.record();
  return true;
}

async function fetchReply(s) {
  try {
    return await askAi(s.scan, s.history);
  } catch (err) {
    console.warn('[ai] both models failed:', err.message);
    return null;
  }
}

// Tap-to-send chips under the chat, refreshed after every reply; skips anything the user already asked.
function renderSuggestions(s, suggestions) {
  const asked = new Set(s.history.filter((m) => m.role === 'user').map((m) => m.content));
  const list = (suggestions.length ? suggestions : FALLBACK_SUGGESTIONS[s.scan.verdict])
    .filter((text) => !asked.has(text))
    .slice(0, 3);
  el.suggestions.replaceChildren(
    ...list.map((text) => {
      const chip = h('button', 'chip', text);
      chip.type = 'button';
      return chip;
    }),
  );
}

async function explainResult() {
  const s = session;
  setBusy(true);
  const reply = await fetchReply(s);
  if (s !== session) return; // a new scan started meanwhile

  if (!reply) {
    setBusy(false);
    const bubble = addMessage('assistant', T.aiUnavailable, { error: true });
    const retry = h('button', 'msg-retry');
    retry.type = 'button';
    retry.innerHTML = '<svg class="icon" aria-hidden="true"><use href="#i-rotate"/></svg>';
    retry.append(T.retry);
    retry.addEventListener('click', () => {
      if (s !== session || s.busy || !passesRateLimit()) return;
      bubble.remove();
      explainResult();
    });
    bubble.append(retry);
    return;
  }

  s.history.push({ role: 'assistant', content: reply.reply });
  renderSuggestions(s, reply.suggestions);
  setBusy(false);
  addMessage('assistant', reply.reply);
}

async function sendFollowup(text) {
  const s = session;
  const question = text.trim();
  if (!s || s.busy || !s.history.length || !question) return;
  if (s.followups >= MAX_FOLLOWUPS) return setStatus(T.limitReached);
  if (!passesRateLimit()) return;

  s.followups += 1;
  s.history.push({ role: 'user', content: question });
  addMessage('user', question);
  el.chatInput.value = '';

  setBusy(true);
  const reply = await fetchReply(s);
  if (s !== session) return;

  if (reply) {
    s.history.push({ role: 'assistant', content: reply.reply });
    renderSuggestions(s, reply.suggestions);
    setBusy(false);
    addMessage('assistant', reply.reply);
  } else {
    // Keep the history alternating and give the question back so it doesn't count.
    s.history.pop();
    s.followups -= 1;
    setBusy(false);
    addMessage('assistant', T.aiUnavailable, { error: true });
  }
  if (!el.chatForm.hidden) el.chatInput.focus({ preventScroll: true });
}

el.chatForm.addEventListener('submit', (event) => {
  event.preventDefault();
  sendFollowup(el.chatInput.value);
});

el.suggestions.addEventListener('click', (event) => {
  const chip = event.target.closest('.chip');
  if (chip) sendFollowup(chip.textContent);
});

if (SIMULATED_FAILURES.size) {
  console.info('[fallback test] simulating failures for:', [...SIMULATED_FAILURES].join(', '));
}
