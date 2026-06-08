// Cloudflare Worker — Claude proxy + Google OAuth + Web Push for urgent-task reminders.
//
// Required bindings (see wrangler.toml):
//   secret  ANTHROPIC_API_KEY     — for the Claude proxy
//   secret  GOOGLE_CLIENT_ID      — same client ID used by the frontend
//   secret  GOOGLE_CLIENT_SECRET  — from Google Cloud Console for that client
//   kv      AUTH_TOKENS           — refresh tokens (session:*) + push subs (push:*)
//
// For Web Push (background reminders even when the app is closed):
//   secret  VAPID_PUBLIC_KEY      — base64url raw P-256 public key
//   secret  VAPID_PRIVATE_KEY     — base64url raw P-256 private scalar (d)
//   secret  VAPID_SUBJECT         — e.g. mailto:you@example.com
//
// Generate a VAPID key pair (one-time):
//   npx web-push generate-vapid-keys
//   # → paste "Public Key" / "Private Key" into the secrets below
//
// Set secrets:
//   npx wrangler secret put ANTHROPIC_API_KEY
//   npx wrangler secret put GOOGLE_CLIENT_ID
//   npx wrangler secret put GOOGLE_CLIENT_SECRET
//   npx wrangler secret put VAPID_PUBLIC_KEY
//   npx wrangler secret put VAPID_PRIVATE_KEY
//   npx wrangler secret put VAPID_SUBJECT
//
// Create KV namespace then paste the id into wrangler.toml:
//   npx wrangler kv:namespace create AUTH_TOKENS
//
// The cron trigger in wrangler.toml drives the scheduled reminders.

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

function randomSessionId() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return [...buf].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function googleTokenRequest(params) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(params).toString(),
  });
  let data;
  try { data = await r.json(); } catch { data = {}; }
  return { ok: r.ok, status: r.status, data };
}

async function handleExchange(request, env) {
  const { code, redirect_uri, code_verifier } = await request.json();
  if (!code || !redirect_uri || !code_verifier) {
    return json({ error: 'missing code, redirect_uri, or code_verifier' }, 400);
  }

  const result = await googleTokenRequest({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    code,
    code_verifier,
    grant_type: 'authorization_code',
    redirect_uri,
  });

  if (!result.ok || !result.data.refresh_token) {
    return json({
      error: 'token_exchange_failed',
      details: result.data,
    }, result.status || 400);
  }

  const sessionId = randomSessionId();
  await env.AUTH_TOKENS.put(`session:${sessionId}`, JSON.stringify({
    refresh_token: result.data.refresh_token,
    created_at: Date.now(),
  }));

  return json({
    session_id: sessionId,
    access_token: result.data.access_token,
    expires_in: result.data.expires_in,
  });
}

async function handleRefresh(request, env) {
  const { session_id } = await request.json();
  if (!session_id) return json({ error: 'missing session_id' }, 400);

  const stored = await env.AUTH_TOKENS.get(`session:${session_id}`);
  if (!stored) return json({ error: 'invalid_session' }, 401);

  const { refresh_token } = JSON.parse(stored);
  const result = await googleTokenRequest({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token,
    grant_type: 'refresh_token',
  });

  if (!result.ok) {
    if (result.data && result.data.error === 'invalid_grant') {
      await env.AUTH_TOKENS.delete(`session:${session_id}`);
      return json({ error: 'invalid_session' }, 401);
    }
    return json({ error: 'refresh_failed', details: result.data }, result.status || 400);
  }

  return json({
    access_token: result.data.access_token,
    expires_in: result.data.expires_in,
  });
}

async function handleRevoke(request, env) {
  const { session_id } = await request.json();
  if (!session_id) return json({ error: 'missing session_id' }, 400);

  const stored = await env.AUTH_TOKENS.get(`session:${session_id}`);
  if (stored) {
    const { refresh_token } = JSON.parse(stored);
    await fetch('https://oauth2.googleapis.com/revoke?token=' + encodeURIComponent(refresh_token), {
      method: 'POST',
    }).catch(() => {});
    await env.AUTH_TOKENS.delete(`session:${session_id}`);
  }
  return json({ ok: true });
}

async function handleAi(request, env) {
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) return json({ error: 'API key not configured' }, 500);

  const body = await request.json();
  const payload = {
    model: body.model || 'claude-sonnet-4-20250514',
    max_tokens: body.max_tokens || 2048,
    system: body.system || '',
    messages: body.messages || [],
  };
  if (body.tools) payload.tools = body.tools;
  if (body.tool_choice) payload.tool_choice = body.tool_choice;

  const response = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify(payload),
  });

  const data = await response.text();
  return new Response(data, {
    status: response.status,
    headers: { ...CORS, 'Content-Type': 'application/json' },
  });
}

// ══════════════════════════════════════════════════
// WEB PUSH (VAPID + RFC 8291 aes128gcm payload encryption)
// ══════════════════════════════════════════════════
const enc = new TextEncoder();
const utf8 = s => enc.encode(s);

function b64urlToBytes(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64url(bytes) {
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function concatBytes(...arrs) {
  let len = 0; for (const a of arrs) len += a.length;
  const out = new Uint8Array(len); let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}

async function importVapidSigningKey(env) {
  const pub = b64urlToBytes(env.VAPID_PUBLIC_KEY); // 65-byte uncompressed point
  const jwk = {
    kty: 'EC', crv: 'P-256',
    x: bytesToB64url(pub.slice(1, 33)),
    y: bytesToB64url(pub.slice(33, 65)),
    d: env.VAPID_PRIVATE_KEY,
    ext: true,
  };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
}

async function vapidAuth(env, audience) {
  const header = bytesToB64url(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const payload = bytesToB64url(utf8(JSON.stringify({
    aud: audience,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: env.VAPID_SUBJECT || 'mailto:admin@example.com',
  })));
  const signingInput = `${header}.${payload}`;
  const key = await importVapidSigningKey(env);
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, utf8(signingInput));
  return `${signingInput}.${bytesToB64url(new Uint8Array(sig))}`;
}

async function hkdf(salt, ikm, info, length) {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, length * 8);
  return new Uint8Array(bits);
}

async function encryptPayload(subscription, plaintext) {
  const uaPublic = b64urlToBytes(subscription.keys.p256dh); // 65 bytes
  const authSecret = b64urlToBytes(subscription.keys.auth); // 16 bytes

  const asKeys = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey('raw', asKeys.publicKey)); // 65 bytes

  const uaKey = await crypto.subtle.importKey('raw', uaPublic, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const ecdhSecret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, asKeys.privateKey, 256));

  const salt = crypto.getRandomValues(new Uint8Array(16));

  // RFC 8291: derive the input keying material from the ECDH + auth secrets.
  const keyInfo = concatBytes(utf8('WebPush: info\0'), uaPublic, asPublic);
  const ikm = await hkdf(authSecret, ecdhSecret, keyInfo, 32);

  // RFC 8188: content-encryption key + nonce.
  const cek = await hkdf(salt, ikm, utf8('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, utf8('Content-Encoding: nonce\0'), 12);

  // Single, final record: data + 0x02 delimiter.
  const record = concatBytes(utf8(plaintext), new Uint8Array([2]));
  const aesKey = await crypto.subtle.importKey('raw', cek, { name: 'AES-GCM' }, false, ['encrypt']);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, record));

  const rs = 4096;
  const header = concatBytes(
    salt,
    new Uint8Array([(rs >>> 24) & 255, (rs >>> 16) & 255, (rs >>> 8) & 255, rs & 255]),
    new Uint8Array([asPublic.length]),
    asPublic,
  );
  return concatBytes(header, ciphertext);
}

async function sendPush(env, subscription, payloadObj) {
  const audience = new URL(subscription.endpoint).origin;
  const jwt = await vapidAuth(env, audience);
  const body = await encryptPayload(subscription, JSON.stringify(payloadObj));
  return fetch(subscription.endpoint, {
    method: 'POST',
    headers: {
      'Authorization': `vapid t=${jwt}, k=${env.VAPID_PUBLIC_KEY}`,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      'TTL': '86400',
    },
    body,
  });
}

async function subKey(endpoint) {
  const h = await crypto.subtle.digest('SHA-256', utf8(endpoint));
  return 'push:' + bytesToB64url(new Uint8Array(h)).slice(0, 32);
}

const DEFAULT_TIMES = ['09:00', '13:00', '17:00', '21:00'];

// Reads the request body once, then verifies the supplied session_id against the
// OAuth sessions in KV. Returns { body } on success or { error: Response } if
// the session is missing/invalid — caller should bail out with that response.
async function authedBody(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return { error: json({ error: 'invalid json' }, 400) }; }
  const sid = body && body.session_id;
  if (!sid || typeof sid !== 'string') return { error: json({ error: 'missing session_id' }, 401) };
  const stored = await env.AUTH_TOKENS.get(`session:${sid}`);
  if (!stored) return { error: json({ error: 'invalid session' }, 401) };
  return { body };
}

async function handlePushSubscribe(request, env) {
  const { body, error } = await authedBody(request, env);
  if (error) return error;
  const { subscription, times, tz, tasks, orders } = body;
  if (!subscription || !subscription.endpoint) return json({ error: 'missing subscription' }, 400);
  const key = await subKey(subscription.endpoint);
  const existing = await env.AUTH_TOKENS.get(key);
  const prev = existing ? JSON.parse(existing) : {};
  await env.AUTH_TOKENS.put(key, JSON.stringify({
    subscription,
    sessionId: body.session_id, // used by /push/notify-now lookup
    times: Array.isArray(times) && times.length ? times : (prev.times || DEFAULT_TIMES),
    tz: tz || prev.tz || 'UTC',
    tasks: Array.isArray(tasks) ? tasks : (prev.tasks || []),
    orders: Array.isArray(orders) ? orders : (prev.orders || []),
    fired: prev.fired || {},
    updated: Date.now(),
  }));
  return json({ ok: true });
}

async function handlePushUnsubscribe(request, env) {
  const { body, error } = await authedBody(request, env);
  if (error) return error;
  const { endpoint } = body;
  if (!endpoint) return json({ error: 'missing endpoint' }, 400);
  await env.AUTH_TOKENS.delete(await subKey(endpoint));
  return json({ ok: true });
}

async function handlePushTest(request, env) {
  if (!env.VAPID_PRIVATE_KEY) return json({ error: 'VAPID keys not configured on the worker' }, 500);
  const { body, error } = await authedBody(request, env);
  if (error) return error;
  const { subscription } = body;
  if (!subscription || !subscription.endpoint) return json({ error: 'missing subscription' }, 400);
  const res = await sendPush(env, subscription, {
    title: '🔔 Test alert',
    body: "Background push is working — you'll be reminded even when the app is closed.",
  });
  return json({ ok: res.ok, status: res.status });
}

// Cron-driven scheduled reminders. Fires once per configured slot per local day.
async function runScheduled(env) {
  if (!env.VAPID_PRIVATE_KEY || !env.VAPID_PUBLIC_KEY) return;
  const list = await env.AUTH_TOKENS.list({ prefix: 'push:' });
  const now = new Date();
  for (const k of list.keys) {
    const raw = await env.AUTH_TOKENS.get(k.name);
    if (!raw) continue;
    let rec; try { rec = JSON.parse(raw); } catch { continue; }
    const tasks = rec.tasks || [];
    const orders = rec.orders || [];
    if (!rec.subscription || (!tasks.length && !orders.length)) continue; // nothing to remind about

    const fmt = new Intl.DateTimeFormat('en-CA', {
      timeZone: rec.tz || 'UTC', hour12: false,
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit',
    });
    const parts = {};
    for (const p of fmt.formatToParts(now)) parts[p.type] = p.value;
    const localDate = `${parts.year}-${parts.month}-${parts.day}`;
    const localMins = parseInt(parts.hour, 10) * 60 + parseInt(parts.minute, 10);

    const times = rec.times && rec.times.length ? rec.times : DEFAULT_TIMES;
    const fired = (rec.fired && rec.fired[localDate]) || [];

    let dueSlot = null;
    for (const t of times) {
      const [h, m] = t.split(':').map(Number);
      const since = localMins - (h * 60 + m);
      if (since >= 0 && since < 120 && !fired.includes(t)) dueSlot = t;
    }
    if (!dueSlot) continue;

    // Compose attention-grabbing message that mixes urgent tasks + ready-to-collect packages.
    const lines = [];
    if (orders.length) {
      orders.slice(0, 3).forEach(o => {
        const label = (o.merchant || 'Order') + (o.product ? ' — ' + o.product : '');
        lines.push('📦 ' + label.slice(0, 80));
      });
      if (orders.length > 3) lines.push(`📦 …and ${orders.length - 3} more package${orders.length - 3 > 1 ? 's' : ''}`);
    }
    if (tasks.length) {
      const taskBudget = Math.max(0, 4 - lines.length);
      tasks.slice(0, taskBudget).forEach(t => lines.push('• ' + (t.title || '').slice(0, 80)));
      const taskExtra = tasks.length - taskBudget;
      if (taskExtra > 0) lines.push(`…and ${taskExtra} more task${taskExtra > 1 ? 's' : ''}`);
    }
    const parts2 = [];
    if (orders.length) parts2.push(`${orders.length} package${orders.length > 1 ? 's' : ''} waiting`);
    if (tasks.length)  parts2.push(`${tasks.length} urgent task${tasks.length > 1 ? 's' : ''}`);
    const titlePrefix = orders.length ? '📦' : '🚨';
    let res;
    try {
      res = await sendPush(env, rec.subscription, {
        title: `${titlePrefix} ${parts2.join(' + ')}`,
        body: lines.join('\n'),
      });
    } catch { continue; }

    if (res.status === 404 || res.status === 410) {
      await env.AUTH_TOKENS.delete(k.name); // subscription expired/gone
      continue;
    }
    rec.fired = { [localDate]: [...fired, dueSlot] }; // keep only today's slots
    rec.updated = Date.now();
    await env.AUTH_TOKENS.put(k.name, JSON.stringify(rec));
  }
}

// ══════════════════════════════════════════════════
// ORDERS — parse shipping messages with Claude
// ══════════════════════════════════════════════════
const ORDER_PARSE_TOOL = {
  name: 'parse_shipping_message',
  description: 'Extract structured fields from a shipping/order notification message (SMS or email).',
  input_schema: {
    type: 'object',
    required: ['merchant', 'status', 'confidence'],
    properties: {
      merchant: { type: 'string', description: 'Merchant or sender (AliExpress, Amazon, the carrier name, the postal service, etc.). Best guess if unclear.' },
      product: { type: 'string', description: 'Product/item description if mentioned. Empty string if not.' },
      tracking_number: { type: 'string', description: 'Shipment tracking number / package number if present. Empty string if absent.' },
      status: { type: 'string', enum: ['ordered', 'shipped', 'arrived', 'collected', 'lost', 'unknown'], description: '"arrived" means it has reached its pickup point and is waiting to be collected (e.g., at a post office, locker, or kiosk). "shipped" means in transit. "ordered" means paid but not yet shipped. Use "unknown" if the message does not clearly indicate status.' },
      ordered_at: { type: 'string', description: 'YYYY-MM-DD if mentioned, else empty string.' },
      expected_at: { type: 'string', description: 'YYYY-MM-DD expected delivery/pickup-by date if mentioned, else empty string.' },
      matched_order_id: { type: 'string', description: 'If this message clearly updates one of the existing orders provided in context (matched by tracking number, merchant, or product), the matching order id. Otherwise empty string.' },
      is_order_message: { type: 'boolean', description: 'TRUE only if this is a genuine transactional order/shipping notification about a specific purchase or parcel. FALSE for marketing/promotional emails, newsletters, coupons, "items left in your cart", wishlist nudges, or anything that is not a real order/shipment update. Used to filter auto-imported mail.' },
      confidence: { type: 'string', enum: ['high', 'medium', 'low'], description: 'Confidence in the extracted fields and the match.' },
      reasoning: { type: 'string', description: 'One short sentence explaining the classification + match decision (for the user to read).' },
    },
  },
};

// Calls Claude with the forced parse tool. Returns the parsed input object.
// `existing` is an array of compact { id, merchant, product, tracking_number, status } records for matching.
// Throws on API/transport errors so callers can decide how to surface them.
async function parseShippingMessage(env, text, existing) {
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) throw new Error('Claude API key not configured on worker');
  const ctx = Array.isArray(existing) ? existing.slice(0, 30) : [];

  const system = `You extract structured order/shipping info from SMS and email messages, often in Hebrew, English, or Chinese (AliExpress).
Common Israeli context: packages often go to דואר ישראל (Israel Post) branches, Boxit/Yango lockers, or kiosks for pickup — those messages indicate status "arrived" (waiting to be collected), not delivered to the door.
Today's date: ${new Date().toISOString().slice(0, 10)}.
You MUST call the parse_shipping_message tool exactly once with your best extraction. Use empty strings for unknown fields rather than guessing.`;

  const userContent = ctx.length
    ? `EXISTING ACTIVE ORDERS (for matching):\n${JSON.stringify(ctx, null, 2)}\n\nMESSAGE TO PARSE:\n${text}`
    : `MESSAGE TO PARSE:\n${text}`;

  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 1024,
      system,
      tools: [ORDER_PARSE_TOOL],
      tool_choice: { type: 'tool', name: 'parse_shipping_message' },
      messages: [{ role: 'user', content: userContent }],
    }),
  });
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error((data && data.error && data.error.message) || ('Claude API error ' + r.status));
    e.apiDetails = data;
    e.status = r.status;
    throw e;
  }
  const toolUse = (data.content || []).find(b => b.type === 'tool_use' && b.name === 'parse_shipping_message');
  if (!toolUse) throw new Error('Claude did not return parsed fields');
  return toolUse.input;
}

async function handleOrderParse(request, env) {
  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) return json({ error: 'Claude API key not configured on worker' }, 500);
  const { body, error } = await authedBody(request, env);
  if (error) return error;
  const text = (body.text || '').trim();
  if (!text) return json({ error: 'missing text' }, 400);
  const existing = Array.isArray(body.existing_orders) ? body.existing_orders : [];

  try {
    const parsed = await parseShippingMessage(env, text, existing);
    return json({ parsed });
  } catch (e) {
    // API errors carry apiDetails; other failures (e.g. no tool_use) surface their own message.
    return json({ error: e.apiDetails ? 'Claude API error' : e.message, details: e.apiDetails }, e.status || 502);
  }
}

// ══════════════════════════════════════════════════
// SERVER-SIDE ORDER STORE (Google Calendar via the session's refresh token)
// Mirrors the frontend's order<->calendar-event serialization so orders the
// worker writes look identical to ones the app writes.
// ══════════════════════════════════════════════════
const ORDER_PREFIX = '📦';
const ORDER_STATUSES = ['ordered', 'shipped', 'arrived', 'collected', 'lost'];

// Mint a fresh Google access token for a session from its stored refresh token.
// Returns null (and prunes a dead session) if the grant is gone.
async function googleAccessTokenForSession(env, sessionId) {
  const stored = await env.AUTH_TOKENS.get(`session:${sessionId}`);
  if (!stored) return null;
  let refresh_token;
  try { ({ refresh_token } = JSON.parse(stored)); } catch { return null; }
  if (!refresh_token) return null;
  const result = await googleTokenRequest({
    client_id: env.GOOGLE_CLIENT_ID,
    client_secret: env.GOOGLE_CLIENT_SECRET,
    refresh_token,
    grant_type: 'refresh_token',
  });
  if (!result.ok) {
    if (result.data && result.data.error === 'invalid_grant') {
      await env.AUTH_TOKENS.delete(`session:${sessionId}`);
    }
    return null;
  }
  return result.data.access_token;
}

async function calApi(accessToken, path, opts = {}) {
  const r = await fetch('https://www.googleapis.com/calendar/v3' + path, {
    ...opts,
    headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json', ...(opts.headers || {}) },
  });
  if (r.status === 204) return {};
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    const e = new Error('calendar API ' + r.status);
    e.status = r.status; e.apiDetails = data;
    throw e;
  }
  return data;
}

// Parse a calendar event into an order object — mirror of the frontend parseOrder().
function parseOrderEvent(event) {
  let data = {};
  try { data = JSON.parse(event.description || '{}') || {}; } catch { data = {}; }
  const summaryText = (event.summary || '').replace(ORDER_PREFIX, '').trim();
  const dashSplit = summaryText.split('—').map(s => s.trim());
  return {
    id: event.id,
    merchant: data.merchant || dashSplit[0] || 'Unknown',
    product: data.product || dashSplit.slice(1).join(' — ') || summaryText,
    trackingNumber: data.trackingNumber || '',
    status: data.status || 'ordered',
    orderedAt: data.orderedAt || (event.start && event.start.date) || '',
    expectedAt: data.expectedAt || null,
    statusHistory: Array.isArray(data.statusHistory) ? data.statusHistory : [],
    notes: data.notes || '',
    sourceMessages: Array.isArray(data.sourceMessages) ? data.sourceMessages : [],
  };
}

async function fetchActiveOrders(accessToken) {
  const now = new Date();
  const min = new Date(now.getFullYear() - 1, 0, 1).toISOString();
  const max = new Date(now.getFullYear() + 2, 0, 1).toISOString();
  const data = await calApi(accessToken,
    `/calendars/primary/events?timeMin=${encodeURIComponent(min)}&timeMax=${encodeURIComponent(max)}&maxResults=500&singleEvents=true&q=${encodeURIComponent(ORDER_PREFIX)}`);
  return (data.items || [])
    .filter(e => (e.summary || '').includes(ORDER_PREFIX))
    .map(parseOrderEvent)
    .filter(o => o.status !== 'collected' && o.status !== 'lost');
}

function orderSummary(o) {
  const m = (o.merchant || 'Order').trim();
  const p = (o.product || '').trim();
  return p ? m + ' — ' + p : m;
}

// Accept only a real YYYY-MM-DD calendar date; reject model misformats
// ('soon', '2026-13-45', '2026-02-30', localized strings) that would 400 the
// Calendar API. The round-trip check rejects impossible-but-well-formatted days.
function validDate(s) {
  if (typeof s !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(s)) return '';
  const d = new Date(s + 'T00:00:00Z');
  return (!isNaN(d.getTime()) && d.toISOString().slice(0, 10) === s) ? s : '';
}

// Google Calendar caps event descriptions at 8192 chars; stay safely under so an
// order accumulating many archived shipping messages can never 400 the write.
const CAL_DESC_LIMIT = 8000;
function orderEventBody(o) {
  const base = {
    merchant: o.merchant || '',
    product: o.product || '',
    trackingNumber: o.trackingNumber || '',
    status: o.status || 'ordered',
    orderedAt: o.orderedAt || '',
    expectedAt: o.expectedAt || null,
    statusHistory: o.statusHistory || [],
    notes: o.notes || '',
    sourceMessages: (o.sourceMessages || []).slice(-20),
    lastUpdated: new Date().toISOString(),
  };
  let out = JSON.stringify(base);
  while (out.length > CAL_DESC_LIMIT && base.sourceMessages.length) {
    base.sourceMessages.shift(); // drop oldest archived message until it fits
    out = JSON.stringify(base);
  }
  return out;
}

// Push a single notification to every subscription belonging to a session.
async function pushToSession(env, sessionId, title, body) {
  if (!env.VAPID_PRIVATE_KEY) return 0;
  const list = await env.AUTH_TOKENS.list({ prefix: 'push:' });
  let sent = 0;
  for (const k of list.keys) {
    const raw = await env.AUTH_TOKENS.get(k.name);
    if (!raw) continue;
    let rec; try { rec = JSON.parse(raw); } catch { continue; }
    if (rec.sessionId && rec.sessionId !== sessionId) continue;
    if (!rec.subscription) continue;
    try {
      const res = await sendPush(env, rec.subscription, { title, body });
      if (res.status === 404 || res.status === 410) await env.AUTH_TOKENS.delete(k.name);
      else sent++;
    } catch { /* best-effort */ }
  }
  return sent;
}

// Decide whether a parsed message is worth turning into/updating an order.
// Filters out marketing mail and ambiguous noise from auto-import sources.
function isIngestableParse(parsed) {
  if (parsed.is_order_message === false) return false;
  if (parsed.status === 'unknown' && parsed.confidence === 'low') return false;
  return true;
}

// Create or update the calendar event for a parsed message. Fires an arrival
// push when status crosses into 'arrived'. `existing` is the active-order list
// (it is mutated in place so callers batching multiple messages stay current).
async function ingestParsedOrder(env, sessionId, accessToken, parsed, originalText, existing) {
  const sourceMsg = { at: new Date().toISOString(), text: (originalText || '').slice(0, 2000) };
  const matched = parsed.matched_order_id ? existing.find(o => o.id === parsed.matched_order_id) : null;
  const status = ORDER_STATUSES.includes(parsed.status)
    ? parsed.status
    : (matched ? matched.status : 'shipped');

  if (matched) {
    const prevStatus = matched.status;
    const updated = {
      ...matched,
      merchant: parsed.merchant || matched.merchant,
      product: parsed.product || matched.product,
      trackingNumber: parsed.tracking_number || matched.trackingNumber,
      status,
      orderedAt: validDate(parsed.ordered_at) || matched.orderedAt,
      expectedAt: validDate(parsed.expected_at) || matched.expectedAt,
      statusHistory: [...(matched.statusHistory || []), { at: sourceMsg.at, status, note: 'Auto-imported' }],
      sourceMessages: [...(matched.sourceMessages || []), sourceMsg],
    };
    await calApi(accessToken, `/calendars/primary/events/${matched.id}`, {
      method: 'PATCH',
      body: JSON.stringify({ summary: ORDER_PREFIX + ' ' + orderSummary(updated), description: orderEventBody(updated) }),
    });
    Object.assign(matched, updated); // keep batch view fresh
    if (prevStatus !== 'arrived' && status === 'arrived') {
      await pushToSession(env, sessionId, '📦 Package ready to collect', orderSummary(updated));
    }
    return { action: 'updated', order: updated };
  }

  const ord = {
    merchant: parsed.merchant || 'Order',
    product: parsed.product || '',
    trackingNumber: parsed.tracking_number || '',
    status,
    orderedAt: validDate(parsed.ordered_at) || new Date().toISOString().slice(0, 10),
    expectedAt: validDate(parsed.expected_at) || null,
    statusHistory: [{ at: sourceMsg.at, status, note: 'Auto-imported' }],
    sourceMessages: [sourceMsg],
  };
  const d = ord.orderedAt;
  const ev = await calApi(accessToken, `/calendars/primary/events`, {
    method: 'POST',
    body: JSON.stringify({ summary: ORDER_PREFIX + ' ' + orderSummary(ord), description: orderEventBody(ord), start: { date: d }, end: { date: d } }),
  });
  ord.id = ev.id;
  existing.push(ord); // keep batch view fresh
  if (status === 'arrived') {
    await pushToSession(env, sessionId, '📦 Package ready to collect', orderSummary(ord));
  }
  return { action: 'created', order: ord };
}

// Compact existing-order list passed to Claude for matching.
function matchContext(existing) {
  return existing.slice(0, 30).map(o => ({
    id: o.id, merchant: o.merchant, product: o.product,
    tracking_number: o.trackingNumber, status: o.status,
  }));
}

// ── /orders/ingest-sms — Tasker (or anything) forwards a raw shipping message ──
// Two call styles, so phone-automation apps don't have to hand-build JSON:
//   A) JSON:      POST { session_id, text }
//   B) raw text:  POST <raw SMS body>, with session_id in ?session_id= or the
//                 X-Session-Id header. Avoids JSON-escaping the message text.
async function handleIngestSms(request, env) {
  if (!env.ANTHROPIC_API_KEY) return json({ error: 'Claude API key not configured on worker' }, 500);

  const url = new URL(request.url);
  const ct = request.headers.get('content-type') || '';
  let sessionId, text;
  if (ct.includes('application/json')) {
    let body; try { body = await request.json(); } catch { return json({ error: 'invalid json' }, 400); }
    sessionId = body && body.session_id;
    text = body && body.text;
  } else {
    sessionId = url.searchParams.get('session_id') || request.headers.get('x-session-id');
    text = await request.text();
  }

  if (!sessionId || typeof sessionId !== 'string') return json({ error: 'missing session_id' }, 401);
  if (!(await env.AUTH_TOKENS.get(`session:${sessionId}`))) return json({ error: 'invalid session' }, 401);
  text = (typeof text === 'string' ? text : '').trim();
  if (!text) return json({ error: 'missing text' }, 400);

  const accessToken = await googleAccessTokenForSession(env, sessionId);
  if (!accessToken) return json({ error: 'google_auth_failed', message: 'session may need to re-connect Google' }, 401);

  let existing;
  try { existing = await fetchActiveOrders(accessToken); }
  catch (e) { return json({ error: 'calendar_read_failed', details: e.apiDetails || e.message }, 502); }

  let parsed;
  try { parsed = await parseShippingMessage(env, text, matchContext(existing)); }
  catch (e) { return json({ error: 'parse_failed', details: e.apiDetails || e.message }, e.status || 502); }

  if (!isIngestableParse(parsed)) {
    return json({ ok: true, action: 'skipped', reason: 'not a recognizable order/shipping update', parsed });
  }

  try {
    const result = await ingestParsedOrder(env, sessionId, accessToken, parsed, text, existing);
    return json({ ok: true, action: result.action, order: { id: result.order.id, merchant: result.order.merchant, product: result.order.product, status: result.order.status } });
  } catch (e) {
    return json({ error: 'save_failed', details: e.apiDetails || e.message }, 502);
  }
}

// ══════════════════════════════════════════════════
// IMMEDIATE PUSH (used when an order is marked 'arrived' right now)
// ══════════════════════════════════════════════════
async function handleNotifyNow(request, env) {
  if (!env.VAPID_PRIVATE_KEY) return json({ error: 'VAPID keys not configured' }, 500);
  const { body, error } = await authedBody(request, env);
  if (error) return error;
  const title = (body.title || '🔔 Reminder').toString().slice(0, 120);
  const text  = (body.body  || '').toString().slice(0, 300);
  const sent = await pushToSession(env, body.session_id, title, text);
  return json({ ok: true, sent });
}

// ══════════════════════════════════════════════════
// GMAIL AUTO-PULL — cron polls each opted-in session's inbox for shipping mail
// and runs it through the same parse + upsert core. Server-side, app-closed.
// Opt-in state lives at  gmailpoll:<sessionId>  in KV.
// ══════════════════════════════════════════════════
// Pre-filter at Gmail so Claude only sees plausibly-relevant mail. Claude's
// is_order_message flag does the final filtering on top of this.
const GMAIL_QUERY = 'newer_than:2d -in:chats -category:promotions ' +
  '(tracking OR shipped OR shipment OR delivery OR delivered OR package OR parcel OR "out for delivery" OR ' +
  'order OR aliexpress OR ebay OR amazon OR "track your" OR ' +
  'משלוח OR חבילה OR מעקב OR נשלח OR "דואר ישראל" OR איסוף OR "הזמנה")';
const GMAIL_MAX_PER_RUN = 8;     // cap Claude calls per session per cron tick
const GMAIL_PROCESSED_CAP = 400; // ring buffer of seen message ids

function b64urlDecodeToString(s) {
  return new TextDecoder().decode(b64urlToBytes(s));
}

function stripHtml(html) {
  return html
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ')
    .trim();
}

// Walk a Gmail message payload, preferring text/plain, falling back to stripped HTML.
function extractBodyText(payload) {
  if (!payload) return '';
  const findPlain = (part) => {
    if (!part) return '';
    if (part.mimeType === 'text/plain' && part.body && part.body.data) return b64urlDecodeToString(part.body.data);
    if (Array.isArray(part.parts)) for (const p of part.parts) { const t = findPlain(p); if (t) return t; }
    return '';
  };
  const findHtml = (part) => {
    if (!part) return '';
    if (part.mimeType === 'text/html' && part.body && part.body.data) return stripHtml(b64urlDecodeToString(part.body.data));
    if (Array.isArray(part.parts)) for (const p of part.parts) { const t = findHtml(p); if (t) return t; }
    return '';
  };
  return findPlain(payload) || findHtml(payload) || '';
}

async function fetchGmailMessageText(accessToken, id) {
  const r = await fetch(`https://gmail.googleapis.com/gmail/v1/users/me/messages/${id}?format=full`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) return '';
  const data = await r.json().catch(() => ({}));
  const headers = (data.payload && data.payload.headers) || [];
  const h = (name) => (headers.find(x => x.name.toLowerCase() === name) || {}).value || '';
  const bodyText = extractBodyText(data.payload) || data.snippet || '';
  return `From: ${h('from')}\nSubject: ${h('subject')}\n\n${bodyText}`.slice(0, 6000);
}

async function pollGmailForSession(env, sessionId, accessToken, cfg, kvKey) {
  const listResp = await fetch(
    'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=20&q=' + encodeURIComponent(GMAIL_QUERY),
    { headers: { Authorization: `Bearer ${accessToken}` } });
  if (!listResp.ok) {
    if (listResp.status === 403) { cfg.scopeError = true; await env.AUTH_TOKENS.put(kvKey, JSON.stringify(cfg)); }
    return;
  }
  const listData = await listResp.json().catch(() => ({}));
  const msgs = listData.messages || [];
  if (!msgs.length) { cfg.lastPolledAt = Date.now(); await env.AUTH_TOKENS.put(kvKey, JSON.stringify(cfg)); return; }

  const processed = new Set(cfg.processedIds || []);
  let existing = [];
  try { existing = await fetchActiveOrders(accessToken); } catch { /* proceed without match context */ }

  const newlySeen = [];
  let handled = 0;
  for (const m of msgs) {
    if (processed.has(m.id)) continue;
    if (handled >= GMAIL_MAX_PER_RUN) break;
    let text;
    try { text = await fetchGmailMessageText(accessToken, m.id); } catch { continue; } // transient → retry next run
    if (!text) continue;
    handled++;
    let parsed;
    try { parsed = await parseShippingMessage(env, text, matchContext(existing)); }
    catch { continue; } // Claude hiccup → leave unseen so it retries
    if (!isIngestableParse(parsed)) { newlySeen.push(m.id); continue; } // junk → mark seen, don't re-Claude
    try {
      await ingestParsedOrder(env, sessionId, accessToken, parsed, text, existing);
      newlySeen.push(m.id); // imported → mark seen
    } catch (e) {
      // Non-transient write failure (e.g. 400/404 bad data) fails identically every
      // tick — mark seen so it can't loop and re-spend Claude tokens forever.
      // Transient (401/403/429/5xx) → leave unseen to retry next tick.
      const st = e && e.status;
      if (st >= 400 && st < 500 && st !== 401 && st !== 403 && st !== 429) newlySeen.push(m.id);
    }
  }

  const merged = [...(cfg.processedIds || []), ...newlySeen];
  cfg.processedIds = merged.slice(-GMAIL_PROCESSED_CAP);
  cfg.lastPolledAt = Date.now();
  cfg.sessionId = sessionId;
  delete cfg.scopeError;
  await env.AUTH_TOKENS.put(kvKey, JSON.stringify(cfg));
}

async function runGmailPoll(env) {
  if (!env.ANTHROPIC_API_KEY) return;
  const list = await env.AUTH_TOKENS.list({ prefix: 'gmailpoll:' });
  for (const k of list.keys) {
    const raw = await env.AUTH_TOKENS.get(k.name);
    if (!raw) continue;
    let cfg; try { cfg = JSON.parse(raw); } catch { continue; }
    if (!cfg.enabled) continue;
    const sessionId = cfg.sessionId || k.name.slice('gmailpoll:'.length);
    const accessToken = await googleAccessTokenForSession(env, sessionId);
    if (!accessToken) {
      // Null can mean a revoked grant OR a transient Google token failure (5xx/429).
      // googleAccessTokenForSession deletes session:<id> only on invalid_grant, so
      // only abandon the opt-in when the session is actually gone — otherwise retry next tick.
      if (!(await env.AUTH_TOKENS.get(`session:${sessionId}`))) await env.AUTH_TOKENS.delete(k.name);
      continue;
    }
    try { await pollGmailForSession(env, sessionId, accessToken, cfg, k.name); }
    catch { /* isolate failures per session */ }
  }
}

// ── /orders/gmail-config — enable/disable auto-import, or read status ──
// POST { session_id }                     → { enabled, lastPolledAt }
// POST { session_id, enabled: true|false} → set (enabling verifies gmail scope)
async function handleGmailConfig(request, env) {
  const { body, error } = await authedBody(request, env);
  if (error) return error;
  const key = 'gmailpoll:' + body.session_id;

  if (body.enabled === undefined) {
    const raw = await env.AUTH_TOKENS.get(key);
    const cfg = raw ? (JSON.parse(raw) || {}) : {};
    return json({ ok: true, enabled: !!cfg.enabled, lastPolledAt: cfg.lastPolledAt || 0 });
  }

  if (!body.enabled) {
    await env.AUTH_TOKENS.delete(key);
    return json({ ok: true, enabled: false });
  }

  // Enabling: confirm the session actually granted gmail.readonly.
  const accessToken = await googleAccessTokenForSession(env, body.session_id);
  if (!accessToken) return json({ error: 'google_auth_failed' }, 401);
  const test = await fetch('https://gmail.googleapis.com/gmail/v1/users/me/profile', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (test.status === 403) return json({ error: 'insufficient_scope', message: 'Re-connect Google to grant Gmail read access' }, 403);
  if (!test.ok) return json({ error: 'gmail_check_failed', status: test.status }, 502);

  const existing = await env.AUTH_TOKENS.get(key);
  const prev = existing ? (JSON.parse(existing) || {}) : {};
  await env.AUTH_TOKENS.put(key, JSON.stringify({
    enabled: true,
    sessionId: body.session_id,
    processedIds: prev.processedIds || [],
    lastPolledAt: prev.lastPolledAt || 0,
    createdAt: prev.createdAt || Date.now(),
  }));
  return json({ ok: true, enabled: true });
}

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }

    const url = new URL(request.url);

    // Public VAPID key lookup (used by the frontend to subscribe).
    if (request.method === 'GET' && url.pathname === '/push/key') {
      return json({ publicKey: env.VAPID_PUBLIC_KEY || '' });
    }

    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: CORS });
    }

    try {
      if (url.pathname === '/oauth/exchange')   return await handleExchange(request, env);
      if (url.pathname === '/oauth/refresh')    return await handleRefresh(request, env);
      if (url.pathname === '/oauth/revoke')     return await handleRevoke(request, env);
      if (url.pathname === '/push/subscribe')   return await handlePushSubscribe(request, env);
      if (url.pathname === '/push/unsubscribe') return await handlePushUnsubscribe(request, env);
      if (url.pathname === '/push/test')        return await handlePushTest(request, env);
      if (url.pathname === '/push/notify-now')  return await handleNotifyNow(request, env);
      if (url.pathname === '/orders/parse')     return await handleOrderParse(request, env);
      if (url.pathname === '/orders/ingest-sms')  return await handleIngestSms(request, env);
      if (url.pathname === '/orders/gmail-config') return await handleGmailConfig(request, env);
      // Default: Claude proxy (preserves existing AI panel behavior, which posts to root).
      return await handleAi(request, env);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env));
    ctx.waitUntil(runGmailPoll(env));
  },
};
