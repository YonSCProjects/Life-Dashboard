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

async function handlePushSubscribe(request, env) {
  const { subscription, times, tz, tasks } = await request.json();
  if (!subscription || !subscription.endpoint) return json({ error: 'missing subscription' }, 400);
  const key = await subKey(subscription.endpoint);
  const existing = await env.AUTH_TOKENS.get(key);
  const prev = existing ? JSON.parse(existing) : {};
  await env.AUTH_TOKENS.put(key, JSON.stringify({
    subscription,
    times: Array.isArray(times) && times.length ? times : (prev.times || DEFAULT_TIMES),
    tz: tz || prev.tz || 'UTC',
    tasks: Array.isArray(tasks) ? tasks : (prev.tasks || []),
    fired: prev.fired || {},
    updated: Date.now(),
  }));
  return json({ ok: true });
}

async function handlePushUnsubscribe(request, env) {
  const { endpoint } = await request.json();
  if (!endpoint) return json({ error: 'missing endpoint' }, 400);
  await env.AUTH_TOKENS.delete(await subKey(endpoint));
  return json({ ok: true });
}

async function handlePushTest(request, env) {
  if (!env.VAPID_PRIVATE_KEY) return json({ error: 'VAPID keys not configured on the worker' }, 500);
  const { subscription } = await request.json();
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
    if (!rec.subscription || !tasks.length) continue; // stay quiet when nothing's urgent

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

    const titles = tasks.slice(0, 4).map(t => '• ' + t.title);
    const extra = tasks.length > 4 ? `\n…and ${tasks.length - 4} more` : '';
    let res;
    try {
      res = await sendPush(env, rec.subscription, {
        title: `🚨 ${tasks.length} urgent task${tasks.length > 1 ? 's' : ''} need attention`,
        body: titles.join('\n') + extra,
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
      // Default: Claude proxy (preserves existing AI panel behavior, which posts to root).
      return await handleAi(request, env);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },

  async scheduled(event, env, ctx) {
    ctx.waitUntil(runScheduled(env));
  },
};
