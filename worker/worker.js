// Cloudflare Worker — Claude proxy + Google OAuth code flow with refresh tokens.
//
// Required bindings (see wrangler.toml):
//   secret  ANTHROPIC_API_KEY     — for the Claude proxy
//   secret  GOOGLE_CLIENT_ID      — same client ID used by the frontend
//   secret  GOOGLE_CLIENT_SECRET  — from Google Cloud Console for that client
//   kv      AUTH_TOKENS           — stores refresh tokens, keyed by session id
//
// Set secrets:
//   npx wrangler secret put ANTHROPIC_API_KEY
//   npx wrangler secret put GOOGLE_CLIENT_ID
//   npx wrangler secret put GOOGLE_CLIENT_SECRET
//
// Create KV namespace then paste the id into wrangler.toml:
//   npx wrangler kv:namespace create AUTH_TOKENS

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
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

export default {
  async fetch(request, env) {
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS });
    }
    if (request.method !== 'POST') {
      return new Response('Method not allowed', { status: 405, headers: CORS });
    }

    const url = new URL(request.url);
    try {
      if (url.pathname === '/oauth/exchange') return await handleExchange(request, env);
      if (url.pathname === '/oauth/refresh')  return await handleRefresh(request, env);
      if (url.pathname === '/oauth/revoke')   return await handleRevoke(request, env);
      // Default: Claude proxy (preserves existing AI panel behavior, which posts to root).
      return await handleAi(request, env);
    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};
