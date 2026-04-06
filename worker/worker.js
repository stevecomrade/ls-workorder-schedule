
// Cloudflare Worker — OAuth proxy for Lightspeed Workorder Schedule extension
// Secrets (set via `wrangler secret put`):
//   LS_CLIENT_ID
//   LS_CLIENT_SECRET

const TOKEN_URL    = 'https://cloud.lightspeedapp.com/oauth/access_token.php';
const REDIRECT_URI = 'https://stevecomrade.github.io/ls-workorder-schedule/callback';

// Only allow requests from your extension / GitHub Pages
const ALLOWED_ORIGINS = [
  'https://stevecomrade.github.io',
  'chrome-extension://',       // any chrome extension origin
  'moz-extension://',          // any firefox extension origin
];

function isAllowedOrigin(origin) {
  if (!origin) return true;  // no origin header = non-browser request (curl, etc.)
  return ALLOWED_ORIGINS.some(allowed => origin.startsWith(allowed));
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin || '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin');

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(origin) });
    }

    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405, headers: corsHeaders(origin),
      });
    }

    if (!isAllowedOrigin(origin)) {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403, headers: corsHeaders(origin),
      });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/token/exchange') {
        return await handleExchange(request, env, origin);
      }
      if (path === '/token/refresh') {
        return await handleRefresh(request, env, origin);
      }
      return new Response(JSON.stringify({ error: 'Not found' }), {
        status: 404, headers: corsHeaders(origin),
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500, headers: corsHeaders(origin),
      });
    }
  },
};

async function handleExchange(request, env, origin) {
  const { code } = await request.json();
  if (!code) {
    return new Response(JSON.stringify({ error: 'Missing code' }), {
      status: 400, headers: corsHeaders(origin),
    });
  }

  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'authorization_code',
      client_id:     env.LS_CLIENT_ID,
      client_secret: env.LS_CLIENT_SECRET,
      code:          code,
      redirect_uri:  REDIRECT_URI,
    }),
  });

  const data = await resp.json();
  if (!resp.ok) {
    return new Response(JSON.stringify({ error: 'Token exchange failed', detail: data }), {
      status: resp.status, headers: corsHeaders(origin),
    });
  }

  // Only return what the extension needs — never echo back the client secret
  return new Response(JSON.stringify({
    access_token:  data.access_token,
    refresh_token: data.refresh_token,
    expires_in:    data.expires_in,
  }), { status: 200, headers: corsHeaders(origin) });
}

async function handleRefresh(request, env, origin) {
  const { refresh_token } = await request.json();
  if (!refresh_token) {
    return new Response(JSON.stringify({ error: 'Missing refresh_token' }), {
      status: 400, headers: corsHeaders(origin),
    });
  }

  const resp = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type:    'refresh_token',
      client_id:     env.LS_CLIENT_ID,
      client_secret: env.LS_CLIENT_SECRET,
      refresh_token: refresh_token,
    }),
  });

  const data = await resp.json();
  if (!resp.ok) {
    return new Response(JSON.stringify({ error: 'Token refresh failed', detail: data }), {
      status: resp.status, headers: corsHeaders(origin),
    });
  }

  return new Response(JSON.stringify({
    access_token:  data.access_token,
    refresh_token: data.refresh_token,
    expires_in:    data.expires_in,
  }), { status: 200, headers: corsHeaders(origin) });
}
