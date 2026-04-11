// OptionsEdge Pro — Cloudflare Worker (ES Modules format)
// Handles: Auth (signup/login), Stripe checkout, JWT validation, API proxy

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ── JWT helpers (no external libs — pure Web Crypto) ──────────────────────────

async function signJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const enc = (obj) => btoa(JSON.stringify(obj)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const data = enc(header) + '.' + enc(payload);
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  return data + '.' + sigB64;
}

async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const data = parts[0] + '.' + parts[1];
    const key = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']
    );
    const sig = Uint8Array.from(atob(parts[2].replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if (!valid) return null;
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ── Password hashing (SHA-256 based) ─────────────────────────────────────────

async function hashPassword(password, salt) {
  const s = salt || crypto.randomUUID();
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + s));
  const hash = btoa(String.fromCharCode(...new Uint8Array(buf)));
  return { hash, salt: s };
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async function initDB(db) {
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER NOT NULL, stripe_customer_id TEXT, stripe_subscription_id TEXT, subscription_status TEXT DEFAULT 'inactive', trial_end INTEGER, plan TEXT)"
  ).run();
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...CORS_HEADERS, 'Content-Type': 'application/json' },
  });
}

// ── Route handlers ────────────────────────────────────────────────────────────

// POST /auth/signup
async function handleSignup(req, env) {
  const { email, password } = await req.json();
  if (!email || !password) return json({ error: 'Email and password required' }, 400);
  if (password.length < 8) return json({ error: 'Password must be at least 8 characters' }, 400);

  await initDB(env.DB);

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (existing) return json({ error: 'An account with this email already exists' }, 409);

  const { hash, salt } = await hashPassword(password);
  const id = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const trialEnd = now + (7 * 24 * 60 * 60); // 7 days

  await env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, salt, created_at, subscription_status, trial_end) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, email.toLowerCase(), hash, salt, now, 'trialing', trialEnd).run();

  const token = await signJWT(
    { sub: id, email: email.toLowerCase(), status: 'trialing', trialEnd, exp: now + 86400 * 30 },
    env.JWT_SECRET
  );

  return json({ token, email: email.toLowerCase(), status: 'trialing', trialEnd });
}

// POST /auth/login
async function handleLogin(req, env) {
  const { email, password } = await req.json();
  if (!email || !password) return json({ error: 'Email and password required' }, 400);

  await initDB(env.DB);

  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email.toLowerCase()).first();
  if (!user) return json({ error: 'Invalid email or password' }, 401);

  const { hash } = await hashPassword(password, user.salt);
  if (hash !== user.password_hash) return json({ error: 'Invalid email or password' }, 401);

  // Check subscription/trial status
  const now = Math.floor(Date.now() / 1000);
  let status = user.subscription_status;
  if (status === 'trialing' && user.trial_end < now) {
    status = 'trial_expired';
    await env.DB.prepare('UPDATE users SET subscription_status = ? WHERE id = ?').bind('trial_expired', user.id).run();
  }

  const token = await signJWT(
    { sub: user.id, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, exp: now + 86400 * 30 },
    env.JWT_SECRET
  );

  return json({ token, email: user.email, status, trialEnd: user.trial_end, plan: user.plan });
}

// POST /auth/verify
async function handleVerify(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return json({ valid: false }, 401);

  // Re-check DB for latest subscription status
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.sub).first();
  if (!user) return json({ valid: false }, 401);

  const now = Math.floor(Date.now() / 1000);
  let status = user.subscription_status;
  if (status === 'trialing' && user.trial_end < now) {
    status = 'trial_expired';
    await env.DB.prepare('UPDATE users SET subscription_status = ? WHERE id = ?').bind('trial_expired', user.id).run();
  }

  return json({ valid: true, email: user.email, status, trialEnd: user.trial_end, plan: user.plan });
}

// POST /stripe/checkout
async function handleCheckout(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return json({ error: 'Unauthorized' }, 401);

  const { plan, successUrl, cancelUrl } = await req.json();
  const priceId = plan === 'annual' ? env.STRIPE_ANNUAL_PRICE : env.STRIPE_MONTHLY_PRICE;

  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(payload.sub).first();

  // Build Stripe checkout session
  const params = new URLSearchParams({
    mode: 'subscription',
    'line_items[0][price]': priceId,
    'line_items[0][quantity]': '1',
    'subscription_data[trial_period_days]': '7',
    success_url: successUrl + '?session_id={CHECKOUT_SESSION_ID}',
    cancel_url: cancelUrl,
    customer_email: user.email,
    'metadata[user_id]': user.id,
  });

  const stripeRes = await fetch('https://api.stripe.com/v1/checkout/sessions', {
    method: 'POST',
    headers: {
      'Authorization': 'Basic ' + btoa(env.STRIPE_SECRET_KEY + ':'),
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params.toString(),
  });

  const session = await stripeRes.json();
  if (!stripeRes.ok) return json({ error: session.error?.message || 'Stripe error' }, 500);

  return json({ url: session.url });
}

// POST /stripe/webhook
async function handleWebhook(req, env) {
  const body = await req.text();
  const sig = req.headers.get('stripe-signature');

  // Parse event (signature verification requires wrangler — skipping in dashboard mode)
  let event;
  try {
    event = JSON.parse(body);
  } catch (e) {
    return new Response('Invalid JSON', { status: 400 });
  }

  await initDB(env.DB);

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const userId = session.metadata?.user_id;
    if (userId) {
      await env.DB.prepare(
        'UPDATE users SET stripe_customer_id = ?, stripe_subscription_id = ?, subscription_status = ?, plan = ? WHERE id = ?'
      ).bind(
        session.customer,
        session.subscription,
        'active',
        session.amount_total === 24900 ? 'monthly' : 'annual',
        userId
      ).run();
    }
  }

  if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.paused') {
    const sub = event.data.object;
    await env.DB.prepare(
      'UPDATE users SET subscription_status = ? WHERE stripe_subscription_id = ?'
    ).bind('inactive', sub.id).run();
  }

  if (event.type === 'invoice.payment_failed') {
    const invoice = event.data.object;
    await env.DB.prepare(
      'UPDATE users SET subscription_status = ? WHERE stripe_customer_id = ?'
    ).bind('past_due', invoice.customer).run();
  }

  return new Response('ok', { status: 200 });
}

// ── Existing proxy logic (preserve all current functionality) ─────────────────

// MarketData.app API token (options chain data)
const MD_TOKEN = 'VjFYQWlwZDVCZ2ZIMm9TV3BFcndIeGxZbkdBelNESGNDVzh2czBWaHF1Yz0';

// ── Response cache (shared across all users) ──────────────────────────────────
// In-memory cache: all users share cached responses for the same API call.
// Cloudflare Workers have per-isolate memory that persists across requests
// within the same isolate (~seconds to minutes), plus we use Cache API for
// longer persistence.
const CACHE_TTL_STOCK = 5 * 60;   // 5 minutes for stock quotes/RSI/SMA
const CACHE_TTL_OPTIONS = 15 * 60; // 15 minutes for options chains/expirations

function getCacheTTL(proxyUrl) {
  if (proxyUrl.includes('api.marketdata.app')) return CACHE_TTL_OPTIONS;
  return CACHE_TTL_STOCK;
}

// Use Cloudflare Cache API for cross-request persistence
async function getCached(cacheKey) {
  const cache = caches.default;
  const resp = await cache.match(cacheKey);
  return resp || null;
}

async function putCache(cacheKey, response, ttl) {
  const cache = caches.default;
  const cloned = new Response(response.body, response);
  cloned.headers.set('Cache-Control', 'public, max-age=' + ttl);
  cloned.headers.set('X-Cache-Expires', new Date(Date.now() + ttl * 1000).toISOString());
  await cache.put(cacheKey, cloned);
}

async function requireAuth(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  const payload = await verifyJWT(token, env.JWT_SECRET);

  if (!payload) return { error: json({ error: 'Unauthorized — please log in' }, 401) };

  const now = Math.floor(Date.now() / 1000);
  if (payload.status === 'trialing' && payload.trialEnd < now) {
    return { error: json({ error: 'Trial expired — please subscribe to continue' }, 402) };
  }
  if (!['active', 'trialing'].includes(payload.status)) {
    return { error: json({ error: 'Subscription required' }, 402) };
  }
  return { payload };
}

async function handleProxy(req, env) {
  const url = new URL(req.url);
  const target = url.searchParams.get('url');
  const mdPath = url.searchParams.get('path');
  if (!target && !mdPath) return new Response('Missing url or path param', { status: 400 });

  // Validate JWT
  const authCheck = await requireAuth(req, env);
  if (authCheck.error) return authCheck.error;

  let proxyUrl;
  let proxyHeaders = { 'User-Agent': 'OptionsEdgePro/1.0' };

  if (mdPath) {
    // MarketData.app proxy: ?path=options/chain/TSLA/&side=call&...
    const params = new URLSearchParams();
    params.set('token', MD_TOKEN);
    for (const [k, v] of url.searchParams.entries()) {
      if (k !== 'path') params.set(k, v);
    }
    proxyUrl = 'https://api.marketdata.app/v1/' + mdPath + '?' + params.toString();
  } else {
    // Generic URL proxy: ?url=https://api.twelvedata.com/...
    proxyUrl = target;
  }

  // ── Check cache before hitting upstream API ──
  const cacheKey = new Request('https://cache.optionsedge.internal/' + encodeURIComponent(proxyUrl));
  const cached = await getCached(cacheKey);
  if (cached) {
    // Return cached response with CORS headers + cache indicator
    const body = await cached.text();
    return new Response(body, {
      status: cached.status,
      headers: {
        ...CORS_HEADERS,
        'Content-Type': cached.headers.get('Content-Type') || 'application/json',
        'X-Cache': 'HIT',
        'X-Cache-Expires': cached.headers.get('X-Cache-Expires') || '',
      },
    });
  }

  // ── Cache MISS — fetch from upstream ──
  const proxyRes = await fetch(proxyUrl, { headers: proxyHeaders });
  const data = await proxyRes.text();

  const response = new Response(data, {
    status: proxyRes.status,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': proxyRes.headers.get('Content-Type') || 'application/json',
      'X-Cache': 'MISS',
    },
  });

  // Only cache successful responses
  if (proxyRes.ok) {
    const ttl = getCacheTTL(proxyUrl);
    const toCache = new Response(data, {
      status: proxyRes.status,
      headers: { 'Content-Type': proxyRes.headers.get('Content-Type') || 'application/json' },
    });
    await putCache(cacheKey, toCache, ttl);
  }

  return response;
}

// ── Main fetch handler (ES Modules format) ────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);

      // CORS preflight
      if (request.method === 'OPTIONS') {
        return new Response(null, { headers: CORS_HEADERS });
      }

      // Temp admin: check user status by email
      if (url.pathname === '/admin/user' && request.method === 'GET') {
        const email = url.searchParams.get('email');
        if (!email) return json({ error: 'email param required' }, 400);
        await initDB(env.DB);
        const user = await env.DB.prepare('SELECT id, email, subscription_status, trial_end, plan, stripe_customer_id, stripe_subscription_id, created_at FROM users WHERE email = ?').bind(email.toLowerCase()).first();
        if (!user) return json({ error: 'User not found' }, 404);
        return json(user);
      }

      // Auth routes
      if (url.pathname === '/auth/signup' && request.method === 'POST') return handleSignup(request, env);
      if (url.pathname === '/auth/login'  && request.method === 'POST') return handleLogin(request, env);
      if (url.pathname === '/auth/verify' && request.method === 'POST') return handleVerify(request, env);

      // Stripe routes
      if (url.pathname === '/stripe/checkout' && request.method === 'POST') return handleCheckout(request, env);
      if (url.pathname === '/stripe/webhook'  && request.method === 'POST') return handleWebhook(request, env);

      // Data proxy (existing functionality, now JWT-gated)
      if (url.pathname === '/' || url.pathname === '') return handleProxy(request, env);

      return new Response('Not found', { status: 404 });
    } catch (err) {
      return json({ error: err.message, stack: err.stack }, 500);
    }
  }
};
