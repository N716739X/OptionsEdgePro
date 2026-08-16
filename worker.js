// OptionsEdge Pro — Cloudflare Worker (ES Modules format)
// Handles: Auth (signup/login), Stripe checkout, JWT validation, API proxy, scoring engine

// ── Tier & ticker configuration ─────────────────────────────────────────────────
// Admin emails get full Trader-tier access regardless of subscription status
const ADMIN_EMAILS = ['mattdavis@whiskerseeker.com'];
const IA11_TICKERS = ['TSLA','NVDA','AMD','MRVL','PLTR','ALAB','AVGO','MU','GOOG','SATS'];
const TIER_LIMITS = {
  ia:     { tickers: IA11_TICKERS, maxCustom: 0,  maxTotal: 11 },
  trader: { tickers: IA11_TICKERS, maxCustom: 14, maxTotal: 25 },
  trial:  { tickers: IA11_TICKERS, maxCustom: 0,  maxTotal: 11 },
};

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
    "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER NOT NULL, stripe_customer_id TEXT, stripe_subscription_id TEXT, subscription_status TEXT DEFAULT 'inactive', trial_end INTEGER, plan TEXT, session_id TEXT, tier TEXT DEFAULT 'trial')"
  ).run();
  // Add columns if missing (existing tables)
  await db.prepare("ALTER TABLE users ADD COLUMN session_id TEXT").run().catch(() => {});
  await db.prepare("ALTER TABLE users ADD COLUMN tier TEXT DEFAULT 'trial'").run().catch(() => {});
  // Cache table for last-known chain data (survives weekends/market closed)
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS chain_cache (ticker TEXT PRIMARY KEY, iv_rank REAL, best_strike REAL, best_premium REAL, best_delta REAL, prem_pct REAL, earnings_risk INTEGER, updated_at INTEGER)"
  ).run();
  // Trailing ~52-week ATM implied-vol samples, for a TRUE IV Rank (implied vol vs its own history).
  await db.prepare(
    "CREATE TABLE IF NOT EXISTS iv_history (ticker TEXT NOT NULL, sample_date TEXT NOT NULL, atm_iv REAL, PRIMARY KEY (ticker, sample_date))"
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
  const sessionId = crypto.randomUUID();
  const now = Math.floor(Date.now() / 1000);
  const trialEnd = now + (7 * 24 * 60 * 60); // 7 days

  await env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, salt, created_at, subscription_status, trial_end, session_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, email.toLowerCase(), hash, salt, now, 'trialing', trialEnd, sessionId).run();

  const token = await signJWT(
    { sub: id, email: email.toLowerCase(), status: 'trialing', trialEnd, sid: sessionId, exp: now + 86400 * 30 },
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

  // Generate new session — invalidates any previous session
  const sessionId = crypto.randomUUID();
  await env.DB.prepare('UPDATE users SET session_id = ? WHERE id = ?').bind(sessionId, user.id).run();

  const token = await signJWT(
    { sub: user.id, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, tier: ADMIN_EMAILS.includes((user.email||'').toLowerCase()) ? 'trader' : (user.tier || 'trial'), sid: sessionId, exp: now + 86400 * 30 },
    env.JWT_SECRET
  );

  return json({ token, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, tier: ADMIN_EMAILS.includes((user.email||'').toLowerCase()) ? 'trader' : (user.tier || 'trial') });
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

  return json({ valid: true, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, tier: ADMIN_EMAILS.includes((user.email||'').toLowerCase()) ? 'trader' : (user.tier || 'trial') });
}

// POST /stripe/checkout
async function handleCheckout(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return json({ error: 'Unauthorized' }, 401);

  const { tier, plan, successUrl, cancelUrl } = await req.json();
  // tier: 'ia' or 'trader', plan: 'monthly' or 'annual'
  let priceId;
  if (tier === 'trader') {
    priceId = plan === 'annual' ? env.STRIPE_TRADER_ANNUAL_PRICE : env.STRIPE_TRADER_MONTHLY_PRICE;
  } else {
    priceId = plan === 'annual' ? env.STRIPE_ANNUAL_PRICE : env.STRIPE_MONTHLY_PRICE;
  }

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
    'metadata[tier]': tier || 'ia',
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
    const tier = session.metadata?.tier || 'ia';
    if (userId) {
      // Determine plan from amount_total (in cents)
      // Monthly: $24.95 = 2495c, $34.95 = 3495c  |  Annual: $249 = 24900c, $349 = 34900c
      // Trial starts: amount_total = 0 (7-day free trial on subscription)
      const amt = session.amount_total || 0;
      const plan = (amt === 24900 || amt === 34900) ? 'annual' : 'monthly';

      await env.DB.prepare(
        'UPDATE users SET stripe_customer_id = ?, stripe_subscription_id = ?, subscription_status = ?, plan = ?, tier = ? WHERE id = ?'
      ).bind(
        session.customer,
        session.subscription,
        'active',
        plan,
        tier,
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

// MarketData.app API token (options chain data) — provided via env.MD_TOKEN (Cloudflare secret)

// ── Response cache (shared across all users within same isolate) ──────────────
// In-memory Map cache: all requests in the same Worker isolate share this.
// Cloudflare Workers keep isolates alive for seconds to minutes between
// requests, so high-traffic periods get excellent cache hit rates.
const CACHE_TTL_STOCK = 5 * 60 * 1000;   // 5 minutes for stock quotes/MR/SMA
const CACHE_TTL_OPTIONS = 15 * 60 * 1000; // 15 minutes for options chains/expirations
const responseCache = new Map(); // key -> { data, contentType, status, expires }

function getCacheTTL(proxyUrl) {
  if (proxyUrl.includes('api.marketdata.app')) return CACHE_TTL_OPTIONS;
  return CACHE_TTL_STOCK;
}

const MAX_STALE = 24 * 60 * 60 * 1000; // serve stale-on-quota up to 24h old, then give up

function getCached(key) {
  const entry = responseCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) return null; // not fresh — but keep it for quota fallback
  return entry;
}
// Last-known value regardless of freshness (used only when upstream is quota-limited).
function getStale(key) {
  const entry = responseCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires + MAX_STALE) { responseCache.delete(key); return null; }
  return entry;
}

function putCache(key, data, contentType, status, ttl) {
  // Cap cache size at 500 entries to prevent memory issues
  if (responseCache.size > 500) {
    const oldest = responseCache.keys().next().value;
    responseCache.delete(oldest);
  }
  responseCache.set(key, { data, contentType, status, expires: Date.now() + ttl });
}

async function requireAuth(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  const payload = await verifyJWT(token, env.JWT_SECRET);

  if (!payload) return { error: json({ error: 'Unauthorized — please log in' }, 401) };

  const now = Math.floor(Date.now() / 1000);
  // Admin emails bypass the subscription/trial gate entirely (they always get
  // full Trader-tier access — see tier assignment at login/verify).
  const isAdmin = ADMIN_EMAILS.includes((payload.email || '').toLowerCase());
  if (!isAdmin) {
    if (payload.status === 'trialing' && payload.trialEnd < now) {
      return { error: json({ error: 'Trial expired — please subscribe to continue' }, 402) };
    }
    if (!['active', 'trialing'].includes(payload.status)) {
      return { error: json({ error: 'Subscription required' }, 402) };
    }
  }

  // Single-session enforcement: verify session_id matches DB
  if (payload.sid) {
    await initDB(env.DB);
    const user = await env.DB.prepare('SELECT session_id FROM users WHERE id = ?').bind(payload.sub).first();
    if (user && user.session_id && user.session_id !== payload.sid) {
      return { error: json({ error: 'Session expired — your account was logged in elsewhere. Please log in again.' }, 403) };
    }
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
    params.set('token', env.MD_TOKEN);
    for (const [k, v] of url.searchParams.entries()) {
      if (k !== 'path') params.set(k, v);
    }
    proxyUrl = 'https://api.marketdata.app/v1/' + mdPath + '?' + params.toString();
  } else if (target) {
    // TwelveData proxy: inject API key server-side so frontend never sees it
    proxyUrl = target;
    if (proxyUrl.includes('api.twelvedata.com')) {
      const tdUrl = new URL(proxyUrl);
      tdUrl.searchParams.set('apikey', env.TD_KEY);
      proxyUrl = tdUrl.toString();
    }
  }

  // ── Check cache before hitting upstream API ──
  const cacheKey = proxyUrl;
  const cached = getCached(cacheKey);
  if (cached) {
    return new Response(cached.data, {
      status: cached.status,
      headers: {
        ...CORS_HEADERS,
        'Content-Type': cached.contentType,
        'X-Cache': 'HIT',
      },
    });
  }

  // ── Cache MISS — fetch from upstream (retry once on a transient 429 burst) ──
  let proxyRes = await fetch(proxyUrl, { headers: proxyHeaders });
  if (proxyRes.status === 429) {
    await new Promise(r => setTimeout(r, 400));
    proxyRes = await fetch(proxyUrl, { headers: proxyHeaders });
  }
  const data = await proxyRes.text();
  const contentType = proxyRes.headers.get('Content-Type') || 'application/json';

  // Cache successful responses
  if (proxyRes.ok || proxyRes.status === 203) {
    putCache(cacheKey, data, contentType, proxyRes.status, getCacheTTL(proxyUrl));
    return new Response(data, {
      status: proxyRes.status,
      headers: { ...CORS_HEADERS, 'Content-Type': contentType, 'X-Cache': 'MISS' },
    });
  }

  // Quota / rate-limit (402 = credits exhausted, 429 = too many requests): serve the last-known
  // value if we have one, so the app degrades to stale data instead of a hard error.
  if (proxyRes.status === 402 || proxyRes.status === 429) {
    const stale = getStale(cacheKey);
    if (stale) {
      return new Response(stale.data, {
        status: stale.status,
        headers: { ...CORS_HEADERS, 'Content-Type': stale.contentType, 'X-Cache': 'STALE-QUOTA' },
      });
    }
  }

  return new Response(data, {
    status: proxyRes.status,
    headers: { ...CORS_HEADERS, 'Content-Type': contentType, 'X-Cache': 'MISS' },
  });
}

// ── Scoring engine (server-side — IP protection) ─────────────────────────────

// TwelveData API key — provided via env.TD_KEY (Cloudflare secret)

// Hardcoded earnings dates — update periodically
const EARNINGS = {
  TSLA: '2026-04-22', NVDA: '2026-05-28', PLTR: '2026-05-05',
  AAPL: '2026-04-30', MSFT: '2026-04-29', AMZN: '2026-04-30',
  GOOG: '2026-04-29', META: '2026-04-23', AMD: '2026-04-29',
  COIN: '2026-05-08', MSTR: '2026-07-30', SQ: '2026-05-01',
  SNOW: '2026-05-28', SHOP: '2026-05-01', NET: '2026-05-01',
  CRWD: '2026-06-03', DDOG: '2026-05-06', SOFI: '2026-04-28',
  MRVL: '2026-05-28', ALAB: '2026-05-05', AVGO: '2026-06-04',
  MU: '2026-06-24', SATS: '2026-05-08',
};

async function fetchJSON(url, headers = {}, attempt = 0) {
  const res = await fetch(url, { headers: { 'User-Agent': 'OptionsEdgePro/1.0', ...headers } });
  // Retry transient rate-limit responses with a short backoff (scan fires several
  // option-chain calls per ticker, so bursts can briefly hit the upstream limit).
  if (res.status === 429 && attempt < 3) {
    await new Promise(r => setTimeout(r, 300 * (attempt + 1)));
    return fetchJSON(url, headers, attempt + 1);
  }
  if (!res.ok && res.status !== 203) throw new Error('HTTP ' + res.status);
  return res.json();
}

// Run an async fn over items with a bounded concurrency (keeps the dashboard
// scan from firing every ticker's option-chain calls at once and rate-limiting).
async function mapLimit(items, limit, fn) {
  const results = new Array(items.length);
  let idx = 0;
  async function worker() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i], i);
    }
  }
  const workers = [];
  for (let w = 0; w < Math.min(limit, items.length); w++) workers.push(worker());
  await Promise.all(workers);
  return results;
}

// Mean Reversion: Wilder RSI(14) → EMA(9) smooth → (val-50)/12.5
// Calibrated to James's InvestAnswers IA-Mean-Reversion on 4H/RTH.
// scale=12.5 maps RSI to ±4, with OB/OS ±2 bands at RSI 75/25.
// Fit from live chart pairs (smoothed RSI, MR): MRVL 48.09/-0.149, NVDA 38.05/-0.972 → scale ~12.3-12.8.
function calcMeanRev(closes) {
  if (!closes || closes.length < 30) return NaN;
  const period = 14, emaP = 9, scale = 12.5;
  const gains = [], losses = [];
  for (let i = 1; i < closes.length; i++) {
    const diff = closes[i] - closes[i - 1];
    gains.push(Math.max(0, diff));
    losses.push(Math.max(0, -diff));
  }
  let avgG = 0, avgL = 0;
  for (let j = 0; j < period; j++) { avgG += gains[j]; avgL += losses[j]; }
  avgG /= period; avgL /= period;
  const rsiSeries = [];
  for (let k = period; k < gains.length; k++) {
    avgG = (avgG * (period - 1) + gains[k]) / period;
    avgL = (avgL * (period - 1) + losses[k]) / period;
    rsiSeries.push(avgL === 0 ? 100 : 100 - (100 / (1 + avgG / avgL)));
  }
  if (rsiSeries.length < emaP) return NaN;
  const mult = 2 / (emaP + 1);
  let ema = rsiSeries[0];
  for (let m = 1; m < rsiSeries.length; m++) {
    ema = (rsiSeries[m] - ema) * mult + ema;
  }
  return (ema - 50) / scale;
}

// Aggregate TwelveData 30-min bars (newest-first, ET datetimes) into 4H closes,
// oldest-first. 4H buckets anchor to the ET clock (…04:00/08:00/12:00/16:00/20:00),
// so extended-hours bars are included — matching the ETH 4H chart James's Mean-BT
// uses. Each 4H close = the close of the last 30-min bar inside its bucket.
function aggregate30mTo4h(vals) {
  const buckets = {};
  for (let i = 0; i < vals.length; i++) {
    const dt = vals[i] && vals[i].datetime;
    if (!dt) continue;
    const c = parseFloat(vals[i].close);
    if (isNaN(c)) continue;
    let hh = parseInt(String(dt).slice(11, 13), 10);
    if (isNaN(hh)) hh = 0;
    const key = String(dt).slice(0, 10) + '_' + (Math.floor(hh / 4) * 4);
    const ex = buckets[key];
    if (!ex || dt > ex.dt) buckets[key] = { dt, close: c }; // latest sub-bar = bucket close
  }
  return Object.keys(buckets)
    .sort((a, b) => (buckets[a].dt < buckets[b].dt ? -1 : 1))
    .map(k => buckets[k].close);
}

// True if the newest bar (newest-first series) is older than ~5 days — feed lagging.
function mrSeriesStale(newestStr) {
  if (!newestStr) return false;
  const dp = String(newestStr).slice(0, 10).split('-');
  if (dp.length !== 3) return false;
  const barUTC   = Date.UTC(parseInt(dp[0]), parseInt(dp[1]) - 1, parseInt(dp[2]));
  const now      = new Date();
  const todayUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return (todayUTC - barUTC) / 86400000 > 5;
}

// Set once per isolate if the ETH (prepost) fetch proves unavailable — extended hours
// needs TwelveData Pro; on Grow/lower the request errors. After the first failure we
// fetch RTH 4h directly instead of burning a wasted prepost call on every ticker.
let mrEthUnavailable = false;

// Restrict an option chain to "round" strikes so the MSL never picks an off-round strike
// (e.g. 325/335 beside the 320/330/340 ladder). Mirrors frontend mslFilterRoundStrikes:
// largest increment (10, then 5) that leaves ≥6 strikes and prunes some; else untouched.
function mslFilterRoundStrikes(chain, price) {
  if (!chain || !Array.isArray(chain.strike) || !chain.strike.length) return chain;
  const strikes = chain.strike.filter(s => s != null);
  const isMult = (s, g) => Math.abs(s / g - Math.round(s / g)) < 1e-6;
  let chosen = 0;
  for (const g of [10, 5]) {
    const n = strikes.filter(s => isMult(s, g)).length;
    if (n >= 6 && n < strikes.length) { chosen = g; break; }
  }
  if (!chosen) return chain;
  const keep = [];
  for (let i = 0; i < chain.strike.length; i++) {
    if (chain.strike[i] != null && isMult(chain.strike[i], chosen)) keep.push(i);
  }
  const out = {};
  Object.keys(chain).forEach(k => {
    out[k] = Array.isArray(chain[k]) && chain[k].length === chain.strike.length
      ? keep.map(idx => chain[k][idx])
      : chain[k];
  });
  return out;
}

function dteFromStr(dateStr) {
  if (!dateStr) return null;
  const parts = dateStr.split('-');
  if (parts.length !== 3) return null;
  const exp = new Date(Date.UTC(parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2])));
  const now = new Date();
  const todayUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.round((exp - todayUTC) / 86400000);
}

// Normalize: shift Thursday expiry dates to Friday to match broker displays
function normalizeExpiry(dateStr) {
  const d = new Date(dateStr + 'T12:00:00Z');
  if (d.getUTCDay() === 4) { // Thursday
    d.setUTCDate(d.getUTCDate() + 1);
    const y = d.getUTCFullYear();
    const m = String(d.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(d.getUTCDate()).padStart(2, '0');
    return y + '-' + m + '-' + dd;
  }
  return dateStr;
}
function normalizeExpirations(arr) { return arr.map(normalizeExpiry); }

function isThirdFriday(dateStr) {
  const d = new Date(dateStr + 'T00:00:00Z');
  if (d.getUTCDay() !== 5) return false;
  const day = d.getUTCDate();
  return day >= 15 && day <= 21;
}

function findBestExpiry(expirations, minDTE, maxDTE) {
  const candidates = expirations.filter(e => {
    const d = dteFromStr(e);
    return d !== null && d >= minDTE && d <= maxDTE;
  });
  const monthly = candidates.filter(isThirdFriday);
  if (monthly.length > 0) return monthly[0];
  if (candidates.length > 0) return candidates[0];
  return null;
}

// true = earnings before expiry, false = confident next earnings is after expiry,
// null = UNKNOWN (no date, or the stored date is already in the past → next one unknown).
// null must NOT read as "clear" — the hardcoded table goes stale, so unknown means "verify".
function earningsBeforeExpiry(ticker, expiryStr) {
  const eDate = EARNINGS[ticker];
  if (!eDate) return null;
  const earningsDate = new Date(eDate);
  const expiryDate = new Date(expiryStr);
  const today = new Date();
  if (!(earningsDate > today)) return null; // stored date is stale → next one unknown
  return earningsDate < expiryDate;
}

function scoreToGrade(score, total) {
  const pct = total > 0 ? (score / total) * 100 : 0;
  if (pct >= 90) return 'A';
  if (pct >= 75) return 'B';
  if (pct >= 55) return 'C';
  if (pct >= 35) return 'D';
  return 'F';
}

function badgeInfo(score, total, isScored) {
  const pct = total > 0 ? (score / total) * 100 : 0;
  if (pct >= 75) return { cls: 'badge-ideal', txt: 'IDEAL \u00b7 ' + score + '/' + total };
  if (pct >= 40) return { cls: 'badge-watch', txt: 'WATCH \u00b7 ' + score + '/' + total };
  return { cls: 'badge-notready', txt: (isScored ? 'NO TRADE' : 'WAIT') + ' \u00b7 ' + score + '/' + total };
}

// \u2500\u2500 Server-side LEAPS-chain scoring for MSL + Synthetic Long \u2500\u2500
// Ports the frontend runMslPhase3 / runSynthPhase3 logic exactly so dashboard
// cards match the analyzers, without the client needing to fetch chains (phase 3).
function scoreMslChains(price, mr, expiry, dte, callChain, putChain, week52H) {
  const out = { chainScored: false, expiry: expiry, mr: mr,
    c1: !isNaN(mr) ? mr <= -2 : null, c2: null, c3: null, c4: dte >= 365, c5: null, c6: null, c7: null, c8: null, c9: null,
    weighted: null, t1Pass: null, score: null, callRatio: null, netDebitPct: null, putCreditPct: null, riskRatio: null,
    threeXFail: null, target3x: null, move3xPct: null };
  if (!callChain || !callChain.strike || !putChain || !putChain.strike || !callChain.strike.length || !putChain.strike.length) return out;
  callChain = mslFilterRoundStrikes(callChain, price);
  putChain = mslFilterRoundStrikes(putChain, price);
  // Bull put spread — ATM-anchored (Course 301): SELL the ATM put, BUY a lower put so width ~20%
  // of price (10-30% band), credit >=42% of width (50% ideal). Mirrors frontend mslPickPutSpread.
  let soldPutIdx = -1, boughtPutIdx = -1;
  {
    const pstrike = putChain.strike, pmid = putChain.mid || [], poi = putChain.openInterest || [];
    let sBest = Infinity;
    for (let i = 0; i < pstrike.length; i++) {
      if (pstrike[i] == null || pmid[i] == null || pmid[i] <= 0) continue;
      const d = Math.abs(pstrike[i] - price);
      if (d < sBest) { sBest = d; soldPutIdx = i; }
    }
    if (soldPutIdx >= 0) {
      const Sk = pstrike[soldPutIdx], Sm = pmid[soldPutIdx];
      const minW = price * 0.10, maxW = price * 0.30, targetW = price * 0.20, FLOOR = 42;
      let best = null;
      for (let li = 0; li < pstrike.length; li++) {
        const Lk = pstrike[li], Lm = pmid[li];
        if (Lk == null || Lm == null || Lm <= 0 || Lk >= Sk) continue;
        const w = Sk - Lk; if (w < minW || w > maxW) continue;
        const c = { li, cr: (Sm - Lm) / w * 100, wdiff: Math.abs(w - targetW), oi: (poi[li] != null ? poi[li] : 0) };
        if (!best) { best = c; continue; }
        const aOk = c.cr >= FLOOR, bOk = best.cr >= FLOOR;
        if (aOk !== bOk) { if (aOk) best = c; continue; }
        if (Math.abs(c.wdiff - best.wdiff) > 1e-9) { if (c.wdiff < best.wdiff) best = c; continue; }
        if (c.cr !== best.cr) { if (c.cr > best.cr) best = c; continue; }
        if (c.oi > best.oi) best = c;
      }
      boughtPutIdx = best ? best.li : -1;
      if (boughtPutIdx < 0) soldPutIdx = -1;
    }
  }
  if (soldPutIdx < 0 || boughtPutIdx < 0) return out;
  const soldPutStrike = putChain.strike[soldPutIdx];
  const soldPutMid = putChain.mid ? putChain.mid[soldPutIdx] : null;
  const boughtPutStrike = putChain.strike[boughtPutIdx];
  const boughtPutMid = putChain.mid ? putChain.mid[boughtPutIdx] : null;
  const spreadWidth = soldPutStrike - boughtPutStrike;
  const putSpreadCredit = (soldPutMid !== null && boughtPutMid !== null) ? soldPutMid - boughtPutMid : null;
  const putCreditPct = (putSpreadCredit !== null && spreadWidth > 0) ? (putSpreadCredit / spreadWidth * 100) : null;
  // Leg 3: deep ITM call \u2014 prefer higher OI, but only WITHIN the ideal 45\u201355% I/E band first, so
  // a marginally-more-liquid strike can't drag the pick off 50/50. Widen to the 40\u201360% pass band
  // only if the ideal band is empty; final fallback = pure closest-to-50/50.
  const pickCall = (lo, hi) => {
    let idx = -1, oiBest = -1, dBest = Infinity;
    for (let ci = 0; ci < callChain.strike.length; ci++) {
      if (callChain.strike[ci] >= price) continue;
      const cMid = callChain.mid ? callChain.mid[ci] : null;
      if (cMid === null || cMid <= 0) continue;
      const intr = price - callChain.strike[ci];
      const extr = cMid - intr; if (extr <= 0) continue;
      const r = intr / cMid;
      if (r < lo || r > hi) continue;
      const d = Math.abs(r - 0.50);
      const oi = (callChain.openInterest && callChain.openInterest[ci] != null) ? callChain.openInterest[ci] : 0;
      if (oi > oiBest || (oi === oiBest && d < dBest)) { oiBest = oi; dBest = d; idx = ci; }
    }
    return idx;
  };
  let bestCallIdx = pickCall(0.45, 0.55);                    // ideal band, OI-weighted
  if (bestCallIdx < 0) bestCallIdx = pickCall(0.40, 0.60);   // widen to pass band, OI-weighted
  if (bestCallIdx < 0) {                                     // final fallback: pure closest-to-50/50
    let dBest2 = Infinity;
    for (let cif = 0; cif < callChain.strike.length; cif++) {
      if (callChain.strike[cif] >= price) continue;
      const cMidF = callChain.mid ? callChain.mid[cif] : null;
      if (cMidF === null || cMidF <= 0) continue;
      const intrF = price - callChain.strike[cif];
      const extrF = cMidF - intrF; if (extrF <= 0) continue;
      const diffF = Math.abs((intrF / cMidF) - 0.50);
      if (diffF < dBest2) { dBest2 = diffF; bestCallIdx = cif; }
    }
  }
  if (bestCallIdx < 0) return out;
  const callStrike = callChain.strike[bestCallIdx];
  const callMid = callChain.mid[bestCallIdx];
  const callRatio = (price - callStrike) / callMid;
  const callOI = callChain.openInterest ? callChain.openInterest[bestCallIdx] : null;
  const soldPutOI = putChain.openInterest ? putChain.openInterest[soldPutIdx] : null;
  const netDebit = (callMid !== null && putSpreadCredit !== null) ? callMid - putSpreadCredit : null;
  const netDebitPct = (netDebit !== null && price) ? (netDebit / price * 100) : null;
  // SL comparison (MM56): the SAME deep-ITM call + a short ATM put (no protective lower put).
  let atmPutIdx = -1, atmBest = Infinity;
  for (let s = 0; s < putChain.strike.length; s++) { const sd = Math.abs(putChain.strike[s] - price); if (sd < atmBest) { atmBest = sd; atmPutIdx = s; } }
  const slPutStrike = atmPutIdx >= 0 ? putChain.strike[atmPutIdx] : null;
  const slPutMid = (atmPutIdx >= 0 && putChain.mid) ? putChain.mid[atmPutIdx] : null;
  const slNetDebit = (callMid !== null && slPutMid !== null) ? callMid - slPutMid : null;
  const slRisk = (slNetDebit !== null && slPutStrike) ? (slPutStrike + slNetDebit) : null;
  const mslRisk = (netDebit !== null && spreadWidth > 0) ? (netDebit + spreadWidth) : null;
  const riskRatio = (slRisk && slRisk > 0 && mslRisk !== null) ? (mslRisk / slRisk * 100) : null;
  // MM60 risk gate: MSL risk ≤ 50% of owning the stock (price per share), not vs the synthetic long.
  const riskVsStockPct = (mslRisk !== null && price) ? (mslRisk / price * 100) : null;
  out.c2 = putCreditPct !== null ? putCreditPct >= 42 : null;
  out.c3 = (callRatio !== null && !isNaN(callRatio)) ? (callRatio >= 0.40 && callRatio <= 0.60) : null;
  out.c5 = netDebitPct !== null ? netDebitPct <= 45 : null; // net debit sanity cap (course MSLs run 24-42%); ≤33% = ideal
  out.c6 = callOI !== null ? callOI >= 500 : null;
  out.c7 = soldPutOI !== null ? soldPutOI >= 500 : null;
  out.c8 = riskVsStockPct !== null ? riskVsStockPct <= 50 : null; // MM60: ≤ 50% of owning stock
  out.c9 = (putSpreadCredit !== null && price) ? ((putSpreadCredit / price * 100) >= 6) : null; // credit ≥6% of stock price
  out.callRatio = callRatio; out.netDebitPct = netDebitPct; out.putCreditPct = putCreditPct; out.riskRatio = riskRatio; out.riskVsStockPct = riskVsStockPct;
  // Laura's 3x test: price for a 3x return = call strike + 3 x per-share risk. Flag when that
  // sits above the 52-wk high (upside proxy) — reward is thin at this entry (caps the grade).
  const target3x = (mslRisk !== null && callStrike != null) ? (callStrike + 3 * mslRisk) : null;
  out.target3x = target3x;
  out.move3xPct = (target3x !== null && price) ? ((target3x / price - 1) * 100) : null;
  out.threeXFail = (target3x !== null && week52H) ? (target3x > week52H) : null;
  out.score = [out.c1, out.c2, out.c3, out.c4, out.c5, out.c8, out.c9].filter(x => x === true).length;
  out.weighted = (out.c1 === true ? 2 : 0) + (out.c2 === true ? 2 : 0) + (out.c8 === true ? 2 : 0) +
                 (out.c3 === true ? 1 : 0) + (out.c5 === true ? 1 : 0) + (out.c4 === true ? 1 : 0) + (out.c9 === true ? 1 : 0);
  const oiHardReject = (callOI !== null && callOI < 10) || (soldPutOI !== null && soldPutOI < 25);
  out.t1Pass = (out.c1 === true && out.c2 === true && out.c8 === true && !oiHardReject);
  out.chainScored = true;
  return out;
}

// ── True IV Rank ────────────────────────────────────────────────────────────────
// Laura's "don't buy LEAPS when IV is inflated" needs IMPLIED vol ranked over ~1 year.
// We sample ~30-day ATM IV weekly from MarketData's historical chains (cached in D1) and
// rank today's ATM IV within that window — E*Trade's IV Rank definition. Everything here is
// best-effort: any failure falls back to the caller's cross-strike proxy so scoring never breaks.
const IV_HIST_DAYS = 365, IV_MIN_SAMPLES = 20, IV_BACKFILL_MAX = 10, IV_BACKFILL_BATCH = 5;
function _ivYmd(d) { return d.getUTCFullYear() + '-' + ('0'+(d.getUTCMonth()+1)).slice(-2) + '-' + ('0'+d.getUTCDate()).slice(-2); }
// Most recent completed Friday on/before ms — a stable weekly grid (trading day) that doesn't drift day-to-day.
function _mostRecentFriday(ms) {
  const d = new Date(ms), back = (d.getUTCDay() + 2) % 7; // Fri->0, Sat->1, Sun->2, Mon->3, ...
  return new Date(d.getTime() - back * 86400000);
}
// ATM IV (%) = the IV of the strike nearest the underlying price.
function atmIvFromChain(chain, price) {
  if (!chain || !chain.strike || !chain.iv) return null;
  let px = price;
  if (px == null) px = Array.isArray(chain.underlyingPrice) ? chain.underlyingPrice[0] : chain.underlyingPrice;
  if (px == null || isNaN(px)) return null;
  let best = Infinity, iv = null;
  for (let i = 0; i < chain.strike.length; i++) {
    const s = chain.strike[i]; if (s == null) continue;
    const v = chain.iv[i]; if (v == null || isNaN(v) || v <= 0) continue;
    const d = Math.abs(s - px);
    if (d < best) { best = d; iv = v <= 1 ? v * 100 : v; }
  }
  return iv;
}
// 52 stable weekly Fridays over the trailing year — anchored to calendar Fridays (a trading day), NOT to
// "today", so the set doesn't shift day-to-day and backfill settles to empty once a ticker is seeded.
function ivSampleDates() {
  const out = [], f = _mostRecentFriday(Date.now() - 86400000);
  for (let w = 0; w < 52; w++) out.push(_ivYmd(new Date(f.getTime() - w * 7 * 86400000)));
  return out;
}
// Store a sample. iv may be null → stored as a "checked, no data" marker so weekends/holidays/empties
// aren't re-fetched forever (which would stall backfill on the same oldest missing dates every request).
async function recordAtmIv(env, ticker, dateStr, iv) {
  if (!env || !env.DB || !dateStr) return;
  const val = (iv == null || isNaN(iv)) ? null : iv;
  try { await env.DB.prepare("INSERT OR IGNORE INTO iv_history (ticker, sample_date, atm_iv) VALUES (?, ?, ?)").bind(ticker, dateStr, val).run(); } catch (e) {}
}
// Bounded, best-effort backfill of missing weekly ATM-IV samples from historical ~30-DTE chains.
async function backfillIvHistory(env, ticker, max) {
  if (!env || !env.DB) return;
  let have = new Set();
  try {
    const rows = await env.DB.prepare("SELECT sample_date FROM iv_history WHERE ticker = ?").bind(ticker).all();
    ((rows && rows.results) || []).forEach(r => have.add(r.sample_date));
  } catch (e) { return; }
  const missing = ivSampleDates().filter(d => !have.has(d)).slice(0, max || IV_BACKFILL_MAX);
  if (!missing.length) return;
  // Throttled batches — one successful refresh seeds the year without a huge parallel burst.
  for (let i = 0; i < missing.length; i += IV_BACKFILL_BATCH) {
    const batch = missing.slice(i, i + IV_BACKFILL_BATCH);
    await Promise.all(batch.map(async (dateStr) => {
      const ch = await cachedFetch('https://api.marketdata.app/v1/options/chain/' + ticker + '/?date=' + dateStr + '&dte=30&side=put&token=' + env.MD_TOKEN).catch(() => null);
      if (ch == null) return; // fetch failed (rate limit / network) — leave the date missing so it retries next time
      await recordAtmIv(env, ticker, dateStr, atmIvFromChain(ch, null)); // real response → store the IV, or a null marker (holiday/no-data)
    }));
  }
}
// IV-rank state: {rank, source, samples}. Records today's ATM IV, then ranks it within the trailing 52
// weeks once >= IV_MIN_SAMPLES real samples exist. Under-seeded → source 'proxy' (caller keeps its proxy).
async function ivRankState(env, ticker, todayIv) {
  if (!env || !env.DB || todayIv == null || isNaN(todayIv)) return { rank: null, source: 'proxy', samples: 0 };
  try {
    await recordAtmIv(env, ticker, _ivYmd(new Date()), todayIv);
    const since = _ivYmd(new Date(Date.now() - IV_HIST_DAYS * 86400000));
    const rows = await env.DB.prepare("SELECT atm_iv FROM iv_history WHERE ticker = ? AND sample_date >= ? AND atm_iv IS NOT NULL").bind(ticker, since).all();
    const vals = (((rows && rows.results) || []).map(r => r.atm_iv)).filter(v => v != null && !isNaN(v) && v > 0);
    const samples = vals.length;
    if (samples < IV_MIN_SAMPLES) return { rank: null, source: 'proxy', samples };
    let lo = Infinity, hi = -Infinity;
    for (const v of vals) { if (v < lo) lo = v; if (v > hi) hi = v; }
    const rank = hi > lo ? Math.min(100, Math.max(0, (todayIv - lo) / (hi - lo) * 100)) : 50;
    return { rank, source: 'true', samples };
  } catch (e) { return { rank: null, source: 'proxy', samples: 0 }; }
}

function scoreSynthChains(price, mr, expiry, dte, callChain, putChain) {
  const out = { chainScored: false, expiry: expiry, dte: dte, mr: mr,
    c1: !isNaN(mr) ? mr <= -2 : null, c2: null, c3: dte >= 540, c4: null, c5: null, c6: null, c7: null, ivRank: null, netCostPct: null, score: null };
  let slCall = null, slPut = null;
  if (callChain && callChain.strike && putChain && putChain.strike) {
    const putMap = {};
    for (let pi = 0; pi < putChain.strike.length; pi++) putMap[putChain.strike[pi]] = pi;
    let bestDist = Infinity, bestCI = -1, bestPI = -1;
    for (let i = 0; i < callChain.strike.length; i++) {
      const sk = callChain.strike[i];
      if (!(sk in putMap)) continue;
      const dist = Math.abs(sk - price);
      if (dist < bestDist) { bestDist = dist; bestCI = i; bestPI = putMap[sk]; }
    }
    if (bestCI >= 0) {
      slCall = { mid: callChain.mid ? callChain.mid[bestCI] : null, bid: callChain.bid ? callChain.bid[bestCI] : null, ask: callChain.ask ? callChain.ask[bestCI] : null, oi: callChain.openInterest ? callChain.openInterest[bestCI] : null };
      slPut  = { mid: putChain.mid ? putChain.mid[bestPI] : null, bid: putChain.bid ? putChain.bid[bestPI] : null, ask: putChain.ask ? putChain.ask[bestPI] : null, oi: putChain.openInterest ? putChain.openInterest[bestPI] : null };
    }
  }
  if (!slCall || !slPut) return out;
  const netCost = (slCall.mid !== null && slPut.mid !== null) ? slCall.mid - slPut.mid : null;
  const netCostPct = (netCost !== null && price) ? (netCost / price * 100) : null;
  const callSpread = (slCall.bid !== null && slCall.ask !== null) ? slCall.ask - slCall.bid : null;
  const putSpread = (slPut.bid !== null && slPut.ask !== null) ? slPut.ask - slPut.bid : null;
  const callSpreadPct = (callSpread !== null && slCall.mid) ? (callSpread / slCall.mid * 100) : null;
  const putSpreadPct = (putSpread !== null && slPut.mid) ? (putSpread / slPut.mid * 100) : null;
  if (putChain && putChain.iv && putChain.iv.length > 0) {
    const ivs = [];
    for (let k = 0; k < putChain.iv.length; k++) { const v = putChain.iv[k]; if (v !== null && v !== undefined && !isNaN(v) && v > 0) ivs.push(v <= 1 ? v * 100 : v); }
    if (ivs.length > 0) { ivs.sort((a, b) => a - b); const atmIV = ivs[Math.floor(ivs.length / 2)]; const range = ivs[ivs.length - 1] - ivs[0]; out.ivRank = range > 0 ? Math.min(100, Math.max(0, (atmIV - ivs[0]) / range * 100)) : 50; }
  }
  out.netCostPct = netCostPct;
  out.c2 = out.ivRank !== null ? out.ivRank <= 50 : null; // IV not inflated (Laura: don't buy LEAPS at high IV); ≤30 = ideal
  out.c4 = netCostPct !== null ? netCostPct <= 8 : null; // course SLs run ~5.5–7.5% of price
  out.c5 = slCall.oi !== null ? slCall.oi >= 500 : null;
  out.c6 = slPut.oi !== null ? slPut.oi >= 500 : null;
  out.c7 = (callSpreadPct !== null && putSpreadPct !== null) ? (callSpreadPct <= 10 && putSpreadPct <= 10) : null;
  out.score = [out.c1, out.c2, out.c3, out.c4, out.c7].filter(x => x === true).length;
  out.chainScored = true;
  return out;
}

async function scoreTicker(ticker, env) {
  // Use internal cache for upstream API calls
  async function cachedFetch(url) {
    const cacheKey = url;
    const cached = getCached(cacheKey);
    if (cached) return JSON.parse(cached.data);
    const data = await fetchJSON(url);
    const dataStr = JSON.stringify(data);
    const ttl = url.includes('api.marketdata.app') ? CACHE_TTL_OPTIONS : CACHE_TTL_STOCK;
    putCache(cacheKey, dataStr, 'application/json', 200, ttl);
    return data;
  }

  // Phase 1: price + Mean Reversion + SMA (parallel).
  // &country=United States pins the US listing — some symbols are multi-exchange (e.g. SPCX
  // lists on NASDAQ + Swiss SIX + Canadian CDRs), and TwelveData 400s on an ambiguous symbol.
  const TD_COUNTRY = '&country=United%20States';
  // Quote is essential; time_series (MR) and SMA-200 degrade gracefully. A just-IPO'd stock
  // (e.g. SPCX) has no 200-day history, so TwelveData errors on the SMA — catch it → no value
  // (criteria show neutral) instead of failing the whole card.
  // MR source: ETH 30-min (aggregated to 4H) when prepost is available (TwelveData Pro),
  // else RTH 4h. Once prepost has failed this isolate, go straight to RTH.
  const mrTsUrl = mrEthUnavailable
    ? 'https://api.twelvedata.com/time_series?symbol=' + ticker + '&interval=4h&outputsize=60' + TD_COUNTRY + '&apikey=' + env.TD_KEY
    : 'https://api.twelvedata.com/time_series?symbol=' + ticker + '&interval=30min&outputsize=500&prepost=true&timezone=America%2FNew_York' + TD_COUNTRY + '&apikey=' + env.TD_KEY;
  const [quoteData, tsData, smaData] = await Promise.all([
    cachedFetch('https://api.twelvedata.com/quote?symbol=' + ticker + TD_COUNTRY + '&apikey=' + env.TD_KEY),
    cachedFetch(mrTsUrl).catch(() => ({ values: [] })),
    cachedFetch('https://api.twelvedata.com/sma?symbol=' + ticker + '&interval=1day&time_period=200&outputsize=1' + TD_COUNTRY + '&apikey=' + env.TD_KEY).catch(() => ({ values: [] })), // SMA stays daily (trend filter)
  ]);

  const price = parseFloat(quoteData.close || quoteData.price);
  const change = parseFloat(quoteData.change);
  const changePct = parseFloat(quoteData.percent_change);
  const week52H = parseFloat(quoteData.fifty_two_week?.high || quoteData.high);
  const week52L = parseFloat(quoteData.fifty_two_week?.low || quoteData.low);
  // Mean Reversion: Wilder RSI(14) → EMA(9) smooth → (val-50)/12.5 — matches James's indicator.
  // Preferred source is ETH 30-min bars aggregated into 4H (James/Laura read Mean-BT on the
  // ETH chart); falls back to RTH 4h when prepost is unavailable (non-Pro plan). Scale=12.5
  // is a 4H calibration and holds for both.
  // Data-quality guard: reject thin or stale series so recently-surged / thinly-covered
  // names (where TwelveData's history lags the live quote) return NaN instead of a bogus MR.
  const tsVals = tsData.values || [];
  let meanRev = NaN;
  const minBars = mrEthUnavailable ? 30 : 60;
  if (tsVals.length >= minBars && !mrSeriesStale(tsVals[0] && tsVals[0].datetime)) {
    const closes = mrEthUnavailable
      ? tsVals.map(v => parseFloat(v.close)).reverse() // RTH 4h: closes are already 4H, oldest-first
      : aggregate30mTo4h(tsVals);                      // ETH 30-min → oldest-first 4H closes
    if (closes.length >= 30) meanRev = calcMeanRev(closes);
  }
  // ETH attempt yielded nothing (prepost unavailable on this plan) → remember + fall back to RTH 4h.
  if (isNaN(meanRev) && !mrEthUnavailable) {
    mrEthUnavailable = true;
    const rth = await cachedFetch('https://api.twelvedata.com/time_series?symbol=' + ticker + '&interval=4h&outputsize=60' + TD_COUNTRY + '&apikey=' + env.TD_KEY).catch(() => ({ values: [] }));
    const rv = rth.values || [];
    if (rv.length >= 30 && !mrSeriesStale(rv[0] && rv[0].datetime)) {
      meanRev = calcMeanRev(rv.map(v => parseFloat(v.close)).reverse());
    }
  }
  const smaVals = smaData.values || [];
  const sma200 = parseFloat(smaVals.length > 0 ? smaVals[0].sma : (smaData.sma || NaN));

  // All strategies use 4H Mean Reversion — James's scale (RSI14/EMA9/scale25)
  // weeklyMeanRev alias kept for backward compat with scoring fields below
  const weeklyMeanRev = meanRev; // same 4H value — no separate weekly fetch needed

  // Phase 2: expirations + ATR (parallel)
  const [expData, atrData] = await Promise.all([
    cachedFetch('https://api.marketdata.app/v1/options/expirations/' + ticker + '/?token=' + env.MD_TOKEN).catch(() => ({ expirations: [] })),
    cachedFetch('https://api.twelvedata.com/atr?symbol=' + ticker + '&interval=1day&time_period=14&outputsize=30' + TD_COUNTRY + '&apikey=' + env.TD_KEY).catch(() => ({ values: [] })),
  ]);

  const expirations = normalizeExpirations(expData.expirations || []);
  const atrSeries = (atrData.values || []).map(v => parseFloat(v.atr)).reverse();

  // CSP income trade: 30–45 DTE only (Laura OG, mirror of the MM45 call rule)
  let bestExpiry = findBestExpiry(expirations, 30, 45);
  if (!bestExpiry) bestExpiry = findBestExpiry(expirations, 25, 45);

  const dte = bestExpiry ? dteFromStr(bestExpiry) : null;

  // Next earnings: prefer the EXACT Earnings Calendar (Grow plan); fall back to estimating from the
  // /earnings history + quarterly cadence. No country filter (fundamentals endpoints reject it).
  // Cached 12h (not the 5-min stock TTL) — earnings dates change rarely; avoids burning credits.
  // Any failure → null so the criterion shows "verify", never a false "clear".
  let nextEarnings = null;
  try {
    const _ymd = d => d.getFullYear() + '-' + ('0'+(d.getMonth()+1)).slice(-2) + '-' + ('0'+d.getDate()).slice(-2);
    const _t = new Date(), _e = new Date(_t.getTime() + 400 * 86400000), todayStr = _ymd(_t);
    const EARN_TTL = 12 * 60 * 60 * 1000;
    const fetchCached = async (url) => {
      const c = getCached(url);
      if (c) return JSON.parse(c.data);
      const d = await fetchJSON(url).catch(() => null);
      if (d) putCache(url, JSON.stringify(d), 'application/json', 200, EARN_TTL);
      return d;
    };
    const entries = (data) => {
      if (!data) return [];
      if (Array.isArray(data)) return data;
      const e = data.earnings;
      if (Array.isArray(e)) return e;
      if (e && typeof e === 'object') { let o = []; for (const k of Object.keys(e)) { const v = e[k]; if (Array.isArray(v)) o = o.concat(v); else if (v && v.date) o.push(v); } return o; }
      return [];
    };
    // 1) exact calendar
    const calUrl = 'https://api.twelvedata.com/earnings_calendar?symbol=' + ticker + '&start_date=' + todayStr + '&end_date=' + _ymd(_e) + '&apikey=' + env.TD_KEY;
    const futs = entries(await fetchCached(calUrl)).map(x => x && x.date).filter(x => typeof x === 'string' && x >= todayStr).sort();
    if (futs.length) nextEarnings = futs[0];
    // 2) estimate from history
    if (!nextEarnings) {
      const eUrl = 'https://api.twelvedata.com/earnings?symbol=' + ticker + '&outputsize=8&apikey=' + env.TD_KEY;
      const ds = entries(await fetchCached(eUrl)).map(x => x && x.date).filter(x => typeof x === 'string').sort();
      if (ds.length >= 2) {
        const gaps = [];
        for (let i = 1; i < ds.length; i++) gaps.push((new Date(ds[i]) - new Date(ds[i-1])) / 86400000);
        gaps.sort((a,b) => a-b);
        const med = gaps[Math.floor(gaps.length/2)] || 91;
        let nx = new Date(ds[ds.length-1]), g = 0;
        while (nx <= _t && g++ < 12) nx = new Date(nx.getTime() + med * 86400000);
        nextEarnings = _ymd(nx);
      }
    }
  } catch (e) { nextEarnings = null; }

  const earningsRisk = (bestExpiry && nextEarnings) ? (nextEarnings < bestExpiry) : null;
  let bestPremium = null, bestStrike = null, bestDelta = null, ivRank = null, todayAtmIv = null;

  if (bestExpiry) {
    try {
      const putChain = await cachedFetch(
        'https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + bestExpiry + '&side=put&token=' + env.MD_TOKEN
      );

      // Today's ~30-day ATM IV — the current point for the true IV Rank (E*Trade uses ~30d IV).
      todayAtmIv = atmIvFromChain(putChain, price);

      // IV rank from chain
      if (putChain?.iv?.length > 0) {
        const ivs = putChain.iv.filter(v => v !== null && v !== undefined && !isNaN(v) && v > 0)
          .map(v => v <= 1 ? v * 100 : v).sort((a, b) => a - b);
        if (ivs.length > 0) {
          const atmIV = ivs[Math.floor(ivs.length / 2)];
          const ivRange = ivs[ivs.length - 1] - ivs[0];
          ivRank = ivRange > 0 ? Math.min(100, Math.max(0, (atmIV - ivs[0]) / ivRange * 100)) : 50;
        }
      }

      // Best strike near delta 0.20
      if (putChain?.strike) {
        let bestDiff = Infinity;
        for (let i = 0; i < putChain.strike.length; i++) {
          const delta = putChain.delta ? putChain.delta[i] : null;
          if (delta === null) continue;
          const diff = Math.abs(Math.abs(delta) - 0.20);
          if (diff < bestDiff) {
            bestDiff = diff;
            bestStrike = putChain.strike[i];
            bestDelta = delta;
            bestPremium = putChain.mid ? putChain.mid[i] : null;
          }
        }
      }
    } catch (e) { /* options unavailable */ }
  }

  // If chain returned valid data, persist to D1 for weekend/off-hours fallback
  if (ivRank !== null && env?.DB) {
    try {
      await env.DB.prepare(
        "INSERT OR REPLACE INTO chain_cache (ticker, iv_rank, best_strike, best_premium, best_delta, prem_pct, earnings_risk, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(ticker, ivRank, bestStrike, bestPremium, bestDelta,
        (bestPremium && price) ? (bestPremium / price * 100) : null,
        earningsRisk === null ? null : (earningsRisk ? 1 : 0),
        Date.now()
      ).run();
    } catch (e) { /* cache write failed — non-critical */ }
  }

  // If chain returned no IV data, fall back to last-known cached values from D1
  if (ivRank === null && env?.DB) {
    try {
      const cached = await env.DB.prepare(
        "SELECT iv_rank, best_strike, best_premium, best_delta, prem_pct, earnings_risk FROM chain_cache WHERE ticker = ?"
      ).bind(ticker).first();
      if (cached && cached.iv_rank !== null) {
        ivRank = cached.iv_rank;
        if (bestStrike === null) bestStrike = cached.best_strike;
        if (bestPremium === null) bestPremium = cached.best_premium;
        if (bestDelta === null) bestDelta = cached.best_delta;
      }
    } catch (e) { /* cache read failed — non-critical */ }
  }

  const premPct = (bestPremium && price) ? (bestPremium / price * 100) : null;
  const deltaOk = bestDelta !== null && Math.abs(bestDelta) >= 0.15 && Math.abs(bestDelta) <= 0.25;

  // ── Covered Call: score off the actual CALL chain + its own 30–45 expiry (matches the CC analyzer) ──
  // Laura OG income-call rules: 4H chart, +2 MR, 30–45 DTE, sell an OTM call (~8% OTM target).
  let ccExpiry = findBestExpiry(expirations, 30, 45) || findBestExpiry(expirations, 25, 45);
  let ccDte = ccExpiry ? dteFromStr(ccExpiry) : null;
  let ccEarnRisk = (ccExpiry && nextEarnings) ? (nextEarnings < ccExpiry) : null;
  let ccStrike = null, ccDelta = null, ccPremium = null;
  if (ccExpiry) {
    try {
      const callChain = await cachedFetch(
        'https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + ccExpiry + '&side=call&token=' + env.MD_TOKEN
      );
      if (callChain?.strike) {
        // Laura OG (MM13): sell at overhead resistance (~9% OTM), taking whatever
        // delta comes with it. Anchor on % OTM with a wide delta band so high-IV
        // names aren't pushed far OTM by a tight delta cap.
        const targetOTM = price * 1.09; // ~9% OTM (resistance proxy)
        let bd = Infinity;
        for (let i = 0; i < callChain.strike.length; i++) {
          const dl = callChain.delta ? callChain.delta[i] : null;
          if (dl === null) continue;
          if (dl < 0.10 || dl > 0.55) continue; // wide band — resistance strike, not a delta target
          const dif = Math.abs(callChain.strike[i] - targetOTM);
          if (dif < bd) { bd = dif; ccStrike = callChain.strike[i]; ccDelta = dl; ccPremium = callChain.mid ? callChain.mid[i] : null; }
        }
      }
    } catch (e) { /* options unavailable */ }
  }
  const ccPremPct = (ccPremium && price) ? (ccPremium / price * 100) : null;
  const ccUpside = (ccStrike && price) ? ((ccStrike - price) / price * 100) : null;
  const ccOtmOk = ccUpside !== null ? (ccUpside >= 5 && ccUpside <= 12) : null; // near a resistance level (~8–10%)

  // ── Score all 4 strategies ──
  const put_c1 = null; // IV Rank is not one of the CSP analyzer's 6 criteria
  const put_c2 = !isNaN(meanRev) ? meanRev <= -2 : null; // Laura OG (mirror of MM45 calls): −2 MR (Deeply Oversold), 4H
  const put_c3 = !isNaN(sma200) ? price > sma200 : null;  // Price above 200 SMA (confirmed uptrend)
  const put_c4 = earningsRisk === null ? null : !earningsRisk;
  const put_c5 = premPct !== null ? premPct > 2 : null;
  const put_c6 = deltaOk;
  const put_c7 = dte !== null ? (dte >= 30 && dte <= 45) : null;
  const putScore = [put_c2, put_c3, put_c4, put_c5, put_c6, put_c7].filter(x => x === true).length;

  const cc_c1 = null; // IV Rank is not one of the CC analyzer's 6 criteria
  const cc_c2 = !isNaN(meanRev) ? meanRev >= 2 : null; // Laura OG: +2 MR (Deeply Overbought), 4H
  const cc_c3 = !isNaN(sma200) ? price > sma200 : null;  // Price above 200 SMA (confirmed uptrend)
  const cc_c4 = ccEarnRisk === null ? null : !ccEarnRisk;
  const cc_c5 = ccPremPct !== null ? ccPremPct >= 2 : null; // premium from the CALL we'd sell
  const cc_c6 = ccOtmOk;                                    // strike 5–15% OTM (targets 8%)
  const cc_c7 = ccDte !== null ? (ccDte >= 30 && ccDte <= 45) : null;
  const ccScore = [cc_c2, cc_c3, cc_c4, cc_c5, cc_c6, cc_c7].filter(x => x === true).length;

  // ── Synth + MSL: LEAPS-chain scoring, server-side (replaces the old client phase-3) ──
  // Fetch the farthest LEAPS chain once and score both strategies from it, so the
  // dashboard cards populate without the client having to fetch chains and rate-limit.
  let leapsExps = expirations.filter(e => dteFromStr(e) >= 540);
  if (leapsExps.length === 0) leapsExps = expirations.filter(e => dteFromStr(e) >= 365);
  let leapsExpiry = null, leapsDte = null, leapsCall = null, leapsPut = null;
  if (leapsExps.length > 0) {
    leapsExps.sort((a, b) => dteFromStr(b) - dteFromStr(a));
    leapsExpiry = leapsExps[0];
    leapsDte = dteFromStr(leapsExpiry);
    try {
      const lc = await cachedFetch('https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + leapsExpiry + '&side=call&token=' + env.MD_TOKEN).catch(() => null);
      const lp = await cachedFetch('https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + leapsExpiry + '&side=put&token=' + env.MD_TOKEN).catch(() => null);
      leapsCall = lc; leapsPut = lp;
    } catch (e) { /* chain unavailable — falls back to un-scored (client phase-3) */ }
  }
  const synthCh = scoreSynthChains(price, weeklyMeanRev, leapsExpiry, leapsDte, leapsCall, leapsPut);
  const mslCh   = scoreMslChains(price, meanRev, leapsExpiry, leapsDte, leapsCall, leapsPut, week52H);
  if (synthCh.ivRank !== null) ivRank = synthCh.ivRank; // match the analyzer's LEAPS-expiry IV rank (proxy)
  // TRUE IV Rank (implied vol vs its own trailing 52 weeks) — Laura's "don't buy inflated IV". Overrides
  // the cross-strike proxy once enough history is seeded; otherwise leaves the proxy in place. Best-effort.
  let ivRankSource = 'proxy', ivSamples = 0;
  try {
    const tiv = await ivRankState(env, ticker, todayAtmIv);
    ivSamples = tiv.samples;
    if (tiv.source === 'true' && tiv.rank != null) {
      ivRank = tiv.rank;
      synthCh.ivRank = tiv.rank;
      synthCh.c2 = tiv.rank <= 50;
      synthCh.score = [synthCh.c1, synthCh.c2, synthCh.c3, synthCh.c4, synthCh.c7].filter(x => x === true).length;
      ivRankSource = 'true';
    }
    await backfillIvHistory(env, ticker); // bounded, best-effort — seeds future requests
  } catch (e) { /* keep the proxy */ }
  const chainScored = synthCh.chainScored && mslCh.chainScored;

  const synthScore = synthCh.score !== null ? synthCh.score : [synthCh.c1, synthCh.c2, synthCh.c3, synthCh.c4, synthCh.c7].filter(x => x === true).length;
  const mslScore   = mslCh.score   !== null ? mslCh.score   : [mslCh.c1, mslCh.c2, mslCh.c3, mslCh.c4, mslCh.c5, mslCh.c8, mslCh.c9].filter(x => x === true).length;

  // Build response — grades + badge info + display data
  const putBadge = badgeInfo(putScore, 6, true);
  const ccBadge = badgeInfo(ccScore, 6, true);
  const synthBadge = badgeInfo(synthScore, 5, false);
  const mslBadge = badgeInfo(mslScore, 7, false);

  return {
    ticker,
    price, change, changePct, week52H, week52L, meanRev, weeklyMeanRev, sma200,
    ivRank, ivRankSource, ivSamples, expiry: bestExpiry, dte, bestStrike, bestPremium, premPct, earningsRisk, nextEarnings,
    atrSeries, chainScored, mslExpiry: leapsExpiry,
    // Covered-call-specific display data (its own expiry/strike/premium from the call chain)
    ccExpiry, ccDte, ccStrike, ccPremium, ccPremPct,
    put:   { score: putScore, total: 6, grade: scoreToGrade(putScore, 6), badge: putBadge, c1: put_c1, c2: put_c2, c3: put_c3, c4: put_c4, c5: put_c5, c6: put_c6, c7: put_c7 },
    cc:    { score: ccScore, total: 6, grade: scoreToGrade(ccScore, 6), badge: ccBadge, c1: cc_c1, c2: cc_c2, c3: cc_c3, c4: cc_c4, c5: cc_c5, c6: cc_c6, c7: cc_c7 },
    synth: { score: synthScore, total: 5, grade: scoreToGrade(synthScore, 5), badge: synthBadge, mr: synthCh.mr, netCostPct: synthCh.netCostPct, ivRank: synthCh.ivRank, ivRankSource: ivRankSource,
             c1: synthCh.c1, c2: synthCh.c2, c3: synthCh.c3, c4: synthCh.c4, c5: synthCh.c5, c6: synthCh.c6, c7: synthCh.c7 },
    msl:   { score: mslScore, total: 7, grade: scoreToGrade(mslScore, 7), badge: mslBadge, weighted: mslCh.weighted, t1Pass: mslCh.t1Pass,
             mr: mslCh.mr, callRatio: mslCh.callRatio, netDebitPct: mslCh.netDebitPct, riskRatio: mslCh.riskRatio, riskVsStockPct: mslCh.riskVsStockPct, expiry: mslCh.expiry,
             threeXFail: mslCh.threeXFail, target3x: mslCh.target3x, move3xPct: mslCh.move3xPct,
             c1: mslCh.c1, c2: mslCh.c2, c3: mslCh.c3, c4: mslCh.c4, c5: mslCh.c5, c6: mslCh.c6, c7: mslCh.c7, c8: mslCh.c8, c9: mslCh.c9 },
  };
}

// POST /api/scores — accepts { tickers: ["TSLA","NVDA"] }
// Enforces tier-based ticker restrictions
// Fully seed one ticker's IV history in a single request (bounded to ~52 historical calls for THIS
// ticker — safe subrequest budget), then return its true IV Rank. Called automatically by the client
// in the background for each unseeded ticker, so users never wait through manual refreshes.
async function handleIvSeed(req, env) {
  const authCheck = await requireAuth(req, env);
  if (authCheck.error) return authCheck.error;
  await initDB(env.DB);
  const url = new URL(req.url);
  let ticker = (url.searchParams.get('ticker') || '').trim().toUpperCase();
  if (!ticker) { try { const b = await req.json(); ticker = ((b && b.ticker) || '').trim().toUpperCase(); } catch (e) {} }
  if (!ticker) return json({ error: 'ticker required' }, 400);
  try {
    // Today's ~30-day ATM IV from a near-dated put chain (the point we rank within the 52-week window).
    const expData = await cachedFetch('https://api.marketdata.app/v1/options/expirations/' + ticker + '/?token=' + env.MD_TOKEN).catch(() => ({ expirations: [] }));
    const expirations = normalizeExpirations(expData.expirations || []);
    const bestExpiry = findBestExpiry(expirations, 30, 45) || findBestExpiry(expirations, 25, 60);
    let todayAtmIv = null;
    if (bestExpiry) {
      const putChain = await cachedFetch('https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + bestExpiry + '&side=put&token=' + env.MD_TOKEN).catch(() => null);
      todayAtmIv = atmIvFromChain(putChain, null);
    }
    await backfillIvHistory(env, ticker, 52); // full year in one shot
    const st = await ivRankState(env, ticker, todayAtmIv);
    return json({ ticker, ivRank: st.rank, ivRankSource: st.source, ivSamples: st.samples });
  } catch (e) {
    return json({ ticker, error: e.message, ivRankSource: 'proxy', ivSamples: 0 });
  }
}

async function handleScores(req, env) {
  const authCheck = await requireAuth(req, env);
  if (authCheck.error) return authCheck.error;

  await initDB(env.DB);
  const user = await env.DB.prepare('SELECT tier, email FROM users WHERE id = ?').bind(authCheck.payload.sub).first();
  const userTier = (user && ADMIN_EMAILS.includes((user.email||'').toLowerCase())) ? 'trader' : ((user && user.tier) || 'trial');
  const tierConfig = TIER_LIMITS[userTier] || TIER_LIMITS.trial;

  const { tickers } = await req.json();
  if (!Array.isArray(tickers) || tickers.length === 0) return json({ error: 'tickers array required' }, 400);

  // Enforce ticker limits based on tier
  let allowedTickers;
  if (userTier === 'trader') {
    // Trader: IA11 + custom up to maxTotal (25)
    allowedTickers = tickers.slice(0, tierConfig.maxTotal).map(t => t.toUpperCase());
  } else {
    // IA Edition / Trial: only IA11 tickers allowed
    allowedTickers = tickers.map(t => t.toUpperCase()).filter(t => IA11_TICKERS.includes(t));
  }

  if (allowedTickers.length === 0) return json({ error: 'No permitted tickers for your plan', tier: userTier }, 403);

  // Score allowed tickers with bounded concurrency — each ticker makes several
  // upstream option-chain calls, so scoring all at once can trip the rate limit.
  const results = await mapLimit(allowedTickers, 5, async (t) => {
    try {
      return await scoreTicker(t, env);
    } catch (e) {
      return { ticker: t, error: e.message };
    }
  });

  return json({ scores: results, tier: userTier, allowedTickers });
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

      // Auth routes
      if (url.pathname === '/auth/signup' && request.method === 'POST') return handleSignup(request, env);
      if (url.pathname === '/auth/login'  && request.method === 'POST') return handleLogin(request, env);
      if (url.pathname === '/auth/verify' && request.method === 'POST') return handleVerify(request, env);

      // Stripe routes
      if (url.pathname === '/stripe/checkout' && request.method === 'POST') return handleCheckout(request, env);
      if (url.pathname === '/stripe/webhook'  && request.method === 'POST') return handleWebhook(request, env);

      // Server-side scoring (IP-protected scoring engine)
      if (url.pathname === '/api/scores' && request.method === 'POST') return handleScores(request, env);

      // Background IV-history seeding for one ticker (auto-called by the client)
      if (url.pathname === '/api/iv-seed') return handleIvSeed(request, env);

      // Data proxy (existing functionality, now JWT-gated)
      if (url.pathname === '/' || url.pathname === '') return handleProxy(request, env);

      return new Response('Not found', { status: 404 });
    } catch (err) {
      return json({ error: err.message, stack: err.stack }, 500);
    }
  }
};
