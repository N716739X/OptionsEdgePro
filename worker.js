// OptionsEdge Pro — Cloudflare Worker (ES Modules format)
// Handles: Auth (signup/login), Stripe checkout, JWT validation, API proxy, scoring engine

// ── Tier & ticker configuration ─────────────────────────────────────────────────
const IA11_TICKERS = ['TSLA','NVDA','AMD','MRVL','PLTR','ALAB','AVGO','MU','GOOG','SATS','NPPTF'];
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
    { sub: user.id, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, tier: user.tier || 'trial', sid: sessionId, exp: now + 86400 * 30 },
    env.JWT_SECRET
  );

  return json({ token, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, tier: user.tier || 'trial' });
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

  return json({ valid: true, email: user.email, status, trialEnd: user.trial_end, plan: user.plan, tier: user.tier || 'trial' });
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

// MarketData.app API token (options chain data)
const MD_TOKEN = 'VjFYQWlwZDVCZ2ZIMm9TV3BFcndIeGxZbkdBelNESGNDVzh2czBWaHF1Yz0';

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

function getCached(key) {
  const entry = responseCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) {
    responseCache.delete(key);
    return null;
  }
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
  if (payload.status === 'trialing' && payload.trialEnd < now) {
    return { error: json({ error: 'Trial expired — please subscribe to continue' }, 402) };
  }
  if (!['active', 'trialing'].includes(payload.status)) {
    return { error: json({ error: 'Subscription required' }, 402) };
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
    params.set('token', MD_TOKEN);
    for (const [k, v] of url.searchParams.entries()) {
      if (k !== 'path') params.set(k, v);
    }
    proxyUrl = 'https://api.marketdata.app/v1/' + mdPath + '?' + params.toString();
  } else if (target) {
    // TwelveData proxy: inject API key server-side so frontend never sees it
    proxyUrl = target;
    if (proxyUrl.includes('api.twelvedata.com')) {
      const tdUrl = new URL(proxyUrl);
      tdUrl.searchParams.set('apikey', TD_KEY);
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

  // ── Cache MISS — fetch from upstream ──
  const proxyRes = await fetch(proxyUrl, { headers: proxyHeaders });
  const data = await proxyRes.text();
  const contentType = proxyRes.headers.get('Content-Type') || 'application/json';

  // Cache successful responses
  if (proxyRes.ok || proxyRes.status === 203) {
    const ttl = getCacheTTL(proxyUrl);
    putCache(cacheKey, data, contentType, proxyRes.status, ttl);
  }

  return new Response(data, {
    status: proxyRes.status,
    headers: { ...CORS_HEADERS, 'Content-Type': contentType, 'X-Cache': 'MISS' },
  });
}

// ── Scoring engine (server-side — IP protection) ─────────────────────────────

const TD_KEY = '170a58b2c2094e3987e4289f4fe39a08';

// Hardcoded earnings dates — update periodically
const EARNINGS = {
  TSLA: '2026-04-22', NVDA: '2026-05-28', PLTR: '2026-05-05',
  AAPL: '2026-04-30', MSFT: '2026-04-29', AMZN: '2026-04-30',
  GOOG: '2026-04-29', META: '2026-04-23', AMD: '2026-04-29',
  COIN: '2026-05-08', MSTR: '2026-04-29', SQ: '2026-05-01',
  SNOW: '2026-05-28', SHOP: '2026-05-01', NET: '2026-05-01',
  CRWD: '2026-06-03', DDOG: '2026-05-06', SOFI: '2026-04-28',
};

async function fetchJSON(url, headers = {}) {
  const res = await fetch(url, { headers: { 'User-Agent': 'OptionsEdgePro/1.0', ...headers } });
  if (!res.ok && res.status !== 203) throw new Error('HTTP ' + res.status);
  return res.json();
}

// Mean Reversion: Wilder RSI(16) → EMA(12) smooth → (val-50)/8
function calcMeanRev(closes) {
  if (!closes || closes.length < 30) return NaN;
  const period = 16, emaP = 12, scale = 8;
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

function earningsBeforeExpiry(ticker, expiryStr) {
  const eDate = EARNINGS[ticker];
  if (!eDate) return false;
  const earningsDate = new Date(eDate);
  const expiryDate = new Date(expiryStr);
  const today = new Date();
  return earningsDate > today && earningsDate < expiryDate;
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

  // Phase 1: price + Mean Reversion + SMA (parallel)
  const [quoteData, tsData, smaData] = await Promise.all([
    cachedFetch('https://api.twelvedata.com/quote?symbol=' + ticker + '&apikey=' + TD_KEY),
    cachedFetch('https://api.twelvedata.com/time_series?symbol=' + ticker + '&interval=1day&outputsize=60&apikey=' + TD_KEY),
    cachedFetch('https://api.twelvedata.com/sma?symbol=' + ticker + '&interval=1day&time_period=200&outputsize=1&apikey=' + TD_KEY),
  ]);

  const price = parseFloat(quoteData.close || quoteData.price);
  const change = parseFloat(quoteData.change);
  const changePct = parseFloat(quoteData.percent_change);
  const week52H = parseFloat(quoteData.fifty_two_week?.high || quoteData.high);
  const week52L = parseFloat(quoteData.fifty_two_week?.low || quoteData.low);
  // Mean Reversion: Wilder RSI(16) → EMA(12) smooth → (val-50)/8
  const tsVals = tsData.values || [];
  const closes = tsVals.map(v => parseFloat(v.close)).reverse(); // oldest-first
  const meanRev = calcMeanRev(closes);
  const smaVals = smaData.values || [];
  const sma200 = parseFloat(smaVals.length > 0 ? smaVals[0].sma : (smaData.sma || NaN));

  // Weekly Mean Reversion for LEAPS/Synth
  let weeklyMeanRev = meanRev; // fallback to daily
  try {
    const wkData = await cachedFetch('https://api.twelvedata.com/time_series?symbol=' + ticker + '&interval=1week&outputsize=60&apikey=' + TD_KEY);
    const wkCloses = (wkData.values || []).map(v => parseFloat(v.close)).reverse();
    const wkMR = calcMeanRev(wkCloses);
    if (!isNaN(wkMR)) weeklyMeanRev = wkMR;
  } catch(e) { /* use daily as fallback */ }

  // Phase 2: expirations + ATR (parallel)
  const [expData, atrData] = await Promise.all([
    cachedFetch('https://api.marketdata.app/v1/options/expirations/' + ticker + '/?token=' + MD_TOKEN).catch(() => ({ expirations: [] })),
    cachedFetch('https://api.twelvedata.com/atr?symbol=' + ticker + '&interval=1day&time_period=14&outputsize=30&apikey=' + TD_KEY).catch(() => ({ values: [] })),
  ]);

  const expirations = normalizeExpirations(expData.expirations || []);
  const atrSeries = (atrData.values || []).map(v => parseFloat(v.atr)).reverse();

  let bestExpiry = findBestExpiry(expirations, 30, 50);
  if (!bestExpiry) bestExpiry = findBestExpiry(expirations, 25, 60);

  const dte = bestExpiry ? dteFromStr(bestExpiry) : null;
  const earningsRisk = bestExpiry ? earningsBeforeExpiry(ticker, bestExpiry) : null;
  let bestPremium = null, bestStrike = null, bestDelta = null, ivRank = null;

  if (bestExpiry) {
    try {
      const putChain = await cachedFetch(
        'https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + bestExpiry + '&side=put&token=' + MD_TOKEN
      );

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

  // ── Score all 4 strategies ──
  const put_c1 = ivRank !== null ? ivRank > 80 : null;
  const put_c2 = !isNaN(meanRev) ? meanRev <= -2 : null;
  const put_c3 = !isNaN(sma200) ? price > sma200 : null;  // Price above 200 SMA (confirmed uptrend)
  const put_c4 = earningsRisk === null ? null : !earningsRisk;
  const put_c5 = premPct !== null ? premPct > 2 : null;
  const put_c6 = deltaOk;
  const put_c7 = dte !== null ? (dte >= 30 && dte <= 45) : null;
  const putScore = [put_c1, put_c2, put_c3, put_c4, put_c5, put_c6, put_c7].filter(x => x === true).length;

  const cc_c1 = ivRank !== null ? ivRank > 80 : null;
  const cc_c2 = !isNaN(meanRev) ? meanRev >= 2 : null;
  const cc_c3 = !isNaN(sma200) ? price > sma200 : null;  // Price above 200 SMA (confirmed uptrend)
  const cc_c4 = earningsRisk === null ? null : !earningsRisk;
  const cc_c5 = premPct !== null ? premPct >= 2 : null;
  const cc_c6 = deltaOk;
  const cc_c7 = dte !== null ? (dte >= 30 && dte <= 45) : null;
  const ccScore = [cc_c1, cc_c2, cc_c3, cc_c4, cc_c5, cc_c6, cc_c7].filter(x => x === true).length;

  const hasLeapsExp = expirations.some(e => dteFromStr(e) >= 540);
  const leaps_c1 = ivRank !== null ? ivRank < 55 : null;           // IV < 55% (Buy Low IV)
  const leaps_c2 = null;                                            // Intrinsic/Extrinsic ~50/50 (need chain)
  const leaps_c3 = null;                                            // Strike Deep ITM Δ 0.70-0.90 (need chain)
  const leaps_c4 = hasLeapsExp;                                     // Duration 18+ months
  const leaps_c5 = !isNaN(weeklyMeanRev) ? weeklyMeanRev <= -2 : null; // MR ≤ -2σ Weekly
  const leaps_c6 = null;                                            // OI >= 300 (need chain)
  const leaps_c7 = null;                                            // Bid/Ask Spread <= 10% (need chain)
  const leapsScore = [leaps_c1, leaps_c2, leaps_c3, leaps_c4, leaps_c5, leaps_c6, leaps_c7].filter(x => x === true).length;

  // Synth: James-aligned same-strike synthetic long
  const hasSynthExp = expirations.some(e => dteFromStr(e) >= 540);
  const synth_c1 = !isNaN(weeklyMeanRev) ? weeklyMeanRev <= -2 : null; // MR ≤ -2σ Weekly
  const synth_c2 = ivRank !== null ? ivRank > 50 : null;          // IV > 50%
  const synth_c3 = hasSynthExp;                                   // Duration >= 540 DTE
  const synth_c4 = null;                                          // Net Debit <= 5% (need chain)
  const synth_c5 = null;                                          // Call OI >= 300 (need chain)
  const synth_c6 = null;                                          // Put OI >= 300 (need chain)
  const synth_c7 = null;                                          // Spreads <= 10% (need chain)
  const synthScore = [synth_c1, synth_c2, synth_c3, synth_c4, synth_c5, synth_c6, synth_c7].filter(x => x === true).length;

  // Gut Spread: same criteria as Synth (chain-dependent ones scored in Phase 3 on frontend)
  const gut_c1 = synth_c1; // MR ≤ -2σ Weekly
  const gut_c2 = synth_c2; // IV > 50%
  const gut_c3 = synth_c3; // Duration >= 540 DTE
  const gut_c4 = null;     // Net Debit ≤ 5% (need chain — scored in Phase 3)
  const gut_c5 = null;     // Call OI ≥ 300 (need chain)
  const gut_c6 = null;     // Put OI ≥ 300 (need chain)
  const gut_c7 = null;     // Spreads ≤ 10% (need chain)
  const gutScore = [gut_c1, gut_c2, gut_c3, gut_c4, gut_c5, gut_c6, gut_c7].filter(x => x === true).length;

  // Build response — grades + badge info + display data (no raw scoring logic exposed)
  const putBadge = badgeInfo(putScore, 7, true);
  const ccBadge = badgeInfo(ccScore, 7, true);
  const leapsBadge = badgeInfo(leapsScore, 7, false);
  const synthBadge = badgeInfo(synthScore, 7, false);
  const gutBadge = badgeInfo(gutScore, 7, false);

  return {
    ticker,
    price, change, changePct, week52H, week52L, meanRev, weeklyMeanRev, sma200,
    ivRank, expiry: bestExpiry, dte, bestStrike, bestPremium, premPct, earningsRisk,
    atrSeries,
    put:   { score: putScore, total: 7, grade: scoreToGrade(putScore, 7), badge: putBadge, c1: put_c1, c2: put_c2, c3: put_c3, c4: put_c4, c5: put_c5, c6: put_c6, c7: put_c7 },
    cc:    { score: ccScore, total: 7, grade: scoreToGrade(ccScore, 7), badge: ccBadge, c1: cc_c1, c2: cc_c2, c3: cc_c3, c4: cc_c4, c5: cc_c5, c6: cc_c6, c7: cc_c7 },
    leaps: { score: leapsScore, total: 7, grade: scoreToGrade(leapsScore, 7), badge: leapsBadge, c1: leaps_c1, c2: leaps_c2, c3: leaps_c3, c4: leaps_c4, c5: leaps_c5, c6: leaps_c6, c7: leaps_c7 },
    synth: { score: synthScore, total: 7, grade: scoreToGrade(synthScore, 7), badge: synthBadge, c1: synth_c1, c2: synth_c2, c3: synth_c3, c4: synth_c4, c5: synth_c5, c6: synth_c6, c7: synth_c7 },
    gut:   { score: gutScore, total: 7, grade: scoreToGrade(gutScore, 7), badge: gutBadge, c1: gut_c1, c2: gut_c2, c3: gut_c3, c4: gut_c4, c5: gut_c5, c6: gut_c6, c7: gut_c7 },
  };
}

// POST /api/scores — accepts { tickers: ["TSLA","NVDA"] }
// Enforces tier-based ticker restrictions
async function handleScores(req, env) {
  const authCheck = await requireAuth(req, env);
  if (authCheck.error) return authCheck.error;

  await initDB(env.DB);
  const user = await env.DB.prepare('SELECT tier FROM users WHERE id = ?').bind(authCheck.payload.sub).first();
  const userTier = (user && user.tier) || 'trial';
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

  // Score all allowed tickers in parallel
  const results = await Promise.all(
    allowedTickers.map(async (t) => {
      try {
        return await scoreTicker(t, env);
      } catch (e) {
        return { ticker: t, error: e.message };
      }
    })
  );

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

      // Data proxy (existing functionality, now JWT-gated)
      if (url.pathname === '/' || url.pathname === '') return handleProxy(request, env);

      return new Response('Not found', { status: 404 });
    } catch (err) {
      return json({ error: err.message, stack: err.stack }, 500);
    }
  }
};
