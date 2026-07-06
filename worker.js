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

// \u2500\u2500 Server-side LEAPS-chain scoring for MSL + Synthetic Long \u2500\u2500
// Ports the frontend runMslPhase3 / runSynthPhase3 logic exactly so dashboard
// cards match the analyzers, without the client needing to fetch chains (phase 3).
function scoreMslChains(price, mr, expiry, dte, callChain, putChain) {
  const out = { chainScored: false, expiry: expiry, mr: mr,
    c1: !isNaN(mr) ? mr <= -2 : null, c2: null, c3: null, c4: dte >= 365, c5: null, c6: null, c7: null, c8: null,
    weighted: null, t1Pass: null, score: null, callRatio: null, netDebitPct: null, putCreditPct: null, riskRatio: null };
  if (!callChain || !callChain.strike || !putChain || !putChain.strike || !callChain.strike.length || !putChain.strike.length) return out;
  // Leg 1: sold ATM put \u2014 among strikes near ATM, prefer higher OI (round/even strike) for
  // roll-ability; closest-to-price is the tiebreak. Fallback: strict closest-to-price.
  const atmBand = price * 0.04;
  let soldPutIdx = -1, bestPutOI = -1, bestPutDist = Infinity;
  for (let sp = 0; sp < putChain.strike.length; sp++) {
    if (putChain.strike[sp] > price + 0.001) continue;
    const d1 = Math.abs(putChain.strike[sp] - price);
    if (d1 > atmBand) continue;
    const oi1 = (putChain.openInterest && putChain.openInterest[sp] != null) ? putChain.openInterest[sp] : 0;
    if (oi1 > bestPutOI || (oi1 === bestPutOI && d1 < bestPutDist)) { bestPutOI = oi1; bestPutDist = d1; soldPutIdx = sp; }
  }
  if (soldPutIdx < 0) {
    bestPutDist = Infinity;
    for (let sp0 = 0; sp0 < putChain.strike.length; sp0++) { const d0 = Math.abs(putChain.strike[sp0] - price); if (d0 < bestPutDist) { bestPutDist = d0; soldPutIdx = sp0; } }
  }
  if (soldPutIdx < 0) return out;
  const soldPutStrike = putChain.strike[soldPutIdx];
  const soldPutMid = putChain.mid ? putChain.mid[soldPutIdx] : null;
  // Leg 2: bought lower put \u2014 among strikes \u226542% credit AND within a width tolerance of Laura's
  // ~40-point (\u224820% of price) target, prefer higher OI; width-fit is the tiebreak.
  const targetWidth = price * 0.20; // her "$40 wide on a ~$200 stock", generalized to price
  const widthTol = price * 0.05;
  let boughtPutIdx = -1, bestBpOI = -1, bestDiff = Infinity;
  for (let bp = 0; bp < putChain.strike.length; bp++) {
    if (putChain.strike[bp] >= soldPutStrike) continue;
    const bpMid = putChain.mid ? putChain.mid[bp] : null;
    if (soldPutMid === null || bpMid === null || bpMid <= 0) continue; // skip no-bid/phantom strikes
    const sw = soldPutStrike - putChain.strike[bp]; if (sw <= 0) continue;
    const cp = (soldPutMid - bpMid) / sw * 100;
    if (cp < 42) continue;
    const wd = Math.abs(sw - targetWidth); if (wd > widthTol) continue;
    const oiBp = (putChain.openInterest && putChain.openInterest[bp] != null) ? putChain.openInterest[bp] : 0;
    if (oiBp > bestBpOI || (oiBp === bestBpOI && wd < bestDiff)) { bestBpOI = oiBp; bestDiff = wd; boughtPutIdx = bp; }
  }
  // Fallback 1: nothing within width tolerance \u2192 closest-width among \u226542% credit
  if (boughtPutIdx < 0) {
    bestDiff = Infinity;
    for (let bpf = 0; bpf < putChain.strike.length; bpf++) {
      if (putChain.strike[bpf] >= soldPutStrike) continue;
      const bpMidF = putChain.mid ? putChain.mid[bpf] : null;
      if (soldPutMid === null || bpMidF === null || bpMidF <= 0) continue;
      const swF = soldPutStrike - putChain.strike[bpf]; if (swF <= 0) continue;
      const cpF = (soldPutMid - bpMidF) / swF * 100;
      if (cpF >= 42) { const wdF = Math.abs(swF - targetWidth); if (wdF < bestDiff) { bestDiff = wdF; boughtPutIdx = bpf; } }
    }
  }
  // Fallback 2: closest to 50%
  if (boughtPutIdx < 0) {
    let closest50 = Infinity;
    for (let bp2 = 0; bp2 < putChain.strike.length; bp2++) {
      if (putChain.strike[bp2] >= soldPutStrike) continue;
      const bpMid2 = putChain.mid ? putChain.mid[bp2] : null;
      if (soldPutMid === null || bpMid2 === null) continue;
      const sw2 = soldPutStrike - putChain.strike[bp2]; if (sw2 <= 0) continue;
      const cp2 = (soldPutMid - bpMid2) / sw2 * 100;
      if (Math.abs(cp2 - 50) < closest50) { closest50 = Math.abs(cp2 - 50); boughtPutIdx = bp2; }
    }
  }
  if (boughtPutIdx < 0) return out;
  const boughtPutStrike = putChain.strike[boughtPutIdx];
  const boughtPutMid = putChain.mid ? putChain.mid[boughtPutIdx] : null;
  const spreadWidth = soldPutStrike - boughtPutStrike;
  const putSpreadCredit = (soldPutMid !== null && boughtPutMid !== null) ? soldPutMid - boughtPutMid : null;
  const putCreditPct = (putSpreadCredit !== null && spreadWidth > 0) ? (putSpreadCredit / spreadWidth * 100) : null;
  // Leg 3: deep ITM call \u2014 among calls in the 40\u201360% I/E band, prefer higher OI; closeness to
  // 50/50 is the tiebreak. Fallback: pure best-ratio (closest to 50/50).
  let bestCallIdx = -1, bestCallOI = -1, bestCallDiff = Infinity;
  for (let ci = 0; ci < callChain.strike.length; ci++) {
    if (callChain.strike[ci] >= price) continue;
    const cMid = callChain.mid ? callChain.mid[ci] : null;
    if (cMid === null || cMid <= 0) continue;
    const intrinsic = price - callChain.strike[ci];
    const extrinsic = cMid - intrinsic; if (extrinsic <= 0) continue;
    const ratioCi = intrinsic / cMid;
    if (ratioCi < 0.40 || ratioCi > 0.60) continue;
    const rd = Math.abs(ratioCi - 0.50);
    const oiCi = (callChain.openInterest && callChain.openInterest[ci] != null) ? callChain.openInterest[ci] : 0;
    if (oiCi > bestCallOI || (oiCi === bestCallOI && rd < bestCallDiff)) { bestCallOI = oiCi; bestCallDiff = rd; bestCallIdx = ci; }
  }
  if (bestCallIdx < 0) {
    bestCallDiff = Infinity;
    for (let cif = 0; cif < callChain.strike.length; cif++) {
      if (callChain.strike[cif] >= price) continue;
      const cMidF = callChain.mid ? callChain.mid[cif] : null;
      if (cMidF === null || cMidF <= 0) continue;
      const intrF = price - callChain.strike[cif];
      const extrF = cMidF - intrF; if (extrF <= 0) continue;
      const diffF = Math.abs((intrF / cMidF) - 0.50);
      if (diffF < bestCallDiff) { bestCallDiff = diffF; bestCallIdx = cif; }
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
  // SL comparison (ATM call nearest the sold-put strike)
  let slCallIdx = -1, slBest = Infinity;
  for (let s = 0; s < callChain.strike.length; s++) { const sd = Math.abs(callChain.strike[s] - soldPutStrike); if (sd < slBest) { slBest = sd; slCallIdx = s; } }
  const slCallMid = (slCallIdx >= 0 && callChain.mid) ? callChain.mid[slCallIdx] : null;
  const slNetDebit = (slCallMid !== null && soldPutMid !== null) ? slCallMid - soldPutMid : null;
  const slRisk = (slNetDebit !== null && soldPutStrike) ? (soldPutStrike + slNetDebit) : null;
  const mslRisk = (netDebit !== null && spreadWidth > 0) ? (netDebit + spreadWidth) : null;
  const riskRatio = (slRisk && slRisk > 0 && mslRisk !== null) ? (mslRisk / slRisk * 100) : null;
  out.c2 = putCreditPct !== null ? putCreditPct >= 42 : null;
  out.c3 = (callRatio !== null && !isNaN(callRatio)) ? (callRatio >= 0.40 && callRatio <= 0.60) : null;
  out.c5 = netDebitPct !== null ? netDebitPct <= 40 : null;
  out.c6 = callOI !== null ? callOI >= 500 : null;
  out.c7 = soldPutOI !== null ? soldPutOI >= 500 : null;
  out.c8 = riskRatio !== null ? riskRatio <= 60 : null;
  out.callRatio = callRatio; out.netDebitPct = netDebitPct; out.putCreditPct = putCreditPct; out.riskRatio = riskRatio;
  out.score = [out.c1, out.c2, out.c3, out.c4, out.c5, out.c8].filter(x => x === true).length;
  out.weighted = (out.c1 === true ? 2 : 0) + (out.c2 === true ? 2 : 0) + (out.c8 === true ? 2 : 0) +
                 (out.c3 === true ? 1 : 0) + (out.c5 === true ? 1 : 0) + (out.c4 === true ? 1 : 0);
  const oiHardReject = (callOI !== null && callOI < 10) || (soldPutOI !== null && soldPutOI < 25);
  out.t1Pass = (out.c1 === true && out.c2 === true && out.c8 === true && !oiHardReject);
  out.chainScored = true;
  return out;
}

function scoreSynthChains(price, mr, expiry, dte, callChain, putChain) {
  const out = { chainScored: false, expiry: expiry, dte: dte, mr: mr,
    c1: !isNaN(mr) ? mr <= -2 : null, c3: dte >= 540, c4: null, c5: null, c6: null, c7: null, ivRank: null, netCostPct: null, score: null };
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
  out.c4 = netCostPct !== null ? netCostPct <= 5 : null;
  out.c5 = slCall.oi !== null ? slCall.oi >= 500 : null;
  out.c6 = slPut.oi !== null ? slPut.oi >= 500 : null;
  out.c7 = (callSpreadPct !== null && putSpreadPct !== null) ? (callSpreadPct <= 10 && putSpreadPct <= 10) : null;
  out.score = [out.c1, out.c3, out.c4, out.c7].filter(x => x === true).length;
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

  // Phase 1: price + Mean Reversion + SMA (parallel)
  const [quoteData, tsData, smaData] = await Promise.all([
    cachedFetch('https://api.twelvedata.com/quote?symbol=' + ticker + '&apikey=' + env.TD_KEY),
    cachedFetch('https://api.twelvedata.com/time_series?symbol=' + ticker + '&interval=4h&outputsize=60&apikey=' + env.TD_KEY),
    cachedFetch('https://api.twelvedata.com/sma?symbol=' + ticker + '&interval=1day&time_period=200&outputsize=1&apikey=' + env.TD_KEY), // SMA stays daily (trend filter)
  ]);

  const price = parseFloat(quoteData.close || quoteData.price);
  const change = parseFloat(quoteData.change);
  const changePct = parseFloat(quoteData.percent_change);
  const week52H = parseFloat(quoteData.fifty_two_week?.high || quoteData.high);
  const week52L = parseFloat(quoteData.fifty_two_week?.low || quoteData.low);
  // Mean Reversion: Wilder RSI(14) → EMA(9) smooth → (val-50)/12.5 — matches James's indicator
  const tsVals = tsData.values || [];
  // Data-quality guard: reject thin or stale series so recently-surged / thinly-covered
  // names (where TwelveData's history lags the live quote) return NaN instead of a bogus MR.
  let meanRev = NaN;
  if (tsVals.length >= 30) {
    let stale = false;
    const newestStr = tsVals[0] && tsVals[0].datetime; // TwelveData returns newest-first
    if (newestStr) {
      const dp = String(newestStr).slice(0, 10).split('-'); // date only (tz-safe)
      if (dp.length === 3) {
        const barUTC   = Date.UTC(parseInt(dp[0]), parseInt(dp[1]) - 1, parseInt(dp[2]));
        const now      = new Date();
        const todayUTC = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
        if ((todayUTC - barUTC) / 86400000 > 5) stale = true; // newest bar older than ~5 days
      }
    }
    if (!stale) {
      const closes = tsVals.map(v => parseFloat(v.close)).reverse(); // oldest-first
      meanRev = calcMeanRev(closes);
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
    cachedFetch('https://api.twelvedata.com/atr?symbol=' + ticker + '&interval=1day&time_period=14&outputsize=30&apikey=' + env.TD_KEY).catch(() => ({ values: [] })),
  ]);

  const expirations = normalizeExpirations(expData.expirations || []);
  const atrSeries = (atrData.values || []).map(v => parseFloat(v.atr)).reverse();

  // CSP income trade: 30–45 DTE only (Laura OG, mirror of the MM45 call rule)
  let bestExpiry = findBestExpiry(expirations, 30, 45);
  if (!bestExpiry) bestExpiry = findBestExpiry(expirations, 25, 45);

  const dte = bestExpiry ? dteFromStr(bestExpiry) : null;
  const earningsRisk = bestExpiry ? earningsBeforeExpiry(ticker, bestExpiry) : null;
  let bestPremium = null, bestStrike = null, bestDelta = null, ivRank = null;

  if (bestExpiry) {
    try {
      const putChain = await cachedFetch(
        'https://api.marketdata.app/v1/options/chain/' + ticker + '/?expiration=' + bestExpiry + '&side=put&token=' + env.MD_TOKEN
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

  // ── Covered Call: score off the actual CALL chain + its own 30–45 expiry (matches the CC analyzer) ──
  // Laura OG income-call rules: 4H chart, +2 MR, 30–45 DTE, sell an OTM call (~8% OTM target).
  let ccExpiry = findBestExpiry(expirations, 30, 45) || findBestExpiry(expirations, 25, 45);
  let ccDte = ccExpiry ? dteFromStr(ccExpiry) : null;
  let ccEarnRisk = ccExpiry ? earningsBeforeExpiry(ticker, ccExpiry) : null;
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
  const mslCh   = scoreMslChains(price, meanRev, leapsExpiry, leapsDte, leapsCall, leapsPut);
  if (synthCh.ivRank !== null) ivRank = synthCh.ivRank; // match the analyzer's LEAPS-expiry IV rank
  const chainScored = synthCh.chainScored && mslCh.chainScored;

  const synthScore = synthCh.score !== null ? synthCh.score : [synthCh.c1, synthCh.c3, synthCh.c4, synthCh.c7].filter(x => x === true).length;
  const mslScore   = mslCh.score   !== null ? mslCh.score   : [mslCh.c1, mslCh.c2, mslCh.c3, mslCh.c4, mslCh.c5, mslCh.c8].filter(x => x === true).length;

  // Build response — grades + badge info + display data
  const putBadge = badgeInfo(putScore, 6, true);
  const ccBadge = badgeInfo(ccScore, 6, true);
  const synthBadge = badgeInfo(synthScore, 4, false);
  const mslBadge = badgeInfo(mslScore, 6, false);

  return {
    ticker,
    price, change, changePct, week52H, week52L, meanRev, weeklyMeanRev, sma200,
    ivRank, expiry: bestExpiry, dte, bestStrike, bestPremium, premPct, earningsRisk,
    atrSeries, chainScored, mslExpiry: leapsExpiry,
    // Covered-call-specific display data (its own expiry/strike/premium from the call chain)
    ccExpiry, ccDte, ccStrike, ccPremium, ccPremPct,
    put:   { score: putScore, total: 6, grade: scoreToGrade(putScore, 6), badge: putBadge, c1: put_c1, c2: put_c2, c3: put_c3, c4: put_c4, c5: put_c5, c6: put_c6, c7: put_c7 },
    cc:    { score: ccScore, total: 6, grade: scoreToGrade(ccScore, 6), badge: ccBadge, c1: cc_c1, c2: cc_c2, c3: cc_c3, c4: cc_c4, c5: cc_c5, c6: cc_c6, c7: cc_c7 },
    synth: { score: synthScore, total: 4, grade: scoreToGrade(synthScore, 4), badge: synthBadge, mr: synthCh.mr, netCostPct: synthCh.netCostPct,
             c1: synthCh.c1, c2: null, c3: synthCh.c3, c4: synthCh.c4, c5: synthCh.c5, c6: synthCh.c6, c7: synthCh.c7 },
    msl:   { score: mslScore, total: 6, grade: scoreToGrade(mslScore, 6), badge: mslBadge, weighted: mslCh.weighted, t1Pass: mslCh.t1Pass,
             mr: mslCh.mr, callRatio: mslCh.callRatio, netDebitPct: mslCh.netDebitPct, riskRatio: mslCh.riskRatio, expiry: mslCh.expiry,
             c1: mslCh.c1, c2: mslCh.c2, c3: mslCh.c3, c4: mslCh.c4, c5: mslCh.c5, c6: mslCh.c6, c7: mslCh.c7, c8: mslCh.c8 },
  };
}

// POST /api/scores — accepts { tickers: ["TSLA","NVDA"] }
// Enforces tier-based ticker restrictions
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

      // Data proxy (existing functionality, now JWT-gated)
      if (url.pathname === '/' || url.pathname === '') return handleProxy(request, env);

      return new Response('Not found', { status: 404 });
    } catch (err) {
      return json({ error: err.message, stack: err.stack }, 500);
    }
  }
};
