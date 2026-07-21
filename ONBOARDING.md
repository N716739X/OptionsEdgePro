# OptionsEdge Pro — Onboarding & Handoff

An options-scoring web app that implements the **Options Goddess (Laura OG) / InvestAnswers-James** trading methodology. This doc gets a new developer (or a new Claude account) fully up to speed.

---

## 1. Where everything lives (nothing is stored "in" Claude)

| Piece | Location | Notes |
|---|---|---|
| **Code** | GitHub `N716739X/OptionsEdgePro` | Single source of truth |
| **Frontend (live)** | Netlify — serves `index.html` | Auto-deploys on merge to `main` |
| **Backend (live)** | Cloudflare **Worker** (`worker.js`) | **Manual deploy** (paste in dashboard) |
| **Database** | Cloudflare **D1** (`env.DB`) | Tables: `users`, `chain_cache` |
| **Payments** | Stripe (via Worker) | Keys in Worker env |
| **Market data** | TwelveData + MarketData.app | Tokens in Worker env |

To move Claude accounts: just point the new account's Claude Code at the GitHub repo (add the GitHub user as a repo collaborator if it's a different person). The running app is untouched.

---

## 2. File layout & the golden rule

- **`marketwatch-dev.html`** — the **readable source** you edit.
- **`index.html`** — the **deployed** copy Netlify serves.
- 🔑 **GOLDEN RULE: keep them identical.** After editing dev, run `cp marketwatch-dev.html index.html` (or edit both) before committing. They must match.
- **`worker.js`** — the Cloudflare Worker (auth, D1, Stripe, API proxy, server scoring).
- **`functions/proxy.js`** — legacy Netlify MarketData proxy (the app now routes market data through the Worker `CF_PROXY`).

`CF_PROXY` (in the frontend) = the Worker URL: `https://marketwatchpro.mattdavis-7f2.workers.dev/`.

---

## 3. Deploy process

**Frontend (most changes):** merge to `main` → Netlify auto-deploys `index.html`. Nothing else needed.

**Worker (`worker.js` changes only):** **manual.**
1. Open `worker.js` from `main` (GitHub → Raw → copy).
2. Cloudflare → Workers & Pages → the Worker → **Edit Code**.
3. Select-all, paste, **Save and Deploy**.
4. Sanity check the pasted file contains the function you changed.
- No DB migration needed — `users` and `chain_cache` tables auto-create in `initDB`.
- Deploy order is safe either way: the frontend falls back gracefully if the Worker is older.

**Git workflow (important):** merges to `main` are **squash-merges**, so a feature branch diverges after each merge. The reliable loop:
```
git fetch origin main
git checkout -B <branch> origin/main
git cherry-pick <your commit>        # re-apply work onto fresh main
git push -u origin <branch> --force-with-lease
```
Then open a PR and squash-merge.

**Syntax checks before committing:**
- Worker: `node --check worker.js`
- Frontend: extract each inline `<script>` and `new Function(body)` it (the app is one big inline script).

---

## 4. The methodology (Laura OG / James)

**Mean Reversion (MR)** — the core indicator. Wilder **RSI(14) → EMA(9) → (value − 50) / 12.5**, on the **4H** timeframe.
- **Data source = EXTENDED-hours (ETH) 4H bars, with an RTH fallback.** Laura & James read Mean-BT on the ETH chart, so the app prefers it. TwelveData only serves extended-hours data (`prepost=true`) at **≤30-min** intervals — *not* 4h — so we fetch **30-min ETH bars** (`interval=30min&prepost=true&timezone=America/New_York&outputsize=500`) and aggregate them into 4H buckets via `aggregate30mTo4h` before the RSI calc. 4H buckets anchor to the ET clock (…04:00/08:00/12:00/16:00/20:00 → four bars/day: 04–08, 08–12, 12–16, 16–20); each 4H close = the last 30-min close in its bucket.
  - ⚠️ **`prepost` requires the TwelveData Pro plan.** On Grow/lower the prepost request **errors**, so both `fetchMeanRev` (frontend) and `scoreTicker` (Worker) **fall back to regular-hours 4h bars** and latch a session flag (`_mrEthUnavailable` / `mrEthUnavailable`) so they don't retry prepost on every ticker. On RTH the app slightly under-reads MR magnitude on volatile days (e.g. TSLA app −0.78 vs ETH chart −1.55) — the known cost of not being on Pro. Upgrade TwelveData to Pro and ETH turns on automatically (no code change).
  - Mirrored in `worker.js` (`aggregate30mTo4h`, `mrSeriesStale`, the conditional MR fetch + RTH fallback in `scoreTicker`) — keep both sides in sync.
- `scale = 12.5` was calibrated from live IA-Mean-Reversion chart pairs (maps RSI to ±4; OB/OS ±2 bands at RSI 75/25). It is James's own 4H scale — do **not** rescale it to close a gap; a magnitude gap means the *input bars* differ (session/feed), not the scale.
- Zone labels (display only): ±0.5 = Overbought/Oversold, ±2 = Deeply OB/OS — matches James's IA-Mean-Reversion shading. Entry **triggers** stay at ±2 regardless (the labels don't gate anything).
- Data guard: rejects thin (<30 bars) or stale (>5 days) TwelveData series → shows `—`.
- ⚠️ It **cannot** tick-match James's private "Mean-BT" exactly — that's a data-feed/session (RTH vs ETH) difference. 12.5 is the pragmatic best-fit.

**Entry triggers (all MR-timed):**
| Strategy | Trigger | Notes |
|---|---|---|
| Cash-Secured Put (Income) | MR ≤ −2 | OTM ~0.20Δ, 30–45 DTE, breakeven above 200 SMA (buffer), buy back at 80–90% |
| Cash-Secured Put (Accumulation) | looser (MR ≤ −1) | ATM = **strike nearest the current price** (~0.50Δ in normal IV; anchored to price, not delta, so high-IV names don't drift ITM), **60–90+ DTE**, bigger credit, want assignment; effective buy = strike − credit |
| Covered Call | MR ≥ +2 | sell 1 call/100 shares near resistance (~9% OTM), 30–45 DTE, buy back 80–90%, never naked |
| Synthetic Long | MR ≤ −2 | same-strike ATM call+put, LEAPS ≥540 DTE |
| MSL | MR ≤ −2 (+ 200 SMA / buy divergence) | 3-leg, LEAPS |

Dashboard badges **gate on the MR trigger** → show **WAIT FOR SETUP** until MR is at the trigger.

**MSL (Modified Synthetic Long)** — 3 legs: buy deep-ITM call (~50/50 intrinsic/extrinsic), sell an **OTM** put (buffer anchor), buy lower put (put credit spread).
- Put-spread credit **≥42%** of width (target 50%); net debit **≤40%** of price (ideal ≤33%); MSL max risk **≤60%** of the equivalent Synthetic Long; LEAPS ≥365 DTE (prefer ≥540).
- **Put spread = buffer-first (Laura MM56).** The short put is NOT at-the-money — it's anchored as **far OTM as possible while the spread still pays ~50% credit** (42% hard floor). Selection (`runMsl` / `runMslPhase3` / `mslPickPutSpread` / Worker `scoreMslChains` — **four replicas, keep in sync**): scan short-put strikes below spot × lower long puts with width in **[18%, 30%] of price** (Laura's ~20% baseline, widened up to ~30% "to bring in a little more credit"); Pass A takes the **furthest-OTM** spread with credit ≥50% (tiebreak credit→50%, then short-put OI); Pass B (nothing hits 50%) collects all spreads ≥42%, treats credits **within 2.5 percentage points of the best as a tie**, and breaks toward **liquidity (short-put OI) then buffer (further OTM)** — this stops the old strict-max-credit rule from chasing a fractional-% edge onto a thin strike (the GOOG 345/268-OI-over-340/927-OI mis-pick); Pass C = closest-to-50%. This self-adjusts: ~20% OTM in high IV (SPCX @ ~$150 → sell 120 / buy 80, 40 wide, 50% credit, 20% buffer), near-ATM in low IV (NVDA). Buffer (short-put %OTM) is shown as a headline.
- **Round strikes only.** `mslFilterRoundStrikes` (frontend + Worker) prunes the chain to round strikes before selection *and* the strike tables, so the MSL never picks/lists an off-round strike (e.g. GOOG 325/335 beside the 320/330/340 ladder). It picks the largest increment (10, then 5) that leaves ≥6 strikes and actually prunes some; cheap names with tight $1/$2.50 ladders are left untouched. Applied in `runMsl`, `runMslPhase3`, Grade-Mine (`mslPickCall`/`mslPickPutSpread` call site), and Worker `scoreMslChains` — **not** in `runMslAdjust` (the roll calc must look up arbitrary user strikes).
- **Call = 50/50 first, OI second.** Prefer higher OI only WITHIN the ideal **45–55% I/E band** (widen to 40–60% if empty; else closest-to-50/50). Laura will take a lower-OI strike to get the right 50/50 structure ("liquidity matters, but not more than the structure").
- **MSL Adjust (roll calculator):** roll ONLY on a bottom signal (−2 MR / buy divergence at 200 SMA). Two handles: roll long **call** down for a debit **≤30%** of width (up to ~33% high conviction); roll long **put** down for a credit **≥60%** of width (Laura's lessons cite 55–70% / ≥50%). Short put strike stays fixed. Widening the put spread raises margin.

**Liquidity guard (CSP/CC/Synth):** flags a wide bid-ask (>15% of mid) or thin OI (<100) so users don't trust an unfillable mid.

---

## 5. How scoring works (architecture)

- **Dashboard cards are server-scored** via `POST /api/scores` → Worker `scoreTicker`. This includes the LEAPS-chain criteria for MSL/Synth (server fetches the chains, computes P-CR / I/E / DEBIT / RISK, returns a `chainScored` flag).
- **Client phase-3** (`runMslPhase3` / `runSynthPhase3`, driven by `triggerPhase3`) is now a **fallback only** — it runs for tickers the server couldn't finish (`phase < 3`), with retries and a terminal "No chain data" state.
- **Analyzers** (`runPut`, `runCC`, `runSynth`, `runMsl`, `runMslAdjust`) are frontend; they fetch chains via `fetchMD`/`fetchChain` → `CF_PROXY`.
- Server MSL/Synth scoring in `worker.js` (`scoreMslChains` / `scoreSynthChains`) mirrors the frontend phase-3 logic **exactly** — keep them in sync if you change either.

---

## 6. 🔴 Open items / must-do

1. **ROTATE THE LEAKED API TOKENS.** `MD_TOKEN` (MarketData.app) and `TD_KEY` (TwelveData) appear in git history. Rotate both and set them as Cloudflare Worker secrets. The MarketData token is also single-IP-locked (only the Worker's egress IP can use it — sandbox testing can't).
2. MR calibration is pragmatic, not exact (see §4) — revisit only with extended-hours data if desired.
3. Possible future work: per-leg roll-to-strike in MSL Adjust; an RSI-vs-Mean-BT overlay for calibration.

---

## 7. Quick verification after any change

- Frontend: hard-refresh (Ctrl/Cmd+Shift+R) after Netlify redeploys (~1–2 min).
- Worker change: redeploy manually, then confirm the dashboard cards / login work.
- A dashboard card and its analyzer tab for the same ticker should agree (they run the same rules).
