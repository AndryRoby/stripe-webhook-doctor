# Launch posts — Stripe Webhook Signature Doctor

Research date: 2026-09-04. Tool: https://arling.sk/stripe-webhook-doctor/

Method: GitHub REST search API (`api.github.com/search/issues`), scoped
first to the broad query, then to `stripe/stripe-node`, `vercel/next.js`
(issues and Discussions), `t3-oss/create-t3-app`, `supabase/supabase`,
several exact-quoted Stripe error strings, and framework-specific
combinations (Fastify/NestJS/Laravel/Django/Cloudflare). Also attempted
Stack Overflow and Reddit via web search (no direct API access — see
note under 1.5). Every thread below was actually fetched via the GitHub
API or web search; nothing here is invented. Dates are from each
thread's own API/page data.

**Rule applied:** closed issue/PR with no real public Q&A content, or an
internal task-tracker/roadmap/backlog item → skip. Open issues are
judged on relevance, freshness, and whether a reply would look welcome
(a live troubleshooting thread with room for a genuinely additive
answer) vs. unwelcome (already thoroughly answered, an internal ticket,
or someone else's code-review PR).

---

## 1. Findings

### 1.1 Broad search: `stripe webhook signature verification failed is:issue`

This query, and every other broad (non-quoted) query tried, is
dominated right now by large multi-agent "orchestration log" repos —
single pinned issues with 50–700+ comments that read as an internal
run log or coordination channel for automated dev pipelines, not a
public Q&A thread. Posting a tool link into one of these is spam, not
help, regardless of whether "stripe" and "webhook" appear somewhere in
the (huge) thread body. All skipped:

| Repo / issue | State | Updated (UTC) | Comments | Recommendation |
|---|---|---|---|---|
| [usdimpact/usd-impact-site#53](https://github.com/usdimpact/usd-impact-site/issues/53) | open | 2026-09-04 | 93 | Skip — internal launch-readiness tracker. |
| [usdimpact/usd-impact-site#54](https://github.com/usdimpact/usd-impact-site/issues/54) | open | 2026-09-04 | 68 | Skip — same repo, same pattern. |
| [usdimpact/usd-impact-site#50](https://github.com/usdimpact/usd-impact-site/issues/50) | open | 2026-09-04 | 50 | Skip — same repo, same pattern. |
| [FreeForCharity/FFC-Cloudflare-Automation#719](https://github.com/FreeForCharity/FFC-Cloudflare-Automation/issues/719) — "Agentic OS Conductor Log" | open | 2026-09-04 | 696 | Skip — explicitly a pinned automation run log. |
| [Jaal-Yantra-Textiles/v2#352](https://github.com/Jaal-Yantra-Textiles/v2/issues/352) — "Platform Backlog" | open | 2026-09-04 | 691 | Skip — roadmap umbrella issue. |
| [lionelite/lion-elite-os#38](https://github.com/lionelite/lion-elite-os/issues/38) — "AI Coordination Hub" | open | 2026-09-04 | 92 | Skip — Claude Code ↔ ChatGPT coordination channel. |
| [Swooshz-com/swooshz-platform#104](https://github.com/Swooshz-com/swooshz-platform/issues/104) | open | 2026-09-04 | 708 | Skip — internal programme dashboard. |
| [johazores/my-booking-engine#1](https://github.com/johazores/my-booking-engine/issues/1) | open | 2026-09-04 | 121 | Skip — internal implementation checklist. |
| [peleduri/zero-day-pulse#7](https://github.com/peleduri/zero-day-pulse/issues/7) | open | 2026-09-04 | 399 | Skip — automated security-feed issue, unrelated content. |
| [medusajs/medusa#16228](https://github.com/medusajs/medusa/pull/16228) — "fix(payment-stripe): handle Stripe webhook signature errors" | open (PR) | 2026-09-04 | 3 | **Verified in full, skip** — a maintainer/contributor code-review PR wrapping `constructWebhookEvent` in the module's existing `buildError` error-normalization pattern. Not a help request; commenting a tool link on someone's in-review PR reads as off-topic. |

### 1.2 Repo-scoped: `stripe/stripe-node`

| Issue | State | Updated | Comments | Recommendation |
|---|---|---|---|---|
| [#356 — "Problem parsing body: No signatures found matching expected signature"](https://github.com/stripe/stripe-node/issues/356) | closed | 2026-04-30 | 51 | Skip — closed, and a 51-comment thread from the SDK's own maintainers/community is already exhaustively resolved. |
| [#1768 — "Node: verify signature fails while using APIGatewayProxyEvent.body"](https://github.com/stripe/stripe-node/issues/1768) | closed | — | — | Skip for posting (closed, resolved) — but **verified in full and cited directly** in `llms-full.txt` as the sourced confirmation for the AWS API Gateway `isBase64Encoded` failure mode. |
| [#407 — "Timestamp outside the tolerance zone"](https://github.com/stripe/stripe-node/issues/407) | closed | 2024-08-24 | 2 | Skip — closed, >12 months. |
| [#2763 — "Feedback wanted: event notification handlers"](https://github.com/stripe/stripe-node/issues/2763) | open | 2026-06-23 | 0 | Skip — a maintainer feature-design thread, not a troubleshooting question; not a spot for a third-party tool link. |
| #1294, #2670, #2684, #2685, #2651, #2652 and other recent stripe-node issues/PRs touching webhooks | closed | 2026-04 to 2026-08 | varies | Skip — all internal SDK maintenance/typing/refactor PRs, not public help requests. |

### 1.3 Repo-scoped: `vercel/next.js` (issues) and Discussions

GitHub Issues search:

| Issue | State | Updated | Comments | Recommendation |
|---|---|---|---|---|
| [#60002 — "STRIPE WEBHOOK - Cannot access request raw body"](https://github.com/vercel/next.js/issues/60002) | closed | 2024-12-12 | 8 | Skip — closed, >12 months. |
| [#61365, #57825, #49739, #49025](https://github.com/vercel/next.js/issues) | closed | 2023–2024 | — | Skip — all closed, all >12 months. |

Discussions (`?discussions_q=stripe+webhook+signature`):

| Discussion | Status | Posted | Recommendation |
|---|---|---|---|
| "Stripe Webhook in Nextjs issue" | unanswered, 36 replies | Apr 2023 | Skip — technically unanswered but ~3.5 years old with 36 existing replies; a new comment is very unlikely to be seen, and that much existing discussion means most fixes are probably already in the thread somewhere. |
| "RFC - add rawBody to NextApiRequest" | answered, 35 replies | May 2020 | Skip — answered, 6 years old. |
| "Modify raw body in api route" | answered, 8 replies | Aug 2021 | Skip — answered, 5 years old. |
| Others returned (cart UI, App Directory feedback, etc.) | — | — | Skip — not about signature verification. |

### 1.4 Repo-scoped: `t3-oss/create-t3-app`, `supabase/supabase`

- `t3-oss/create-t3-app`: zero results for `stripe webhook` — no thread to evaluate.
- `supabase/supabase`: search returned mostly unrelated recent PRs (docs updates, Edge Functions template refactors, a "Stripe Sync Engine" integration PR from Jan 2026 that's about building a *different* feature, not troubleshooting signature errors) plus one 2025-08-10 closed issue "Support signed hooks verification" (about Supabase's own database webhooks, not Stripe's) and a 2025-01-22 closed issue about `generateTestHeaderString` in tests. None are open, current, public "why is my signature verification failing" threads. All skip.

### 1.5 Stack Overflow / Reddit

Direct fetches of `stackoverflow.com` search/question pages are not
reachable from this session's fetcher (as with the OAuth-doctor
research before it — a network/robots restriction on the tool, not a
missing result). A general web search for
`stripe webhook signature verification failed site:stackoverflow.com`
and `"stripe webhook" "signature verification failed" reddit 2026`
returned Stripe's own docs, aggregator/SEO article sites, and a Medium
post, but no fetchable individual Stack Overflow question or Reddit
thread to evaluate for a reply. Andrej: worth checking manually at
`https://stackoverflow.com/questions/tagged/stripe-payments` and
`https://www.reddit.com/r/stripe/` and `r/webdev` for anything current
to add — nothing from there is included below because it couldn't be
verified live.

### 1.6 One open, genuinely public thread found

| Issue | State | Updated | Comments | Recommendation |
|---|---|---|---|---|
| [navinagrawalchung07/Swytchcode_Test#1 — "Stripe webhook signature verification keeps failing on Express — what am I doing wrong?"](https://github.com/navinagrawalchung07/Swytchcode_Test/issues/1) | **open**, 2 comments | created 2026-06-25, last updated 2026-08-30 | 2 | **Post, with a caveat** (see §2). A real, specific, on-topic question (Express + `stripe.webhooks.constructEvent()`, Node 20, Stripe SDK v14, on Railway). Both existing comments already give the correct core fix (`express.raw()` before the global `express.json()`), but both read as bot/marketing-flavored — one signs off "posted by @swytch123, a Swytchcode research bot," the other drifts into an unrelated Turkish sentence and pitches a "48h delivery on the paid fix." A clean, credible, non-selling human reply adds real trust value here even though the headline fix overlaps, and there's room to add two things neither existing comment covers: the CLI-secret-vs-Dashboard-secret mix-up, and the test/live mode split — both plausible given the OP says they "verified the webhook secret multiple times" without saying which secret.

### 1.7 A related finding worth flagging (not a reply target)

[realadeel/awesome-webhooks PR#66 — "Add Stripe Signature Debugger to Development Tools"](https://github.com/realadeel/awesome-webhooks/pull/66): closed, not merged, opened 2026-07-27. A different developer built a client-side "Stripe Signature Debugger" (computes the same HMAC Stripe does via Web Crypto API, generates test signature headers, no server, explicitly rejects `sk_`/`rk_` keys pasted in by mistake, MIT licensed) and submitted it to `realadeel/awesome-webhooks`, a real curated "awesome list" of webhook tooling — but the PR was closed without merging (reason not visible from the API). Not a place to comment (it's someone else's closed PR, not a discussion thread), but see §3 point 7 — this is a genuine, on-target submission channel for Andrej himself.

---

## 2. Drafted reply (first person, as Andrej)

### 2.1 → https://github.com/navinagrawalchung07/Swytchcode_Test/issues/1

> The `express.raw()` fix in the comments above is the right core fix — `express.json()` (or any global body parser) running ahead of your webhook route parses the body into an object before `constructEvent()` ever sees it, and the HMAC can only match against the exact raw bytes Stripe sent.
>
> Since you said you've checked the secret multiple times already, two other things are worth ruling out specifically, because they fail in exactly the same visible way (payload reaches your endpoint, secret "looks right," verification still fails):
>
> 1. **Which secret, from where.** A Dashboard-managed endpoint's signing secret (`whsec_...`), the Stripe CLI's own secret from `stripe listen`, and your general API key (`sk_...`) are three different strings. If you're testing with `stripe listen` locally but the secret in your `.env` came from a Dashboard endpoint (or vice versa), verification fails even though the secret is "correct" in the sense of being a real, valid Stripe secret.
> 2. **Test mode vs. live mode.** Stripe generates a separate secret for the same endpoint URL depending on whether it's receiving test-mode or live-mode events. Worth double-checking you're comparing the secret against the mode the incoming event is actually in.
>
> If `express.raw({type: 'application/json'})` is already scoped correctly ahead of any global `express.json()` and it's still failing, those two are where I'd look next.
>
> I built a free tool that walks through this exact decision tree (framework, how the body's handled, where the secret came from, test vs. live) and points at the one specific cause: https://arling.sk/stripe-webhook-doctor/

---

## 3. Facts for the owner (not finished copy) — for Andrej's own Show HN / Reddit / FB post

1. **What it actually does**: you paste the exact error text Stripe/`constructEvent()` threw, answer a handful of questions about your framework, runtime, how your request body is handled, which header you read, and where your secret came from — the tool matches that against Stripe's five documented signature-verification error strings and a specific list of known causes (which framework's body parser runs first, wrong-secret-type, test/live mismatch, AWS Lambda base64 body, Go's read-once request stream, `tolerance: 0`, CSRF blocking the request, missing/renamed header) and tells you which one applies and how to fix it.
2. **Framework coverage is specific, not generic**: separate, distinct fixes for Next.js App Router vs. Pages Router (they need different raw-body handling), plus Express, Fastify, NestJS, Django, Flask, FastAPI, Rails, Laravel, Go, .NET, and serverless (Vercel, Netlify, AWS Lambda, Cloudflare Workers) — every check is grounded in Stripe's own docs or a cited, confirmed GitHub issue (listed in `llms-full.txt`), not generic "check your body parser" advice.
3. **It's 100% client-side, no backend, no account** — same as the other Doctor tools — but with one deliberate difference: it never asks for, and has no field for, your actual webhook signing secret or API key. It only takes the error text and a description of your setup. Worth saying explicitly in any post, since this is the first payments-adjacent tool in the family and readers will (correctly) be more cautious about what they paste.
4. **What it does NOT do**: it doesn't call Stripe's API, doesn't verify anything against your live Stripe account or an actual webhook delivery, and doesn't replace `stripe trigger` / `stripe listen` for actually testing your endpoint end-to-end. It's a pattern-matcher over what you describe, not a live test — a clean report isn't a guarantee the endpoint works.
5. **Free, static, no signup, no beta/pricing language** — GitHub Pages, same as every other tool in the family.
6. **Competitive landscape**: one directly comparable community tool was found — a browser-based "Stripe Signature Debugger" (client-side HMAC computation, test-header generator, MIT licensed) submitted as a PR to the `realadeel/awesome-webhooks` curated list on 2026-07-27, but the PR was closed without merging. Two takeaways: someone else independently saw the same gap (validates it's a real pain point worth a Show HN mention), and that awesome-list — `github.com/realadeel/awesome-webhooks` — is a legitimate, real curated resource. Worth submitting `stripe-webhook-doctor` there directly as a PR; it reaches exactly the target developer audience with none of the subreddit self-promo-rule risk.
7. **Live-thread research came up thin today**: across `stripe/stripe-node`, `vercel/next.js` (issues + Discussions), `t3-oss/create-t3-app`, `supabase/supabase`, and several broad/quoted searches, the only genuinely open, on-topic, public troubleshooting thread found was one Express issue that already has two answers (bot-flavored, but technically correct) — see §1.6/§2.1 for the drafted reply. This isn't a research shortfall; it's today's actual snapshot of a very noisy search index (dominated by large automated-agent "coordination log" repos). Worth re-running this same research in a week or two — fresh "signature verification failed" threads open constantly on Stack Overflow and GitHub, they just didn't turn up a strong candidate today.
8. **Suggested first channels given the above**: the `awesome-webhooks` PR (point 6), a Show HN post (developer-tool audience, matches the family's prior Show HN pattern), and r/webdev / r/node / r/nextjs / r/aws (for the Lambda-specific angle) — check each community's self-promotion rules before posting, same as every prior launch in this family.

---

## 4. Article outline (dev.to)

**Working title:** *Stripe's "signature verification failed" is one error message for a dozen different bugs*

1. **The hook** — the error text never tells you which of a dozen-plus unrelated causes it is; here's the actual decision tree, ranked by how often each one is the real cause.
2. **What Stripe actually verifies** — cite the official mechanism: `signed_payload = "{timestamp}.{raw body}"`, HMAC-SHA256 keyed with the endpoint's `whsec_...` secret, `v1` the only valid live scheme (`v0` is a fake test-only scheme, ignored to prevent downgrade attacks), default 300-second tolerance (link: `docs.stripe.com/webhooks/signature`).
3. **Cause #1, by far: something touched the raw bytes before verification** — one snippet each for Express (`express.json()` ordering), Next.js App Router (`req.text()` vs `req.json()`) vs. Pages Router (`bodyParser: false`), NestJS (`rawBody: true` in `main.ts`), Fastify (`addContentTypeParser`), AWS Lambda + API Gateway (`isBase64Encoded`, with the cited stripe-node issue), and Go (`http.Request.Body` read once by earlier middleware).
4. **Cause #2: the wrong secret, four different ways** — Dashboard endpoint secret vs. CLI `stripe listen` secret vs. API key (`sk_`/`pk_`) vs. test-mode secret used against a live-mode event (or vice versa); up to 16 endpoints per account, each with its own secret.
5. **Cause #3: timestamp tolerance** — clock drift, and the `tolerance: 0` anti-pattern Stripe's own docs warn against.
6. **Cause #4: it never even reaches your signature-verification code** — CSRF middleware blocking the POST first (Rails/Django/Laravel), with Stripe's own `protect_from_forgery except: :webhook` example.
7. **A checklist you can run by hand** — or the free tool that automates matching your specific setup to the cause (link at the end, not before).
8. **Sources** — link every official doc cited in steps 2–6, plus the stripe-node issue for the Lambda base64 case, so the article holds up to scrutiny.
