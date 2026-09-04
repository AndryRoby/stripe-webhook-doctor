# Stripe Webhook Signature Doctor

Live: https://arling.sk/stripe-webhook-doctor/

A free, static, client-side tool that diagnoses Stripe webhook
**signature verification errors**: "No signatures found matching the
expected signature for payload", "Timestamp outside the tolerance
zone", "Unable to extract timestamp and signatures from header",
"Webhook payload must be provided as a string or a Buffer", and "No
webhook payload was provided". Describe how your handler reads the
request body and the `Stripe-Signature` header, where your `whsec_`
secret comes from, and (optionally) paste the relevant lines of code,
and it works out which of Stripe's documented causes is actually
responsible: instead of you re-reading Stripe's webhook docs for the
third time.

## What it's for

If Stripe is rejecting your webhook and the code *looks* right at a
glance, this tool cross-checks the config that's normally scattered
across your route handler, your middleware stack, and your
environment variables for the causes that account for almost all of
these failures:

- **Raw-body integrity**: an already-parsed JSON body, a
  re-serialized body, or a global body-parser middleware that runs
  before the webhook route and consumes the raw bytes first.
- **Next.js App Router** using `req.json()` instead of `req.text()`,
  or a missing `await` on it.
- **Next.js Pages Router** missing `bodyParser: false`.
- **Pasted-code heuristics**: `JSON.parse` before `constructEvent`,
  a global `express.json()`, `req.body` passed without confirmed raw
  handling.
- **The secret**: an API key (`sk_`/`pk_`) used by mistake, an unset
  environment variable, or the `stripe listen` secret used against a
  live, publicly deployed endpoint.
- **Multiple endpoints and modes**: each endpoint, and each of test
  and live mode, has its own `whsec_` secret.
- **The `Stripe-Signature` header** read under the wrong name.
- **Tolerance and clock skew**: including the documented trap of
  setting tolerance to `0`, which disables the check entirely rather
  than tightening it.
- **AWS API Gateway + Lambda's** base64-encoded body.
- **Edge runtimes** (Cloudflare Workers, Vercel Edge) needing
  `constructEventAsync` instead of the synchronous `constructEvent`.

## How it works (client-side only)

Everything runs in your browser. There is no backend, no account, and
no payment wall, and the tool never asks for your secret's actual
value: only its prefix (`whsec_`/`sk_`/`pk_`) and where it came from.
You describe your setup in the page, and `doctor-stripe.js`: one
dependency-free JavaScript file: runs a single pure function,
`diagnose(config)`, entirely in your browser, and you get a
plain-language report with copy-paste fixes for your framework.

Nothing about your configuration is sent anywhere. The only network
activity this site generates is:

- loading its own static assets (HTML/CSS/JS) from GitHub Pages,
- and anonymous product-analytics events (page view, "run check"
  clicked, etc.) sent to a self-hosted Umami instance: **event names
  and counts only, never the content of what you entered.**

You can verify this yourself: open your browser's network tab while
using the tool, or just read `index.html` and `doctor-stripe.js`: it's static files with no build step.

## Running it locally

There's no build step. It's static files.

```bash
git clone https://github.com/AndryRoby/stripe-webhook-doctor.git
cd stripe-webhook-doctor
# any static file server works, e.g.:
npx serve .
# or just open index.html directly in a browser
```

## Running the tests

```bash
node tests.mjs
```

## Reporting a missing case / false positive

Found a signature-verification cause this tool doesn't catch, or a
check that flags something that's actually fine? Please open an issue
on the GitHub repo with:

1. The relevant (redacted) config: framework, body handling, secret
   source and prefix (never the secret value itself).
2. The exact error text Stripe/your library threw.
3. What you expected the tool to say.

## Disclaimer

This tool is provided **as is**, with no warranty of any kind. It
checks for known, common misconfiguration patterns: it cannot
guarantee your webhook will verify correctly, and a clean report is
not a guarantee of a working integration. It performs a read-only,
client-side analysis of the values you type in; nothing is verified
against your live Stripe account, deployed code, or server clock.
Stripe, Next.js, Express, Fastify, NestJS, Django, Flask, FastAPI,
Rails, Laravel, Vercel, Netlify, AWS, Cloudflare, and Microsoft are
not affiliated with this tool, and their docs, SDKs, and defaults may
change in ways that make individual checks stale over time. Always
verify against the current official documentation for anything
security-relevant, and test with `stripe trigger` or a real event
before shipping.

## About

Built by ARLing s. r. o. (Bratislava, Slovakia).
Contact: andrej@arling.sk

Sibling tools in the same "Doctor" family:
- Google OAuth redirect_uri_mismatch: https://arling.sk/google-oauth-redirect-doctor/
- Supabase Auth on the web (Next.js / Vite / SvelteKit): https://arling.sk/supabase-redirect-doctor/
- Supabase Auth on Flutter: https://arling.sk/flutter-supabase-doctor/
- Supabase Auth on Expo / React Native: https://arling.sk/expo-supabase-auth-doctor/
- Hub (more ARLing tools): https://arling.sk/
