// doctor-stripe.js: Stripe Webhook Signature Doctor core logic.
//
// Pure, deterministic, 100% client-side: given the exact error text Stripe's
// library (or your own manual check) threw, how your handler gets the
// request body and the `Stripe-Signature` header, where your whsec_ secret
// comes from, and (optionally) a pasted code snippet, this works out which
// of the handful of documented causes is most likely responsible and gives a
// framework-specific fix.
//
// Nothing in this file makes a network request. It only reads the object you
// pass to diagnose().
//
// This is the fifth sibling in the "Doctor" family (after the Google OAuth,
// Expo, web, and Flutter Supabase Redirect Doctors): same diagnose()-shape
// contract, same zero-dependency, single-file design, different domain:
// Stripe's HMAC webhook-signature verification instead of an OAuth
// redirect_uri allow-list.
//
// Rules implemented here are sourced from (fetched 2026-09-05):
//  - https://docs.stripe.com/webhooks#verify-official-libraries
//      ("Stripe requires the raw body of the request to perform signature
//      verification. If you're using a framework, make sure it doesn't
//      manipulate the raw body. Any manipulation to the raw body of the
//      request causes the verification to fail."; Dashboard: "a signing
//      secret beginning with whsec_ appears"; CLI: "The stripe listen
//      command outputs the {{WEBHOOK_SIGNING_SECRET}}"; "Our libraries have
//      a default tolerance of 5 minutes between the timestamp and the
//      current time... Don't use a tolerance value of 0. Using a tolerance
//      value of 0 disables the recency check entirely."; Stripe-Signature
//      header format "t=...,v1=...,v0=...")
//  - https://docs.stripe.com/webhooks/signature
//      (troubleshooting page: "Webhook signature verification failed. Err:
//      No signatures found matching the expected signature for payload." is
//      caused by one of exactly three parameters being wrong; "The most
//      common error is using the wrong endpoint secret... Don't verify
//      signatures on events forwarded by the CLI using the secret from a
//      Dashboard-managed endpoint, or the other way around."; retrieval
//      table naming Express, Body Parser, Next.js App Router and Pages
//      Router as the frameworks most likely to mutate the raw body; the
//      Express fix: "app.use(express.json()) is placed *after* the webhook
//      route... the order of middleware configuration matters"; AWS API
//      Gateway + Lambda: a Body Mapping Template exposing a `rawBody`
//      property, since API Gateway can base64-encode the body first)
//  - https://docs.stripe.com/stripe-cli/overview
//      + the `stripe listen` section of https://docs.stripe.com/webhooks
//      ("The stripe listen command outputs the {{WEBHOOK_SIGNING_SECRET}}":
//      a value generated for local event forwarding, separate from any
//      Dashboard-created endpoint's secret)
//  - https://nextjs.org/docs/app/building-your-application/routing/route-handlers
//      (redirects to /docs/app/api-reference/file-conventions/route: the
//      "Webhooks" example reads `const text = await request.text()`, in
//      contrast to the "Request Body" example's `await request.json()` for
//      ordinary parsed JSON)
//  - https://expressjs.com/en/resources/middleware/body-parser.html
//      (`bodyParser.raw()`/`express.raw()` "parses all incoming request
//      bodies as a Buffer" and only for the matching `type`; "Route-specific
//      application is recommended" over mounting it globally)
//  - https://github.com/stripe/stripe-node/blob/master/examples/webhook-signing/nextjs/app/api/webhooks/route.ts
//      (canonical App Router handler: `await req.text()` then
//      `stripe.webhooks.constructEvent(text, signature, secret)`)
//  - https://github.com/stripe/stripe-node/blob/master/examples/webhook-signing/nextjs/pages/api/webhooks.ts
//      (canonical Pages Router handler: `export const config = { api: {
//      bodyParser: false } }` plus a hand-rolled `buffer(req)` stream
//      reader, because Next's default API body parser would otherwise
//      consume and JSON-parse the body first)
//  - https://github.com/stripe/stripe-node/blob/master/src/Webhooks.ts
//      (`DEFAULT_TOLERANCE: 300` — 5 minutes, matching the docs page above;
//      a separate `constructEventAsync()` method; `constructEvent()` catches
//      `CryptoProviderOnlySupportsAsyncError` and appends "Use `await
//      constructEventAsync(...)` instead of `constructEvent(...)`" — thrown
//      when the only available crypto provider is async-only, i.e. the Web
//      Crypto API used on edge runtimes such as Cloudflare Workers, which
//      have no Node `crypto` module)
//  - https://github.com/stripe/stripe-node (README.md)
//      ("you must pass the _raw_ request body, exactly as received from
//      Stripe, to the `constructEvent()` function; this will not work with
//      a parsed (i.e., JSON) request body")
//  - https://docs.stripe.com/webhooks.md (Node quickstart sample)
//      (canonical Express route: `app.post('/webhook', express.raw({type:
//      'application/json'}), (request, response) => { ... })` — raw-body
//      middleware mounted on the webhook route only, not globally)
//
// Works as an ES module (import { diagnose, expectedValues } from
// './doctor-stripe.js') and, when loaded with <script type="module">, also
// publishes window.StripeWebhookDoctor = { diagnose, expectedValues } for
// console/debug use.

// ───────────────────────── small helpers ─────────────────────────

function safeStr(v) {
  return typeof v === 'string' ? v : '';
}

function safeBool(v) {
  return typeof v === 'boolean' ? v : null;
}

function safeNum(v) {
  return typeof v === 'number' && isFinite(v) ? v : null;
}

function oneOf(v, list, fallback) {
  return list.includes(v) ? v : fallback;
}

// ───────────────────────── error-message classification ─────────────────────────
// The tool recognizes five verbatim Stripe/stripe-node error strings. Each
// maps to a different root-cause family; everything else still runs the
// config-based checks below, just without a matching headline cause.

const ERROR_PATTERNS = [
  { code: 'no_signatures_found', re: /no signatures found matching/i },
  { code: 'timestamp_outside_tolerance', re: /timestamp outside the tolerance zone/i },
  { code: 'unable_to_extract_timestamp_and_signatures', re: /unable to extract timestamp and signatures/i },
  { code: 'payload_must_be_string_or_buffer', re: /must be provided as a string or a buffer/i },
  { code: 'no_webhook_payload_provided', re: /no webhook payload was provided/i },
];

function classifyErrorMessage(message) {
  const m = safeStr(message).trim();
  if (!m) return '';
  for (const { code, re } of ERROR_PATTERNS) {
    if (re.test(m)) return code;
  }
  return 'unrecognized';
}

// ───────────────────────── code-snippet heuristics ─────────────────────────
// Best-effort regex checks on an optionally pasted handler snippet. These
// never run against anything but the string you paste; they do not execute
// any code.

function hasJsonParseBeforeConstruct(snippet) {
  const s = safeStr(snippet);
  const jsonIdx = s.search(/JSON\.parse\s*\(/);
  const constructIdx = s.search(/constructEvent(Async)?\s*\(/);
  return jsonIdx !== -1 && constructIdx !== -1 && jsonIdx < constructIdx;
}

function hasGlobalJsonParserInSnippet(snippet) {
  return /\.use\s*\(\s*(express\.json\(\)|bodyParser\.json\(\))/.test(safeStr(snippet));
}

function hasReqJsonInAppRouter(snippet) {
  const s = safeStr(snippet);
  return /\b(req|request)\.json\s*\(\s*\)/.test(s) && !/\b(req|request)\.text\s*\(\s*\)/.test(s);
}

function missingAwaitOnText(snippet) {
  const s = safeStr(snippet);
  const re = /(^|[^a-zA-Z0-9_$.])((?:req|request)\.text\(\))/g;
  let match;
  while ((match = re.exec(s))) {
    const start = match.index + match[1].length;
    const before = s.slice(Math.max(0, start - 8), start);
    if (!/await\s*$/.test(before)) return true;
  }
  return false;
}

function usesConstructEventAsync(snippet) {
  return /constructEventAsync\s*\(/.test(safeStr(snippet));
}

function passesReqBodyDirectly(snippet) {
  return /constructEvent(Async)?\s*\(\s*(req|request)\.body\b/.test(safeStr(snippet));
}

function hasBodyParserFalseConfig(snippet) {
  return /bodyParser\s*:\s*false/.test(safeStr(snippet));
}

function mentionsBase64Decode(snippet) {
  return /base64/i.test(safeStr(snippet));
}

// ───────────────────────── per-framework "how to get the raw body" ─────────────────────────

const FRAMEWORKS = [
  'nextjs-app', 'nextjs-pages', 'express', 'fastify', 'nestjs', 'django',
  'flask', 'fastapi', 'rails', 'laravel', 'go', 'dotnet',
  'vercel-function', 'netlify-function', 'aws-lambda', 'cloudflare-workers',
];

const FRAMEWORK_LABEL = {
  'nextjs-app': 'Next.js (App Router)',
  'nextjs-pages': 'Next.js (Pages Router)',
  express: 'Express',
  fastify: 'Fastify',
  nestjs: 'NestJS',
  django: 'Django',
  flask: 'Flask',
  fastapi: 'FastAPI',
  rails: 'Ruby on Rails',
  laravel: 'Laravel',
  go: 'Go (net/http)',
  dotnet: '.NET / ASP.NET Core',
  'vercel-function': 'Vercel Serverless Function',
  'netlify-function': 'Netlify Function',
  'aws-lambda': 'AWS Lambda + API Gateway',
  'cloudflare-workers': 'Cloudflare Workers',
};

const BODY_ACCESS = {
  'nextjs-app': {
    code:
`export async function POST(req) {
  const body = await req.text();            // NOT await req.json()
  const signature = req.headers.get('stripe-signature');
  const event = stripe.webhooks.constructEvent(
    body, signature, process.env.STRIPE_WEBHOOK_SECRET
  );
}`,
    note: "App Router route handlers: read the body with await req.text(), never req.json() — Stripe's own stripe-node example does exactly this.",
  },
  'nextjs-pages': {
    code:
`export const config = { api: { bodyParser: false } };

async function buffer(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

export default async function handler(req, res) {
  const buf = await buffer(req);
  const signature = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(
    buf, signature, process.env.STRIPE_WEBHOOK_SECRET
  );
  res.json({ received: true });
}`,
    note: "Pages Router API routes: disable Next's default body parser with bodyParser: false, then read the raw stream yourself with a buffer(req) helper — this is stripe-node's own documented example.",
  },
  express: {
    code:
`// Mount raw-body parsing on THIS route only, before any global express.json().
app.post('/webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const signature = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(
    req.body, signature, process.env.STRIPE_WEBHOOK_SECRET
  );
  res.json({ received: true });
});

app.use(express.json()); // other routes: parse AFTER the webhook route`,
    note: "express.raw({type:'application/json'}) on the webhook route gives req.body as a Buffer of the exact bytes. If app.use(express.json()) runs first (globally, before this route), it consumes and parses the body first and verification fails — Stripe's own troubleshooting docs single this out as the fix.",
  },
  fastify: {
    code:
`fastify.addContentTypeParser('application/json', { parseAs: 'buffer' }, (req, body, done) => {
  done(null, body); // keep the raw Buffer instead of Fastify's default JSON parsing
});

fastify.post('/webhook', (req, reply) => {
  const signature = req.headers['stripe-signature'];
  const event = stripe.webhooks.constructEvent(
    req.body, signature, process.env.STRIPE_WEBHOOK_SECRET
  );
  reply.send({ received: true });
});`,
    note: 'Fastify parses application/json bodies by default; override the content-type parser to hand you the raw Buffer instead of a parsed object.',
  },
  nestjs: {
    code:
`// main.ts
const app = await NestFactory.create(AppModule, { rawBody: true });

// webhook.controller.ts
@Post('webhook')
handleWebhook(@Req() req: RawBodyRequest<Request>) {
  const event = this.stripe.webhooks.constructEvent(
    req.rawBody, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
  );
}`,
    note: "Pass rawBody: true when creating the Nest app, then read req.rawBody in the webhook handler — Nest's default body parser would otherwise have already parsed and discarded the raw bytes.",
  },
  django: {
    code:
`@csrf_exempt
def stripe_webhook(request):
    payload = request.body  # raw bytes, untouched by Django's own parsing
    sig_header = request.META.get('HTTP_STRIPE_SIGNATURE')
    event = stripe.Webhook.construct_event(
        payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
    )`,
    note: 'request.body gives raw bytes as long as nothing upstream (a DRF parser, a JSON-body middleware) has already consumed the stream. Exempt this view from CSRF protection.',
  },
  flask: {
    code:
`@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    payload = request.get_data()  # raw bytes; NOT request.get_json()
    sig_header = request.headers.get('Stripe-Signature')
    event = stripe.Webhook.construct_event(
        payload, sig_header, os.environ['STRIPE_WEBHOOK_SECRET']
    )`,
    note: 'request.get_data() returns the untouched raw body. request.get_json() or request.form would parse it first and break verification.',
  },
  fastapi: {
    code:
`@app.post("/webhook")
async def stripe_webhook(request: Request):
    payload = await request.body()  # raw bytes; NOT await request.json()
    sig_header = request.headers.get("stripe-signature")
    event = stripe.Webhook.construct_event(
        payload, sig_header, os.environ["STRIPE_WEBHOOK_SECRET"]
    )`,
    note: 'await request.body() returns raw bytes. A Pydantic body model or await request.json() parses first and changes the bytes constructEvent sees.',
  },
  rails: {
    code:
`post '/webhook' do
  payload = request.body.read   # raw string
  sig_header = request.env['HTTP_STRIPE_SIGNATURE']
  event = Stripe::Webhook.construct_event(
    payload, sig_header, ENV['STRIPE_WEBHOOK_SECRET']
  )
end`,
    note: "request.body.read gives the raw string exactly as sent. Also exempt the route from Rails' CSRF check (protect_from_forgery except: :webhook) since Stripe never sends a CSRF token.",
  },
  laravel: {
    code:
`Route::post('/webhook', function (Request $request) {
    $payload = $request->getContent();     // raw string
    $sigHeader = $request->header('Stripe-Signature');
    $event = \\Stripe\\Webhook::constructEvent(
        $payload, $sigHeader, env('STRIPE_WEBHOOK_SECRET')
    );
});`,
    note: '$request->getContent() returns the raw body. Add this route to VerifyCsrfToken::$except since Stripe will not send a CSRF token.',
  },
  go: {
    code:
`func handler(w http.ResponseWriter, req *http.Request) {
    payload, _ := io.ReadAll(req.Body)  // raw bytes
    sigHeader := req.Header.Get("Stripe-Signature")
    event, err := webhook.ConstructEvent(
        payload, sigHeader, os.Getenv("STRIPE_WEBHOOK_SECRET"),
    )
}`,
    note: 'io.ReadAll(req.Body) gives the exact bytes Stripe sent, as long as no earlier middleware (a logging or JSON-decoding wrapper) already drained req.Body.',
  },
  dotnet: {
    code:
`[HttpPost("webhook")]
public async Task<IActionResult> Webhook()
{
    var json = await new StreamReader(Request.Body).ReadToEndAsync(); // raw string
    var signature = Request.Headers["Stripe-Signature"];
    var stripeEvent = EventUtility.ConstructEvent(
        json, signature, Environment.GetEnvironmentVariable("STRIPE_WEBHOOK_SECRET")
    );
}`,
    note: 'Read Request.Body directly with a StreamReader before any [FromBody] model binding runs — model binding would parse (and thus alter) the body first.',
  },
  'vercel-function': {
    code:
`export const config = { api: { bodyParser: false } }; // same rule as Next.js Pages Router

export default async function handler(req, res) {
  const buf = await buffer(req);
  const event = stripe.webhooks.constructEvent(
    buf, req.headers['stripe-signature'], process.env.STRIPE_WEBHOOK_SECRET
  );
}`,
    note: "A Vercel Node serverless Function follows the same rule as Next.js's Pages Router API routes: disable the default body parser and read the raw stream yourself.",
  },
  'netlify-function': {
    code:
`exports.handler = async (event) => {
  const payload = event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body;
  const signature = event.headers['stripe-signature'];
  const stripeEvent = stripe.webhooks.constructEvent(
    payload, signature, process.env.STRIPE_WEBHOOK_SECRET
  );
};`,
    note: 'Netlify Functions hand you event.body as a string (sometimes base64-encoded — check event.isBase64Encoded) — never JSON.parse it before constructEvent.',
  },
  'aws-lambda': {
    code:
`exports.handler = async (event) => {
  const payload = event.isBase64Encoded ? Buffer.from(event.body, 'base64') : event.body;
  const signature = event.headers['stripe-signature'] || event.headers['Stripe-Signature'];
  const stripeEvent = stripe.webhooks.constructEvent(
    payload, signature, process.env.STRIPE_WEBHOOK_SECRET
  );
};`,
    note: "API Gateway commonly base64-encodes the body before Lambda sees it (isBase64Encoded: true) — decode it first, and don't JSON.parse it before constructEvent. Stripe's own docs give a Body Mapping Template that exposes a rawBody field for exactly this case.",
  },
  'cloudflare-workers': {
    code:
`export default {
  async fetch(request, env) {
    const payload = await request.text();       // raw string
    const signature = request.headers.get('stripe-signature');
    const event = await stripe.webhooks.constructEventAsync(
      payload, signature, env.STRIPE_WEBHOOK_SECRET
    );
    return new Response('ok');
  },
};`,
    note: "Workers have no Node crypto module, only the async Web Crypto API — use constructEventAsync (and await it), not the synchronous constructEvent, or stripe-node throws CryptoProviderOnlySupportsAsyncError.",
  },
};

function computeExpected(cfg) {
  const app = cfg.app && typeof cfg.app === 'object' ? cfg.app : {};
  const framework = oneOf(app.framework, FRAMEWORKS, '');
  const ba = BODY_ACCESS[framework] || null;
  return {
    framework,
    frameworkLabel: framework ? FRAMEWORK_LABEL[framework] : null,
    secretSource:
      'Dashboard → Workbench → Webhooks → your endpoint → Reveal secret (or the `stripe listen` terminal output for local testing). Always starts with whsec_, and is a different value per endpoint and per mode (test vs live).',
    bodyAccess: ba
      ? { code: ba.code, note: ba.note }
      : { code: null, note: 'Select a framework/runtime above for the exact raw-body recipe.' },
  };
}

// ───────────────────────── diagnose() ─────────────────────────

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

function sortProblems(problems) {
  return problems
    .map((p, idx) => ({ p, idx }))
    .sort((a, b) => (SEVERITY_ORDER[a.p.severity] - SEVERITY_ORDER[b.p.severity]) || (a.idx - b.idx))
    .map((x) => x.p);
}

function pushProblem(problems, { severity, code, message, path, value, fix }) {
  problems.push({ severity, code, message, path: path || null, value: value == null ? null : value, fix: fix || null, where: path || null });
}

const BODY_HANDLING_VALUES = ['raw', 'parsed-json', 'string-reserialized', 'unknown'];
const READS_HEADER_VALUES = ['stripe-signature', 'Stripe-Signature', 'other', ''];
const SECRET_SOURCE_VALUES = ['dashboard-endpoint', 'cli-listen', 'api-key', 'env-unset', 'unknown'];
const SECRET_PREFIX_VALUES = ['whsec_', 'sk_', 'pk_', 'other'];
const MODE_VALUES = ['test', 'live', 'unknown'];
const RUNTIME_VALUES = ['node', 'edge', 'python', 'ruby', 'php', 'go', 'dotnet', ''];
const PROXY_VALUES = ['none', 'vercel', 'netlify', 'lambda-apigw', 'cloudflare', 'ngrok', 'other'];

/**
 * @param {object} config
 * @param {{message?:string}} [config.error]
 * @param {object} [config.app]
 * @param {{snippet?:string}} [config.code]
 * @returns {{status:'pass'|'warn'|'fail', summary:string, expected:object, problems:Array, fixes:Array, checklist:string[], disclaimer:string}}
 */
export function diagnose(config) {
  const cfg = config && typeof config === 'object' ? config : {};
  const errorCfg = cfg.error && typeof cfg.error === 'object' ? cfg.error : {};
  const app = cfg.app && typeof cfg.app === 'object' ? cfg.app : {};
  const codeCfg = cfg.code && typeof cfg.code === 'object' ? cfg.code : {};

  const problems = [];
  const fixes = [];
  const checklist = [];

  const message = safeStr(errorCfg.message).trim();
  const errorCode = classifyErrorMessage(message);
  const snippet = safeStr(codeCfg.snippet);

  const framework = oneOf(app.framework, FRAMEWORKS, '');
  const bodyHandling = oneOf(app.bodyHandling, BODY_HANDLING_VALUES, 'unknown');
  const usesBodyParserGlobally = safeBool(app.usesBodyParserGlobally);
  const readsHeader = oneOf(app.readsHeader, READS_HEADER_VALUES, '');
  const secretSource = oneOf(app.secretSource, SECRET_SOURCE_VALUES, 'unknown');
  const secretPrefix = oneOf(app.secretPrefix, SECRET_PREFIX_VALUES, 'other');
  const mode = oneOf(app.mode, MODE_VALUES, 'unknown');
  const endpointsCount = safeNum(app.endpointsCount);
  const tolerance = safeNum(app.tolerance);
  const runtime = oneOf(app.runtime, RUNTIME_VALUES, '');
  const proxy = oneOf(app.proxy, PROXY_VALUES, 'none');
  const bodyBase64 = safeBool(app.bodyBase64);
  const clockSkewSeconds = safeNum(app.clockSkewSeconds);

  const expected = computeExpected(cfg);
  const fw = framework ? FRAMEWORK_LABEL[framework] : 'your framework';

  // ── 1. was there an error to classify at all? ──────────────────────
  if (!message) {
    pushProblem(problems, {
      severity: 'low',
      code: 'error_message_missing',
      message: "error.message is empty, so the read below is generic. Paste the exact error text — from your server logs, or Stripe Dashboard → Webhooks → your endpoint → Event deliveries — for a targeted diagnosis.",
      path: 'error.message',
    });
  } else if (errorCode === 'unrecognized') {
    pushProblem(problems, {
      severity: 'low',
      code: 'error_message_unrecognized',
      message: "This text doesn't match one of the five constructEvent/signature error strings this tool recognizes verbatim, so the checks below run on your app config alone, not on the specific wording of the error.",
      path: 'error.message',
      value: message,
    });
  }

  // ── 2. raw body integrity ───────────────────────────────────────────
  if (bodyHandling === 'parsed-json') {
    pushProblem(problems, {
      severity: 'high',
      code: 'raw_body_parsed_json',
      message: "Your handler receives req.body already parsed into a JSON object before constructEvent runs. Stripe's own docs: \"Stripe requires the raw body of the request to perform signature verification... Any manipulation to the raw body of the request causes the verification to fail.\" A parsed-then-untouched object is not the raw body constructEvent needs.",
      path: 'app.bodyHandling',
      value: bodyHandling,
      fix: expected.bodyAccess.code || 'Read the raw body before any JSON parsing runs.',
    });
    fixes.push({ title: `Read the raw body for ${fw}`, value: expected.bodyAccess.code || '(select a framework for the exact recipe)', where: fw });
  } else if (bodyHandling === 'string-reserialized') {
    pushProblem(problems, {
      severity: 'high',
      code: 'raw_body_reserialized',
      message: 'Your handler parses the body to JSON and then re-serializes it (e.g. JSON.stringify(JSON.parse(body))) before calling constructEvent. Re-serializing can change whitespace and key order versus the exact bytes Stripe sent and signed, which breaks the HMAC comparison even though the data looks identical.',
      path: 'app.bodyHandling',
      value: bodyHandling,
      fix: expected.bodyAccess.code || 'Keep the original raw string/Buffer; never JSON.parse then JSON.stringify it before constructEvent.',
    });
    fixes.push({ title: `Read the raw body for ${fw}`, value: expected.bodyAccess.code || '(select a framework for the exact recipe)', where: fw });
  } else if (bodyHandling === 'unknown') {
    pushProblem(problems, {
      severity: 'low',
      code: 'raw_body_unknown',
      message: "app.bodyHandling isn't set, so raw-body integrity — the single most common cause of signature failures — can't be checked yet.",
      path: 'app.bodyHandling',
    });
  }

  if (usesBodyParserGlobally === true) {
    pushProblem(problems, {
      severity: 'high',
      code: 'global_body_parser_before_webhook',
      message: `A body-parsing middleware runs globally (for every route, including the webhook one) before your handler sees the request. Stripe's troubleshooting docs single this out for Express: "If express.json() is applied before your webhook route, it parses the request body before signature verification, causing the verification to fail... the order of middleware configuration matters." The same applies to any global JSON/body parser in ${fw} (DRF, a Rails/Laravel before_action, ASP.NET model binding, Next's own default API body parser, and so on).`,
      path: 'app.usesBodyParserGlobally',
      value: true,
      fix: expected.bodyAccess.code || 'Apply raw-body parsing only to the webhook route, before any global parser runs, or exclude the webhook path from the global parser.',
    });
    fixes.push({ title: 'Move (or scope) raw-body parsing so it runs before any global parser', value: expected.bodyAccess.code || '(select a framework for the exact recipe)', where: fw });
  }

  // ── 3. Next.js-specific body access ─────────────────────────────────
  if (framework === 'nextjs-app') {
    if (hasReqJsonInAppRouter(snippet) || bodyHandling === 'parsed-json') {
      pushProblem(problems, {
        severity: 'high',
        code: 'nextjs_app_router_req_json_not_text',
        message: "App Router route handlers must read the body with await req.text() for a webhook, not await req.json(). stripe-node's own Next.js example uses req.text() specifically because req.json() would parse (and thus change) the payload before constructEvent sees it.",
        path: 'code.snippet',
        fix: expected.bodyAccess.code,
      });
      fixes.push({ title: 'Use req.text(), not req.json()', value: expected.bodyAccess.code, where: 'app/api/.../route.ts' });
    }
    if (missingAwaitOnText(snippet)) {
      pushProblem(problems, {
        severity: 'medium',
        code: 'missing_await_on_text',
        message: 'req.text() (or request.text()) returns a Promise. Without await, you pass that pending Promise object into constructEvent instead of the resolved string, which fails validation — this is exactly what produces "Webhook payload must be provided as a string or a Buffer".',
        path: 'code.snippet',
        fix: 'const body = await req.text();',
      });
    }
  }

  if (framework === 'nextjs-pages') {
    const disabledDefaultParser = hasBodyParserFalseConfig(snippet) || bodyHandling === 'raw';
    if (!disabledDefaultParser) {
      pushProblem(problems, {
        severity: 'high',
        code: 'nextjs_pages_router_bodyparser_not_disabled',
        message: "Pages Router API routes parse the body as JSON by default. Without export const config = { api: { bodyParser: false } }, Next.js has already consumed and parsed the raw bytes before your handler runs — stripe-node's own Pages Router example disables the default parser and reads the stream itself with a buffer(req) helper.",
        path: 'app.bodyHandling',
        fix: expected.bodyAccess.code,
      });
      fixes.push({ title: 'Disable the default body parser and read the raw stream', value: expected.bodyAccess.code, where: 'pages/api/webhooks.ts' });
    }
  }

  // ── 4. framework-agnostic code-snippet heuristics ───────────────────
  if (hasJsonParseBeforeConstruct(snippet)) {
    pushProblem(problems, {
      severity: 'high',
      code: 'snippet_json_parse_before_construct_event',
      message: 'Your pasted code calls JSON.parse(...) on the body before calling constructEvent(...). JSON.parse (even with nothing done to the result afterwards) means the value passed to constructEvent is no longer the raw string/Buffer Stripe sent — pass the pre-parse raw value instead.',
      path: 'code.snippet',
      fix: 'Call constructEvent with the raw body, before any JSON.parse of it.',
    });
  }
  if (framework !== 'nextjs-app' && framework !== 'nextjs-pages' && hasGlobalJsonParserInSnippet(snippet) && usesBodyParserGlobally == null) {
    pushProblem(problems, {
      severity: 'high',
      code: 'snippet_global_json_parser_detected',
      message: "Your pasted code calls .use(express.json()) (or bodyParser.json()) — Express's own docs and Stripe's troubleshooting guide agree this must run after the webhook route, never as global middleware applied before it.",
      path: 'code.snippet',
      fix: expected.bodyAccess.code || 'Move the webhook route above the global JSON parser, or scope raw-body parsing to just this route.',
    });
  }
  if (framework === 'express' && passesReqBodyDirectly(snippet) && bodyHandling !== 'raw') {
    pushProblem(problems, {
      severity: 'medium',
      code: 'snippet_reqbody_not_confirmed_raw',
      message: "Your code passes req.body straight into constructEvent. That's only correct when express.raw({type:'application/json'}) ran on this exact route — set app.bodyHandling to \"raw\" once you've confirmed that, otherwise req.body is more likely Express's parsed object.",
      path: 'code.snippet',
    });
  }

  // ── 5. secret source and format ─────────────────────────────────────
  if (secretPrefix === 'sk_' || secretPrefix === 'pk_') {
    pushProblem(problems, {
      severity: 'high',
      code: 'secret_is_api_key_not_whsec',
      message: `The value you're using as the webhook signing secret starts with "${secretPrefix}" — that's an API key (${secretPrefix === 'sk_' ? 'secret' : 'publishable'} key), not a webhook signing secret. Stripe's Dashboard docs are explicit: "a signing secret beginning with whsec_ appears" on the endpoint's settings page. An API key will never verify a webhook signature correctly.`,
      path: 'app.secretPrefix',
      value: secretPrefix,
      fix: 'Copy the whsec_... value from Dashboard → Webhooks → your endpoint → Reveal secret (or from `stripe listen`'+"'"+'s terminal output), not an API key.',
    });
    fixes.push({ title: 'Use the whsec_ signing secret, not an API key', value: 'Dashboard → Webhooks → your endpoint → Reveal secret', where: 'STRIPE_WEBHOOK_SECRET env var' });
  } else if (secretPrefix === 'other') {
    pushProblem(problems, {
      severity: 'medium',
      code: 'secret_prefix_unrecognized',
      message: "The secret you're using doesn't start with whsec_, sk_, or pk_ — every genuine Stripe webhook signing secret starts with whsec_. Double-check you copied the whole value with no leading/trailing whitespace or truncation.",
      path: 'app.secretPrefix',
      value: secretPrefix,
    });
  }

  if (secretSource === 'env-unset') {
    pushProblem(problems, {
      severity: 'high',
      code: 'secret_env_unset',
      message: "The secret variable (e.g. STRIPE_WEBHOOK_SECRET) doesn't reach constructEvent in this environment — either it isn't set there, or there's a typo in the variable name. Stripe's library throws the same \"No signatures found matching the expected signature for payload\" whether the secret is wrong or simply undefined/empty.",
      path: 'app.secretSource',
      fix: 'Set STRIPE_WEBHOOK_SECRET (or your equivalent) in this exact environment, and log its first few characters at boot to confirm it loaded.',
    });
  } else if (secretSource === 'cli-listen' && mode === 'live') {
    pushProblem(problems, {
      severity: 'high',
      code: 'cli_secret_in_live_mode',
      message: "You're using the secret printed by `stripe listen` while app.mode is \"live\". The CLI's forwarding secret is generated for local event forwarding and is not the signing secret of any publicly registered endpoint — Stripe's own troubleshooting page: \"Don't verify signatures on events forwarded by the CLI using the secret from a Dashboard-managed endpoint, or the other way around.\" A live, publicly deployed endpoint needs the whsec_ secret from its own Dashboard entry.",
      path: 'app.secretSource',
      fix: 'Use the whsec_ secret from Dashboard → Webhooks → your live-mode endpoint, not the `stripe listen` output.',
    });
    fixes.push({ title: 'Use the live endpoint\'s own Dashboard secret', value: 'Dashboard → Webhooks → your live-mode endpoint → Reveal secret', where: 'STRIPE_WEBHOOK_SECRET (production)' });
  }

  if (endpointsCount !== null && endpointsCount > 1) {
    pushProblem(problems, {
      severity: 'low',
      code: 'multiple_endpoints_hint',
      message: `You have ${endpointsCount} webhook endpoints registered. Each one (Dashboard-created or a running \`stripe listen\`) gets its own whsec_ secret. Confirm the secret in your code matches the exact endpoint actually receiving this request — check its URL in Dashboard → Webhooks against where your server is listening.`,
      path: 'app.endpointsCount',
      value: endpointsCount,
    });
  }

  // ── 6. Stripe-Signature header handling ─────────────────────────────
  if (readsHeader === 'other') {
    pushProblem(problems, {
      severity: 'high',
      code: 'header_not_stripe_signature',
      message: 'Your code reads a header other than stripe-signature. Stripe only ever sends the signature in the Stripe-Signature header (Node normalizes this to req.headers[\'stripe-signature\'], lowercase); reading any other header name will never find a valid value, and produces exactly "Unable to extract timestamp and signatures from header" or "No signatures found matching the expected signature for payload".',
      path: 'app.readsHeader',
      value: readsHeader,
      fix: "Read req.headers['stripe-signature'] (or your framework's equivalent case-insensitive lookup).",
    });
  } else if (readsHeader === '') {
    pushProblem(problems, {
      severity: 'low',
      code: 'header_field_unspecified',
      message: "app.readsHeader isn't set, so header handling can't be checked yet.",
      path: 'app.readsHeader',
    });
  } else if (readsHeader === 'Stripe-Signature') {
    pushProblem(problems, {
      severity: 'low',
      code: 'header_case_note',
      message: "HTTP header names are case-insensitive, and virtually every framework normalizes them to lowercase before you read them, so \"Stripe-Signature\" written this way in your code is usually fine. Only worth a second look if you're doing a manual, case-sensitive string comparison somewhere, or forwarding raw headers through a proxy that preserves an unusual case.",
      path: 'app.readsHeader',
    });
  }

  // ── 7. tolerance and clock skew ─────────────────────────────────────
  if (tolerance === 0) {
    pushProblem(problems, {
      severity: 'high',
      code: 'tolerance_zero_disables_check',
      message: "app.tolerance is 0. Stripe's own docs warn against this explicitly: \"Don't use a tolerance value of 0. Using a tolerance value of 0 disables the recency check entirely\" — it doesn't make verification stricter, it turns the replay-attack protection off.",
      path: 'app.tolerance',
      value: 0,
      fix: 'Remove the custom tolerance argument to fall back to the library default (300 seconds), or set an explicit positive value.',
    });
  } else if (tolerance !== null && tolerance > 0 && tolerance < 60) {
    pushProblem(problems, {
      severity: 'medium',
      code: 'tolerance_very_low',
      message: `app.tolerance is ${tolerance} seconds — well under Stripe's own default of 300 seconds (5 minutes). Normal delivery/processing delay (network latency, a serverless cold start, request queuing) can exceed a window this tight, causing sporadic "Timestamp outside the tolerance zone" failures even when nothing is actually wrong.`,
      path: 'app.tolerance',
      value: tolerance,
    });
  }

  if (clockSkewSeconds !== null && clockSkewSeconds !== 0) {
    const tol = tolerance !== null ? tolerance : 300;
    const abs = Math.abs(clockSkewSeconds);
    if (tol > 0 && abs >= tol) {
      pushProblem(problems, {
        severity: 'high',
        code: 'clock_skew_exceeds_tolerance',
        message: `Your server clock is off from real time by about ${abs} second${abs === 1 ? '' : 's'} — at or beyond your ${tol}-second tolerance window. Stripe signs the timestamp into the header, so a skewed clock alone is enough to trigger "Timestamp outside the tolerance zone" even with a correct secret and an untouched body.`,
        path: 'app.clockSkewSeconds',
        value: clockSkewSeconds,
        fix: "Sync the server's clock via NTP (Network Time Protocol), per Stripe's own recommendation.",
      });
      fixes.push({ title: "Sync the server clock (NTP)", value: `Current skew: ~${abs}s against a ${tol}s tolerance`, where: 'Server / container host clock' });
    } else if (tol > 0 && abs >= tol / 2) {
      pushProblem(problems, {
        severity: 'medium',
        code: 'clock_skew_approaching_tolerance',
        message: `Your server clock is off by about ${abs} second${abs === 1 ? '' : 's'} — more than half of your ${tol}-second tolerance window. Not failing yet, but close enough that ordinary delivery delay could push individual requests over the edge.`,
        path: 'app.clockSkewSeconds',
        value: clockSkewSeconds,
      });
    }
  }

  // ── 8. proxy / runtime specifics ────────────────────────────────────
  if (proxy === 'lambda-apigw') {
    if (bodyBase64 === true) {
      if (!mentionsBase64Decode(snippet) && bodyHandling !== 'raw') {
        pushProblem(problems, {
          severity: 'medium',
          code: 'lambda_base64_decode_unconfirmed',
          message: "app.bodyBase64 is true, but nothing in what you've described confirms the base64-encoded body is being decoded before constructEvent runs. API Gateway's isBase64Encoded flag means event.body is a base64 string, not the raw payload bytes yet.",
          path: 'app.bodyBase64',
          fix: expected.bodyAccess.code || "Buffer.from(event.body, 'base64') before calling constructEvent.",
        });
      }
    } else if (bodyBase64 === null) {
      pushProblem(problems, {
        severity: 'low',
        code: 'lambda_base64_unknown',
        message: "API Gateway commonly base64-encodes the body before your Lambda sees it (isBase64Encoded: true), depending on your Content-Type and API Gateway's binary media type settings. Confirm whether yours does, and decode before calling constructEvent if so — Stripe's own troubleshooting docs give a Body Mapping Template for exactly this.",
        path: 'app.bodyBase64',
      });
    }
  }

  if (runtime === 'edge' || proxy === 'cloudflare' || framework === 'cloudflare-workers') {
    if (!usesConstructEventAsync(snippet)) {
      pushProblem(problems, {
        severity: 'high',
        code: 'edge_runtime_needs_construct_event_async',
        message: "Edge runtimes (Cloudflare Workers, Vercel Edge Functions, and similar) have no Node crypto module, only the async Web Crypto API. stripe-node's synchronous constructEvent() detects this and throws CryptoProviderOnlySupportsAsyncError, whose own message says: \"Use `await constructEventAsync(...)` instead of `constructEvent(...)`\".",
        path: 'app.runtime',
        fix: BODY_ACCESS['cloudflare-workers'].code,
      });
      fixes.push({ title: 'Use constructEventAsync on edge runtimes', value: BODY_ACCESS['cloudflare-workers'].code, where: framework === 'cloudflare-workers' ? 'Cloudflare Workers' : (runtime === 'edge' ? 'Edge runtime' : 'behind a Cloudflare proxy') });
    }
  }

  if (proxy === 'ngrok') {
    pushProblem(problems, {
      severity: 'low',
      code: 'ngrok_not_the_cause',
      message: "You're using ngrok. ngrok itself is a transparent TCP/HTTP tunnel and does not rewrite the request body. If you're seeing a raw-body mismatch behind ngrok, the cause is almost certainly your own body-parsing middleware or a devtools/logging proxy that pretty-prints JSON — not ngrok.",
      path: 'app.proxy',
    });
  }

  // ── 9. error-code-specific extra context ────────────────────────────
  if (errorCode === 'no_webhook_payload_provided') {
    pushProblem(problems, {
      severity: 'high',
      code: 'empty_request_body',
      message: 'The request body reaching your handler is empty. Common causes: another middleware or framework default already drained the body stream before your handler ran (leaving nothing to read a second time), a proxy or load balancer stripped the body on this request, or you triggered the endpoint with a GET/empty test request instead of an actual POST from Stripe or `stripe trigger`.',
      path: 'error.message',
      fix: 'Make sure nothing upstream reads the request body before your webhook handler does, and test with `stripe trigger payment_intent.succeeded` or a real Stripe-sent POST.',
    });
  }
  if (errorCode === 'unable_to_extract_timestamp_and_signatures' && readsHeader !== 'other' && readsHeader !== '') {
    pushProblem(problems, {
      severity: 'medium',
      code: 'header_value_malformed',
      message: "Stripe couldn't parse t=...,v1=... out of the header value your code passed in, even though you say you're reading the right header name. Log the raw header value directly before it reaches constructEvent — it may be empty, doubled up by a proxy that forwards it twice, or accidentally an array instead of a single string.",
      path: 'error.message',
    });
  }

  // ── checklist (always populated) ────────────────────────────────────
  checklist.push('Pass the raw request body — the exact bytes Stripe sent, before any JSON.parse or re-serialization — into constructEvent(). Stripe: "Any manipulation to the raw body of the request causes the verification to fail."');
  checklist.push('Confirm the whsec_ secret in your code matches the specific endpoint you are receiving from: a Dashboard-created endpoint and `stripe listen` each generate a different secret, and test/live modes each have their own secret even on the same endpoint URL.');
  if (expected.bodyAccess && expected.bodyAccess.note) checklist.push(expected.bodyAccess.note);
  checklist.push("Re-check after every deploy: a new global body-parser, an updated reverse proxy, or a changed env var can silently break raw-body access again.");

  const sorted = sortProblems(problems);
  const highCount = sorted.filter((p) => p.severity === 'high').length;
  const medCount = sorted.filter((p) => p.severity === 'medium').length;
  const lowCount = sorted.filter((p) => p.severity === 'low').length;

  let status = 'pass';
  if (highCount > 0) status = 'fail';
  else if (medCount > 0 || lowCount > 0) status = 'warn';

  let summary;
  if (status === 'pass') {
    summary = 'No mismatches found in what you described. Raw-body handling, the secret, the header, and timing all look consistent with a working signature check.';
  } else if (status === 'fail') {
    const top = sorted.find((p) => p.severity === 'high');
    summary = `${highCount} likely blocking cause${highCount > 1 ? 's' : ''} found. Most likely: ${top.message}`;
  } else {
    const top = sorted[0];
    summary = `Nothing blocking identified, but ${medCount + lowCount} thing${medCount + lowCount > 1 ? 's' : ''} worth checking. Top of the list: ${top.message}`;
  }

  return {
    status,
    summary,
    expected,
    problems: sorted,
    fixes,
    checklist,
    disclaimer:
      'Read-only, client-side analysis of the values you entered. Nothing is verified against your live Stripe account, deployed code, or server clock: always confirm by testing with `stripe trigger` or a real event before shipping. Not affiliated with Stripe.',
  };
}

/**
 * Standalone helper: just the expected values (framework label, secret
 * source guidance, exact raw-body recipe) for a config, without running the
 * full diagnostic. Handy for live-updating a preview as the user types.
 */
export function expectedValues(config) {
  const cfg = config && typeof config === 'object' ? config : {};
  return computeExpected(cfg);
}

// Also expose as a plain browser global when loaded via <script type="module">.
if (typeof window !== 'undefined') {
  window.StripeWebhookDoctor = { diagnose, expectedValues };
}
