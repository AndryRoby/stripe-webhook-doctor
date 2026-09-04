// tests.mjs — plain Node test runner for doctor-stripe.js (no external dependencies).
// Run with: node tests.mjs

import { diagnose, expectedValues } from './doctor-stripe.js';

let pass = 0;
let fail = 0;
const failures = [];

function ok(name, cond, detail) {
  if (cond) {
    pass++;
  } else {
    fail++;
    failures.push(`${name}${detail ? ' — ' + detail : ''}`);
  }
}

function eq(name, actual, expected) {
  const condition = actual === expected;
  ok(name, condition, condition ? '' : `expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
}

function has(name, arr, code) {
  const condition = Array.isArray(arr) && arr.some((p) => p.code === code);
  ok(name, condition, condition ? '' : `expected a problem with code "${code}", got codes [${(arr || []).map((p) => p.code).join(', ')}]`);
}

function lacks(name, arr, code) {
  const condition = Array.isArray(arr) && !arr.some((p) => p.code === code);
  ok(name, condition, condition ? '' : `did not expect a problem with code "${code}"`);
}

function severityOf(arr, code) {
  const p = (arr || []).find((x) => x.code === code);
  return p ? p.severity : undefined;
}

function messageOf(arr, code) {
  const p = (arr || []).find((x) => x.code === code);
  return p ? p.message : '';
}

// ─────────────────────────────────────────────────────────────────────────
// 1. expectedValues() — per-framework raw-body recipe
// ─────────────────────────────────────────────────────────────────────────

eq('nextjs-app: bodyAccess.code uses req.text()',
  /req\.text\(\)/.test(expectedValues({ app: { framework: 'nextjs-app' } }).bodyAccess.code), true);

eq('nextjs-pages: bodyAccess.code disables the default body parser',
  /bodyParser:\s*false/.test(expectedValues({ app: { framework: 'nextjs-pages' } }).bodyAccess.code), true);

eq('express: bodyAccess.code uses express.raw on the route',
  /express\.raw\(/.test(expectedValues({ app: { framework: 'express' } }).bodyAccess.code), true);

eq('fastify: bodyAccess.code overrides the content-type parser',
  /addContentTypeParser/.test(expectedValues({ app: { framework: 'fastify' } }).bodyAccess.code), true);

eq('nestjs: bodyAccess.code enables rawBody on the Nest app',
  /rawBody:\s*true/.test(expectedValues({ app: { framework: 'nestjs' } }).bodyAccess.code), true);

eq('django: bodyAccess.code reads request.body',
  /request\.body\b/.test(expectedValues({ app: { framework: 'django' } }).bodyAccess.code), true);

eq('flask: bodyAccess.code reads request.get_data()',
  /request\.get_data\(\)/.test(expectedValues({ app: { framework: 'flask' } }).bodyAccess.code), true);

eq('fastapi: bodyAccess.code reads await request.body()',
  /await request\.body\(\)/.test(expectedValues({ app: { framework: 'fastapi' } }).bodyAccess.code), true);

eq('rails: bodyAccess.code reads request.body.read',
  /request\.body\.read/.test(expectedValues({ app: { framework: 'rails' } }).bodyAccess.code), true);

eq('laravel: bodyAccess.code reads $request->getContent()',
  /getContent\(\)/.test(expectedValues({ app: { framework: 'laravel' } }).bodyAccess.code), true);

eq('go: bodyAccess.code reads io.ReadAll(req.Body)',
  /io\.ReadAll\(req\.Body\)/.test(expectedValues({ app: { framework: 'go' } }).bodyAccess.code), true);

eq('dotnet: bodyAccess.code reads Request.Body via StreamReader',
  /StreamReader\(Request\.Body\)/.test(expectedValues({ app: { framework: 'dotnet' } }).bodyAccess.code), true);

eq('vercel-function: bodyAccess.code disables the default body parser',
  /bodyParser:\s*false/.test(expectedValues({ app: { framework: 'vercel-function' } }).bodyAccess.code), true);

eq('netlify-function: bodyAccess.code checks isBase64Encoded',
  /isBase64Encoded/.test(expectedValues({ app: { framework: 'netlify-function' } }).bodyAccess.code), true);

eq('aws-lambda: bodyAccess.code checks isBase64Encoded',
  /isBase64Encoded/.test(expectedValues({ app: { framework: 'aws-lambda' } }).bodyAccess.code), true);

eq('cloudflare-workers: bodyAccess.code uses constructEventAsync',
  /constructEventAsync/.test(expectedValues({ app: { framework: 'cloudflare-workers' } }).bodyAccess.code), true);

eq('unrecognized/empty framework: bodyAccess.code is null',
  expectedValues({ app: { framework: 'made-up' } }).bodyAccess.code, null);

eq('expectedValues(undefined) does not throw and returns framework ""',
  expectedValues(undefined).framework, '');

// ─────────────────────────────────────────────────────────────────────────
// 2. diagnose() — defensive input handling
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose(undefined);
  ok('diagnose(undefined) does not throw and returns a status', typeof r.status === 'string');
}
{
  const r = diagnose({ error: null, app: null, code: null });
  ok('diagnose with all-null sections does not throw', typeof r.status === 'string');
}
{
  const r = diagnose({});
  has('empty config: flags missing error.message', r.problems, 'error_message_missing');
  eq('empty config: error_message_missing severity is low', severityOf(r.problems, 'error_message_missing'), 'low');
}
{
  const r = diagnose({ error: { message: 'some totally different error' } });
  has('unrecognized error text is flagged', r.problems, 'error_message_unrecognized');
  eq('unrecognized error text severity is low', severityOf(r.problems, 'error_message_unrecognized'), 'low');
}
{
  const r = diagnose({ error: { message: 'No signatures found matching the expected signature for payload' } });
  lacks('a recognized error string is not flagged as unrecognized', r.problems, 'error_message_unrecognized');
  lacks('a recognized error string is not flagged as missing', r.problems, 'error_message_missing');
}

// ─────────────────────────────────────────────────────────────────────────
// 3. diagnose() — raw body integrity
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ app: { framework: 'express', bodyHandling: 'parsed-json' } });
  has('parsed-json body handling is flagged high', r.problems, 'raw_body_parsed_json');
  eq('raw_body_parsed_json severity is high', severityOf(r.problems, 'raw_body_parsed_json'), 'high');
  const fix = r.fixes.find((f) => f.title.includes('Read the raw body for Express'));
  ok('a fix offers the Express raw-body snippet', !!fix && /express\.raw\(/.test(fix.value));
}
{
  const r = diagnose({ app: { bodyHandling: 'string-reserialized' } });
  has('string-reserialized body handling is flagged high', r.problems, 'raw_body_reserialized');
  eq('raw_body_reserialized severity is high', severityOf(r.problems, 'raw_body_reserialized'), 'high');
}
{
  const r = diagnose({ app: { bodyHandling: 'unknown' } });
  has('unknown body handling is flagged low', r.problems, 'raw_body_unknown');
  eq('raw_body_unknown severity is low', severityOf(r.problems, 'raw_body_unknown'), 'low');
}
{
  const r = diagnose({ app: { bodyHandling: 'raw' } });
  lacks('raw body handling is not flagged', r.problems, 'raw_body_parsed_json');
  lacks('raw body handling is not flagged as reserialized', r.problems, 'raw_body_reserialized');
  lacks('raw body handling is not flagged as unknown', r.problems, 'raw_body_unknown');
}
{
  const r = diagnose({ app: { usesBodyParserGlobally: true, framework: 'express' } });
  has('global body parser is flagged high', r.problems, 'global_body_parser_before_webhook');
  eq('global_body_parser_before_webhook severity is high', severityOf(r.problems, 'global_body_parser_before_webhook'), 'high');
}
{
  const r = diagnose({ app: { usesBodyParserGlobally: false } });
  lacks('body parser explicitly not-global is not flagged', r.problems, 'global_body_parser_before_webhook');
}
{
  const r = diagnose({ app: { usesBodyParserGlobally: null } });
  lacks('unknown (null) body-parser-globally is not flagged', r.problems, 'global_body_parser_before_webhook');
}

// ─────────────────────────────────────────────────────────────────────────
// 4. diagnose() — Next.js App Router / Pages Router specifics
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ app: { framework: 'nextjs-app' }, code: { snippet: "const body = await req.json();" } });
  has('App Router using req.json() is flagged high', r.problems, 'nextjs_app_router_req_json_not_text');
  eq('nextjs_app_router_req_json_not_text severity is high', severityOf(r.problems, 'nextjs_app_router_req_json_not_text'), 'high');
}
{
  const r = diagnose({ app: { framework: 'nextjs-app' }, code: { snippet: "const body = await req.text();" } });
  lacks('App Router using req.text() correctly is not flagged', r.problems, 'nextjs_app_router_req_json_not_text');
}
{
  const r = diagnose({ app: { framework: 'nextjs-app' }, code: { snippet: "const body = req.text();" } });
  has('App Router calling req.text() without await is flagged', r.problems, 'missing_await_on_text');
  eq('missing_await_on_text severity is medium', severityOf(r.problems, 'missing_await_on_text'), 'medium');
}
{
  const r = diagnose({ app: { framework: 'nextjs-app' }, code: { snippet: "const body = await req.text();" } });
  lacks('await req.text() is not flagged as missing await', r.problems, 'missing_await_on_text');
}
{
  const r = diagnose({ app: { framework: 'nextjs-pages' } });
  has('Pages Router with no info at all defaults to flagging bodyParser not disabled', r.problems, 'nextjs_pages_router_bodyparser_not_disabled');
}
{
  const r = diagnose({ app: { framework: 'nextjs-pages', bodyHandling: 'raw' } });
  lacks('Pages Router with bodyHandling raw is not flagged', r.problems, 'nextjs_pages_router_bodyparser_not_disabled');
}
{
  const r = diagnose({ app: { framework: 'nextjs-pages' }, code: { snippet: 'export const config = { api: { bodyParser: false } };' } });
  lacks('Pages Router snippet with bodyParser:false is not flagged', r.problems, 'nextjs_pages_router_bodyparser_not_disabled');
}

// ─────────────────────────────────────────────────────────────────────────
// 5. diagnose() — framework-agnostic code-snippet heuristics
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ code: { snippet: 'const parsed = JSON.parse(body); stripe.webhooks.constructEvent(parsed, sig, secret);' } });
  has('JSON.parse before constructEvent is flagged high', r.problems, 'snippet_json_parse_before_construct_event');
  eq('snippet_json_parse_before_construct_event severity is high', severityOf(r.problems, 'snippet_json_parse_before_construct_event'), 'high');
}
{
  const r = diagnose({ code: { snippet: 'stripe.webhooks.constructEvent(raw, sig, secret); const other = JSON.parse(somethingElse);' } });
  lacks('JSON.parse appearing after constructEvent is not flagged', r.problems, 'snippet_json_parse_before_construct_event');
}
{
  const r = diagnose({ app: { framework: 'express' }, code: { snippet: "app.use(express.json());" } });
  has('global express.json() detected in snippet is flagged when usesBodyParserGlobally is unset', r.problems, 'snippet_global_json_parser_detected');
}
{
  const r = diagnose({ app: { framework: 'express', usesBodyParserGlobally: true }, code: { snippet: "app.use(express.json());" } });
  lacks('snippet-based global-parser flag does not double up once usesBodyParserGlobally is already set', r.problems, 'snippet_global_json_parser_detected');
}
{
  const r = diagnose({ app: { framework: 'express', bodyHandling: 'unknown' }, code: { snippet: "stripe.webhooks.constructEvent(req.body, sig, secret);" } });
  has('Express passing req.body with unconfirmed raw handling is flagged medium', r.problems, 'snippet_reqbody_not_confirmed_raw');
  eq('snippet_reqbody_not_confirmed_raw severity is medium', severityOf(r.problems, 'snippet_reqbody_not_confirmed_raw'), 'medium');
}
{
  const r = diagnose({ app: { framework: 'express', bodyHandling: 'raw' }, code: { snippet: "stripe.webhooks.constructEvent(req.body, sig, secret);" } });
  lacks('Express passing req.body with confirmed raw handling is not flagged', r.problems, 'snippet_reqbody_not_confirmed_raw');
}

// ─────────────────────────────────────────────────────────────────────────
// 6. diagnose() — secret source and format
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ app: { secretPrefix: 'sk_' } });
  has('sk_ secret prefix is flagged high', r.problems, 'secret_is_api_key_not_whsec');
  eq('secret_is_api_key_not_whsec severity is high', severityOf(r.problems, 'secret_is_api_key_not_whsec'), 'high');
}
{
  const r = diagnose({ app: { secretPrefix: 'pk_' } });
  has('pk_ secret prefix is flagged high', r.problems, 'secret_is_api_key_not_whsec');
}
{
  const r = diagnose({ app: { secretPrefix: 'whsec_' } });
  lacks('whsec_ secret prefix is not flagged as an API key', r.problems, 'secret_is_api_key_not_whsec');
  lacks('whsec_ secret prefix is not flagged as unrecognized', r.problems, 'secret_prefix_unrecognized');
}
{
  const r = diagnose({ app: { secretPrefix: 'other' } });
  has('unrecognized secret prefix is flagged medium', r.problems, 'secret_prefix_unrecognized');
  eq('secret_prefix_unrecognized severity is medium', severityOf(r.problems, 'secret_prefix_unrecognized'), 'medium');
}
{
  const r = diagnose({ app: { secretSource: 'env-unset' } });
  has('unset secret env var is flagged high', r.problems, 'secret_env_unset');
  eq('secret_env_unset severity is high', severityOf(r.problems, 'secret_env_unset'), 'high');
}
{
  const r = diagnose({ app: { secretSource: 'cli-listen', mode: 'live' } });
  has('CLI secret used in live mode is flagged high', r.problems, 'cli_secret_in_live_mode');
  eq('cli_secret_in_live_mode severity is high', severityOf(r.problems, 'cli_secret_in_live_mode'), 'high');
}
{
  const r = diagnose({ app: { secretSource: 'cli-listen', mode: 'test' } });
  lacks('CLI secret used in test mode is not flagged', r.problems, 'cli_secret_in_live_mode');
}
{
  const r = diagnose({ app: { secretSource: 'dashboard-endpoint', mode: 'live' } });
  lacks('Dashboard secret in live mode is not flagged', r.problems, 'cli_secret_in_live_mode');
}
{
  const r = diagnose({ app: { endpointsCount: 3 } });
  has('more than one endpoint is flagged low', r.problems, 'multiple_endpoints_hint');
  eq('multiple_endpoints_hint severity is low', severityOf(r.problems, 'multiple_endpoints_hint'), 'low');
}
{
  const r = diagnose({ app: { endpointsCount: 1 } });
  lacks('exactly one endpoint is not flagged', r.problems, 'multiple_endpoints_hint');
}

// ─────────────────────────────────────────────────────────────────────────
// 7. diagnose() — Stripe-Signature header
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ app: { readsHeader: 'other' } });
  has('reading the wrong header is flagged high', r.problems, 'header_not_stripe_signature');
  eq('header_not_stripe_signature severity is high', severityOf(r.problems, 'header_not_stripe_signature'), 'high');
}
{
  const r = diagnose({ app: { readsHeader: 'stripe-signature' } });
  lacks('reading the correct lowercase header is not flagged', r.problems, 'header_not_stripe_signature');
  lacks('reading the correct lowercase header has no case note', r.problems, 'header_case_note');
}
{
  const r = diagnose({ app: { readsHeader: 'Stripe-Signature' } });
  has('reading the capitalized header name gets an informational note', r.problems, 'header_case_note');
  eq('header_case_note severity is low', severityOf(r.problems, 'header_case_note'), 'low');
}
{
  const r = diagnose({ app: { readsHeader: '' } });
  has('unset readsHeader is flagged low', r.problems, 'header_field_unspecified');
}

// ─────────────────────────────────────────────────────────────────────────
// 8. diagnose() — tolerance and clock skew
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ app: { tolerance: 0 } });
  has('tolerance of 0 is flagged high', r.problems, 'tolerance_zero_disables_check');
  eq('tolerance_zero_disables_check severity is high', severityOf(r.problems, 'tolerance_zero_disables_check'), 'high');
}
{
  const r = diagnose({ app: { tolerance: 300 } });
  lacks('default tolerance of 300 is not flagged as zero', r.problems, 'tolerance_zero_disables_check');
  lacks('default tolerance of 300 is not flagged as too low', r.problems, 'tolerance_very_low');
}
{
  const r = diagnose({ app: { tolerance: 10 } });
  has('a very low positive tolerance is flagged medium', r.problems, 'tolerance_very_low');
  eq('tolerance_very_low severity is medium', severityOf(r.problems, 'tolerance_very_low'), 'medium');
}
{
  const r = diagnose({ app: { clockSkewSeconds: 400, tolerance: 300 } });
  has('clock skew beyond tolerance is flagged high', r.problems, 'clock_skew_exceeds_tolerance');
  eq('clock_skew_exceeds_tolerance severity is high', severityOf(r.problems, 'clock_skew_exceeds_tolerance'), 'high');
}
{
  const r = diagnose({ app: { clockSkewSeconds: 200, tolerance: 300 } });
  has('clock skew over half of tolerance is flagged medium', r.problems, 'clock_skew_approaching_tolerance');
  eq('clock_skew_approaching_tolerance severity is medium', severityOf(r.problems, 'clock_skew_approaching_tolerance'), 'medium');
}
{
  const r = diagnose({ app: { clockSkewSeconds: 5, tolerance: 300 } });
  lacks('negligible clock skew is not flagged', r.problems, 'clock_skew_exceeds_tolerance');
  lacks('negligible clock skew is not flagged as approaching', r.problems, 'clock_skew_approaching_tolerance');
}
{
  const r = diagnose({ app: { clockSkewSeconds: 0 } });
  lacks('zero clock skew is not flagged', r.problems, 'clock_skew_exceeds_tolerance');
}
{
  const r = diagnose({ app: { clockSkewSeconds: null } });
  lacks('unset clock skew is not flagged', r.problems, 'clock_skew_exceeds_tolerance');
}

// ─────────────────────────────────────────────────────────────────────────
// 9. diagnose() — Lambda/API Gateway base64 and edge runtimes
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ app: { proxy: 'lambda-apigw', bodyBase64: null } });
  has('unknown base64 status on Lambda/API Gateway is flagged low', r.problems, 'lambda_base64_unknown');
}
{
  const r = diagnose({ app: { proxy: 'lambda-apigw', bodyBase64: true, bodyHandling: 'unknown' } });
  has('base64 body with no confirmed decode step is flagged medium', r.problems, 'lambda_base64_decode_unconfirmed');
  eq('lambda_base64_decode_unconfirmed severity is medium', severityOf(r.problems, 'lambda_base64_decode_unconfirmed'), 'medium');
}
{
  const r = diagnose({ app: { proxy: 'lambda-apigw', bodyBase64: true, bodyHandling: 'raw' } });
  lacks('base64 body with raw handling confirmed is not flagged', r.problems, 'lambda_base64_decode_unconfirmed');
}
{
  const r = diagnose({ app: { proxy: 'lambda-apigw', bodyBase64: false } });
  lacks('non-base64 Lambda body is not flagged', r.problems, 'lambda_base64_decode_unconfirmed');
  lacks('non-base64 Lambda body is not flagged as unknown', r.problems, 'lambda_base64_unknown');
}
{
  const r = diagnose({ app: { runtime: 'edge' }, code: { snippet: 'stripe.webhooks.constructEvent(body, sig, secret);' } });
  has('edge runtime using sync constructEvent is flagged high', r.problems, 'edge_runtime_needs_construct_event_async');
  eq('edge_runtime_needs_construct_event_async severity is high', severityOf(r.problems, 'edge_runtime_needs_construct_event_async'), 'high');
}
{
  const r = diagnose({ app: { runtime: 'edge' }, code: { snippet: 'await stripe.webhooks.constructEventAsync(body, sig, secret);' } });
  lacks('edge runtime already using constructEventAsync is not flagged', r.problems, 'edge_runtime_needs_construct_event_async');
}
{
  const r = diagnose({ app: { framework: 'cloudflare-workers' } });
  has('Cloudflare Workers framework alone (no snippet) is flagged', r.problems, 'edge_runtime_needs_construct_event_async');
}
{
  const r = diagnose({ app: { runtime: 'node' } });
  lacks('plain Node runtime is not flagged for async construct', r.problems, 'edge_runtime_needs_construct_event_async');
}
{
  const r = diagnose({ app: { proxy: 'ngrok' } });
  has('ngrok proxy gets a reassuring low-severity note', r.problems, 'ngrok_not_the_cause');
  eq('ngrok_not_the_cause severity is low', severityOf(r.problems, 'ngrok_not_the_cause'), 'low');
}

// ─────────────────────────────────────────────────────────────────────────
// 10. diagnose() — error-message-specific extra context
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({ error: { message: 'No webhook payload was provided.' } });
  has('empty-payload error text is flagged high', r.problems, 'empty_request_body');
  eq('empty_request_body severity is high', severityOf(r.problems, 'empty_request_body'), 'high');
}
{
  const r = diagnose({ error: { message: 'Unable to extract timestamp and signatures from header' }, app: { readsHeader: 'stripe-signature' } });
  has('malformed-header error with a correctly-named header gets a follow-up hint', r.problems, 'header_value_malformed');
}
{
  const r = diagnose({ error: { message: 'Unable to extract timestamp and signatures from header' }, app: { readsHeader: 'other' } });
  lacks('malformed-header error already explained by the wrong header name does not double up', r.problems, 'header_value_malformed');
}
{
  const r = diagnose({ error: { message: 'Timestamp outside the tolerance zone' } });
  eq('timestamp-outside-tolerance error text alone does not throw', typeof diagnose({ error: { message: 'Timestamp outside the tolerance zone' } }).status, 'string');
}
{
  const r = diagnose({ error: { message: 'Webhook payload must be provided as a string or a Buffer' } });
  ok('payload-must-be-string-or-buffer error still returns a status', typeof r.status === 'string');
}

// ─────────────────────────────────────────────────────────────────────────
// 11. diagnose() — overall status + summary
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({
    error: { message: 'No signatures found matching the expected signature for payload' },
    app: {
      framework: 'express', bodyHandling: 'raw', usesBodyParserGlobally: false,
      readsHeader: 'stripe-signature', secretSource: 'dashboard-endpoint', secretPrefix: 'whsec_',
      mode: 'live', endpointsCount: 1, tolerance: 300, runtime: 'node', proxy: 'none',
      bodyBase64: null, clockSkewSeconds: 0,
    },
    code: { snippet: "app.post('/webhook', express.raw({type:'application/json'}), (req,res)=>{ stripe.webhooks.constructEvent(req.body, req.headers['stripe-signature'], secret); });" },
  });
  eq('a fully clean config yields status "pass"', r.status, 'pass');
  ok('pass summary says no mismatches found', /No mismatches found/.test(r.summary));
  eq('a passing diagnosis reports zero problems', r.problems.length, 0);
}
{
  const r = diagnose({ app: { readsHeader: 'Stripe-Signature' } });
  eq('a single low-severity finding yields status "warn"', r.status, 'warn');
}
{
  const r = diagnose({ app: { secretPrefix: 'sk_' } });
  eq('any high-severity finding yields status "fail"', r.status, 'fail');
  ok('fail summary names a likely blocking cause', /likely blocking cause/.test(r.summary));
}
{
  const r = diagnose({ app: { secretPrefix: 'sk_', tolerance: 0, readsHeader: 'other' } });
  eq('several high-severity problems at once still yield a single "fail" status', r.status, 'fail');
  ok('several high-severity codes are all present', ['secret_is_api_key_not_whsec', 'tolerance_zero_disables_check', 'header_not_stripe_signature'].every((c) => r.problems.some((p) => p.code === c)));
}

// ─────────────────────────────────────────────────────────────────────────
// 12. diagnose() — checklist and sort order
// ─────────────────────────────────────────────────────────────────────────

{
  const r = diagnose({});
  ok('checklist has generic guidance even with no input at all', r.checklist.length >= 3);
}
{
  const r = diagnose({ app: { framework: 'express' } });
  ok('checklist includes the framework-specific raw-body note once a framework is known', r.checklist.some((c) => /express\.raw/i.test(c) || /Express/.test(c)));
}
{
  const r = diagnose({ app: { secretPrefix: 'sk_' }, error: { message: '' } });
  eq('sorted problems: first entry is high severity', r.problems[0].severity, 'high');
  eq('sorted problems: last entry is not higher severity than the first', SEVERITY_RANK(r.problems[r.problems.length - 1].severity) >= SEVERITY_RANK(r.problems[0].severity), true);
}

function SEVERITY_RANK(s) {
  return { high: 0, medium: 1, low: 2 }[s];
}

// ─────────────────────────────────────────────────────────────────────────

console.log(`\n${pass} passed, ${fail} failed`);
if (fail > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  - ${f}`);
  process.exit(1);
} else {
  console.log('All tests passed.');
}
