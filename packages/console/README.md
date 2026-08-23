# @hemlig/console

Browser management interface for the Hemlig administrator API.

It is an ordinary HTTP client of a public API and nothing else: no server, no
AWS credentials, no AWS SDK, and no access to DynamoDB, S3, or KMS. Everything
it can do, it does through the contract in
[`openapi/consumer-secrets.yaml`](../../openapi/consumer-secrets.yaml).

See [the console plan](../../docs/console-plan.md) for the boundary this sits
behind and why.

## Local development

MiniStack provides DynamoDB, S3, and KMS but no API Gateway and no identity
provider, so the console cannot obtain a real token or reach a deployed route.
A dev bridge invokes the matching admin or audit-query handler in process
instead.

```sh
yarn ministack:up      # once
yarn dev:api           # provisions hml-local resources, serves the API bridge on :5274
yarn dev:ui            # serves the console on :5273
```

The bridge fabricates the JWT claims API Gateway would normally have validated.
That is exactly the control it bypasses, so it binds to loopback only, refuses
to start unless `AWS_ENDPOINT_URL` is local, unsets any ambient `AWS_PROFILE`,
and is never bundled into a Lambda or the published construct. `config.json`
likewise refuses `dev-bridge` mode against a non-loopback API.

What this cannot exercise: mTLS, the JWT authorizer, CORS preflight against the
real `$default` route, Object Lock retention behaviour, or IAM. Those need the
isolated AWS acceptance environment.

## Rules that are not obvious

These come from properties of the service. Changing them will break correctness
in ways that are hard to see. Each is enforced by a test.

**Environments are administrator-defined, not configuration.** They used to be a
static list baked into `config.json`; they are now `GET`/`POST
/v1/admin/environments` records in DynamoDB, bounded to 100, each recording
who created it. A fresh deployment starts with **none**. Because every screen
is scoped to one environment, `/` is a resolver (`RootResolver.vue`), not a
redirect: it waits for a session, loads the list once through the shared
`useEnvironmentsQuery` cache entry, and either sends the operator to their
remembered environment (falling back to the first one if that name no longer
exists), renders a first-run panel prompting them to create one, or shows the
load failure with its correlation ID and a retry — it never guesses a name to
redirect into. Do not fetch the list inside `store.initialize()`: that runs
before sign-in, and in OIDC mode there is no session yet to authenticate the
call with.

**Nothing auto-refreshes.** Every administrator request writes attempted,
authorized, and terminal audit objects into an Object Lock Compliance archive
that cannot be deleted for seven years. `refetchInterval`,
`refetchOnWindowFocus`, `refetchOnReconnect`, and `refetchOnMount` are off
globally in `main.ts`. Do not turn them on. Do not add an N+1: a list view
renders from its page response only. One catalog render costs three permanent
objects; per-row detail fetches on a 100-row page would cost three hundred.

**Idempotency is asymmetric.** Secret create, update, and payload routes
hard-conflict on a reused key and never replay the original response, so an
ambiguous outcome must be resolved by re-reading and comparing
`controlVersionId` — never by retrying. Consumer enroll, rotate, and revoke do
replay by key, so retrying the same key is correct there.
`useGuardedMutation` encodes both halves; pick the right `family`.

**A `412` is never retried automatically.** It means someone else advanced the
control revision. The draft is preserved and the decision handed to the
administrator. Silently re-reading and resubmitting would defeat optimistic
concurrency.

**An empty page does not mean no results.** The catalog and consumer queries
filter after a bounded read, so a page can be empty while a cursor is still
outstanding. `useCursorPages` chases cursors until it has something to show,
within a hop budget. Never render "no results" before `exhausted`.

**Payload values never leave the editor component.** Not the store, the query
cache, the URL, router state, browser storage, or an error message. They are
cleared on unmount.

Reading a payload is possible — `GET /v1/admin/secrets/{id}/payload` decrypts
and returns it — but it is a deliberate, separately audited action, so the
editor loads values only when the operator explicitly asks. Do not fetch a
payload to render a list, a preview, or a diff: each read writes permanent
audit evidence naming the administrator who did it.

**The in-browser CSR generator's private key never leaves the modal, either.**
`CsrGeneratorModal.vue` generates the key pair with WebCrypto and builds the
PKCS#10 CSR itself (`src/api/csr-generate.ts`), since Hemlig only ever wants
the public key. The private key is held in local component state for a
one-time copy/download, cleared on close and on unmount, and is never written
to the store, the query cache, the URL, or localStorage/sessionStorage/
IndexedDB/cookies — the same rule as payload values above, for the same
reason. Pasting a CSR generated on the consumer host remains the stronger
option: it means a consumer's private key never exists in an administrator's
browser at all, which the in-browser generator cannot claim. That is why
pasting stays the default path in both the enrollment and rotation flows, and
generation is one deliberate click away rather than the other way around.

`csr-generate.ts` writes the CSR's DER by hand rather than pulling in
`@peculiar/x509` or `pkijs`: a bug in an ASN.1 _parser_ can be dangerous
(malformed input coerced into wrongly validating), but a bug in a _writer_
can only produce bytes that fail to parse, and this output is verified twice
— once by the test suite against node-forge, the same library the service
uses server-side, and again by the service itself on submit. See the header
comment in `csr-generate.ts` for the full reasoning, including the point
where hand-rolling stops being proportionate (real certificate extensions)
and `@peculiar/x509` becomes the right swap.

**`401` and `403` are different.** API Gateway rejects a bad token itself with
a bare `401` and no error envelope — re-authenticate. A `403` can only come
from the handler rejecting a token the gateway already accepted, which is a
deployment configuration mismatch; re-authenticating would loop.

**The dev configuration never ships.** `dev-config.json` is served at
`/config.json` by a dev-server plugin and deliberately does not live in
`public/`, because everything there is copied into `dist/`. The dev document is
_valid_ — loopback API, no identity provider — so a deployed console that
picked it up would boot cleanly and quietly talk to nothing instead of failing
loudly. The deployed `config.json` is generated by the CDK stack.

**Never test against a real deployment's administrator API.** Every request
writes permanent audit evidence.

**Silent token renewal is a separate document, not an SPA route.** The
identity provider redirects the hidden renewal iframe back to
`/silent.html`, so the console ends up framing its own origin — something
the default `frame-ancestors 'none'` forbids. That path needs its own
`frame-ancestors 'self'` response-headers policy, distinct from every other
path, so it cannot be the same SPA document the rest of the app is served
from. `src/silent.ts` is a standalone entry with no router, store, or Vue
app; see `vite.config.ts`'s multi-page `rollupOptions.input`.

## Commands

```sh
yarn dev      # vite dev server on 127.0.0.1:5273
yarn build    # type-check and bundle to dist/
yarn lint     # vue-tsc --noEmit
yarn test     # vitest
```

The published Content-Security-Policy forbids inline script and style, so the
build inlines nothing into `index.html` and runtime configuration is fetched
from `/config.json` rather than templated in.
