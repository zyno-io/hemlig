# AWS acceptance runbook

MiniStack exercises the AWS SDK integrations — envelope encryption, conditional
S3 writes, DynamoDB transactions, idempotency, recovery — against a local
emulator. It is deliberately not the authority for anything enforced by AWS
itself.

This runbook covers what only a real deployment can prove. Run it in an
isolated account before any production use. The gates are ordered so that a
failure stops you at the cheapest point: gate 1 breaks every subsequent gate,
so do not skip ahead.

Each gate states what to run, what a pass looks like, and what a failure means.
Where a failure has a known remedy that is more than "fix the typo", it is
written down — several of these have non-obvious fixes.

## What MiniStack already covers

Do not re-test these here; they are covered by `yarn test` and
`yarn ministack:verify`:

- KMS `GenerateDataKey`/`Decrypt`, AES-256-GCM payload envelopes, encryption
  context binding
- Conditional immutable S3 revision writes and checksum verification
- DynamoDB conditional writes, transactions, leases, idempotency records
- The prepared-revision mutation protocol and recovery of expired workflows
- Catalog, consumer, identity, and revision index queries
- The admin handler's routing, validation, and error envelopes

## Prerequisites

- An isolated AWS account. Nothing here should run beside anything you care
  about: it creates Object Lock Compliance buckets, whose objects cannot be
  deleted for the configured retention.
- A hosted zone you control, and the ability to delegate it if the stack
  creates one.
- An identity-provider application registration that can issue an **access
  token** — not just an ID token — carrying the configured audience and the
  `oidcAdminScope`. This is the most common source of a failed gate 2.
- An ACM certificate in **us-east-1** covering the console FQDN, unless the
  stack has a concrete `env` and you supplied `existingHostedZoneId`. See
  [the deployment guide](cdk-integration.md#console-hosting).

## Gate 0 — the stack deploys

```sh
yarn cdk:deploy \
  -c environment=acc \
  -c adminFqdn=admin.acc.example.com \
  -c apiFqdn=api.acc.example.com \
  -c consoleFqdn=acc.example.com \
  -c zoneDomain=acc.example.com \
  -c existingHostedZoneId=ZXXXXXXXXXXXXX \
  -c oidcIssuer=https://login.example.com/tenant/v2.0 \
  -c oidcAudience=api://hemlig \
  -c oidcAdminScope=hemlig.admin \
  -c oidcClientId=<client-id> \
  -c consoleCertificateArn=arn:aws:acm:us-east-1:<account>:certificate/<id>
```

**Pass:** the stack completes and outputs `ConsoleUrl`, `AdminUrl`,
`DeliveryUrl`, `ConsoleDistributionId`.

**If `ConsoleAssetsPending` appears in the outputs**, the console build output
was missing at synth time and the distribution has no objects. Every request
will 403, including the error page. Run `yarn console:build` and redeploy —
`build:cdk` should have done this for you, so investigate why it did not.

## Gate 1 — CORS preflight

**This is the highest-risk item in the whole deployment.** Everything after it
depends on it, and it cannot be tested locally because MiniStack has no API
Gateway.

The admin API uses a `$default` catch-all route with a JWT authorizer. A
`$default` route also catches `OPTIONS`, so an authorized preflight would fail
with `401` before reaching anything. The stack adds an explicit unauthenticated
`OPTIONS /{proxy+}` route to outrank it.

```sh
curl -i -X OPTIONS https://admin.acc.example.com/v1/admin/secrets \
  -H 'origin: https://acc.example.com' \
  -H 'access-control-request-method: POST' \
  -H 'access-control-request-headers: authorization,idempotency-key,if-match'
```

**Pass:** `204`, with `access-control-allow-origin: https://acc.example.com`,
the four methods, the four allowed headers, and `access-control-expose-headers:
etag`.

**Fail — `401`:** the explicit OPTIONS route is not outranking `$default`.
Confirm the route exists and has `AuthorizationType: NONE`.

**Fail — `204` but no `access-control-allow-origin`:** API Gateway is not
attaching the configured CORS headers to an integration response on an explicit
OPTIONS route. This is the failure mode to watch for, and the obvious fix does
not work — AWS ignores CORS headers returned by the integration when CORS is
configured on the API. The remedy is to stop using a catch-all: replace
`defaultIntegration`/`$default` with explicit per-route definitions for each
admin path and method, so no route matches `OPTIONS` and API Gateway answers
preflight itself. Doing that puts an unauthenticated fall-through next to
authorized routes, so every route must be listed explicitly and reviewed.

Also confirm the preflight wrote no audit evidence — it must not, because it is
a browser capability check, not an administrator action:

```sh
aws s3 ls s3://<audit-bucket>/audit/ --recursive | wc -l   # before and after
```

## Gate 2 — the access token is the right shape

```sh
TOKEN=<access token from your provider>
python3 -c "import base64,json,sys;p=sys.argv[1].split('.')[1];print(json.dumps(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))),indent=1))" "$TOKEN"
```

**Pass:** `aud` equals the configured `oidcAudience`, `iss` equals
`oidcIssuer` exactly, and `scp` or `scope` contains `oidcAdminScope`.

**Fail — `aud` is the client ID, or the token is an ID token:** you requested
the wrong thing. Ask for a resource-scoped access token: on Entra request the
API registration's delegated scope, for example
`api://<application-id>/hemlig.admin`; use an `audience` parameter on Auth0 or
a custom API scope on Okta. Entra returns the short `hemlig.admin` value in
`scp`, which is the value Hemlig enforces.

**Fail — `iss` differs by a trailing slash or a `/v2.0` suffix:** the handler
compares issuers exactly. Match the string the provider actually emits.

Then:

```sh
curl -s -o /dev/null -w '%{http_code}\n' https://admin.acc.example.com/v1/admin/secrets?environment=dev \
  -H "authorization: Bearer $TOKEN"
```

**Pass:** `200`.

**`401`** means API Gateway rejected the token before Lambda — audience,
signature, expiry, or missing scope. **`403`** means the gateway accepted it and
the handler refused it, which is gateway/Lambda configuration drift: the two
disagree about issuer, audience, or scope. Re-authenticating will not fix a
`403`.

## Gate 3 — the console loads and reads

Open `https://acc.example.com`.

**Pass:** the shell renders, sign-in redirects to the provider and returns, and
the secrets catalog loads. `/config.json` returns the deployed configuration —
confirm `auth.mode` is `oidc` and `adminApiUrl` is the admin FQDN, **not** a
loopback address:

```sh
curl -s https://acc.example.com/config.json
```

**Fail — `adminApiUrl` is `http://127.0.0.1:5274`:** the local development
configuration reached the bucket. It should be impossible — it is not in the
build output and the asset source excludes it — but it would boot cleanly and
silently talk to nothing, so it is worth one look.

Confirm the shell is not edge-cached:

```sh
curl -sI https://acc.example.com/ | grep -i 'cache-control\|x-cache'
```

**Pass:** `cache-control: no-store`. A cached shell means the default behavior
is not `CACHING_DISABLED`, and a console deploy will not reach browsers.

## Gate 4 — silent renew survives the provider redirect

The subtlest failure here. Renewal loads the provider in a hidden iframe, and
the provider redirects that iframe back to `https://acc.example.com/silent.html`.
Two separate CSP directives must both allow it: the parent's `frame-src` must
name `'self'` for the navigation back, and the callback document's
`frame-ancestors` must be `'self'` for the embedding.

```sh
curl -sI https://acc.example.com/silent.html | grep -i content-security-policy
curl -sI https://acc.example.com/          | grep -i content-security-policy
```

**Pass:** both carry `frame-src 'self' https://<issuer-origin>`; `/silent.html`
carries `frame-ancestors 'self'` and `/` carries `frame-ancestors 'none'`.

Then leave the console open past the access token's lifetime, with the browser
console visible.

**Pass:** the session continues without a redirect, and no CSP violation is
reported.

**Fail — a `frame-src` violation:** the redirect back to the console origin was
blocked. Renewal never completes, so requests go out with no bearer token and
get `401` — worse than the full-redirect fallback this is meant to preserve.

**Fail — renewal blocked by the provider or third-party cookie policy:** some
providers refuse to be framed at all. The redirect fallback still works but
interrupts the session; decide whether that is acceptable, and if not, revisit
the decision to persist no refresh token.

## Gate 5 — mutation semantics

Create a secret, set a payload, then edit metadata. The console does this in
three screens; the point is to confirm the properties the UI depends on.

**Pass:**

- A metadata-only edit leaves `payloadKeyCount` unchanged. If it disappears, the
  inheritance in `SecretService.update` regressed and the console's destructive
  edit warning goes blind.
- A stale `If-Match` returns `412`, and the console shows the concurrency panel
  with the draft preserved rather than silently reloading.
- Reusing an idempotency key on a secret route returns `409` and does **not**
  replay the original response. The console must reconcile by re-reading, not
  retry.
- Reusing one on a consumer route **does** replay the recorded result.

## Gate 6 — mutual TLS

Enroll a consumer through the console with a CSR you generated locally, then
exercise the delivery API with three certificates:

| Certificate | Expected |
| --- | --- |
| the issued, active leaf | `200` with the payload |
| the same leaf after revoking it in the console | rejected, immediately — no truststore propagation wait |
| a leaf signed by an unrelated CA | rejected at TLS |

**Pass:** all three. Revocation is a strongly consistent DynamoDB read, so the
second case must take effect on the very next request.

Also confirm the default `execute-api` endpoints are disabled on both APIs — a
request to the raw `https://<api-id>.execute-api.<region>.amazonaws.com` URL
must fail.

## Gate 7 — IAM boundaries

These are the controls MiniStack cannot evaluate at all.

**Pass:**

- The admin and delivery roles can `PutObject` to the audit prefix and cannot
  read or delete anything in it.
- The delivery role can decrypt only with the `purpose=secret-payload`
  encryption context, and cannot decrypt the issuer envelope.
- The admin role can decrypt only with `purpose=issuer-ca`.
- The retention role can delete revision object versions; the serving roles
  cannot.

## Gate 8 — Object Lock retention

**Pass:** the revision bucket's default retention is 90 days COMPLIANCE and the
audit bucket's is seven years, and an attempt to delete an audit object version
fails.

```sh
aws s3api get-object-lock-configuration --bucket <audit-bucket>
aws s3api get-object-lock-configuration --bucket <revision-bucket>
```

Remember that COMPLIANCE retention cannot be shortened or removed by anyone,
including the account root. Every object written during this run persists for
its full retention. This is why the account must be disposable in every sense
except the buckets, which you will not be able to empty.

## Teardown

Stateful resources use `RemovalPolicy.RETAIN` and the stack attaches no
auto-delete custom resource, so `cdk destroy` leaves the buckets, table, and KMS
key behind by design. The Object Lock buckets cannot be emptied until their
retention expires. Budget for that before you start, rather than discovering it
afterwards.
