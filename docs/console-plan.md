# Clavis console plan

This is the implementation plan for **Clavis Console**, a browser management
interface for the administrator API. It is a plan, not a description of
existing behavior; nothing here is implemented yet.

The console is built as a static Vue 3 bundle, published to a private S3
bucket, and served by CloudFront. It is a pure consumer of the public
administrator HTTP API — it holds no AWS credentials, no server component, and
no state of its own beyond an in-memory access token.

## Contents

1. [Scope](#scope)
2. [Decisions](#decisions)
3. [Domain layout](#domain-layout)
4. [Gap analysis](#gap-analysis)
5. [Phase 0 — API and data-model prerequisites](#phase-0--api-and-data-model-prerequisites)
6. [Console architecture](#console-architecture)
7. [Authentication](#authentication)
8. [Screens](#screens)
9. [Cross-cutting behavior](#cross-cutting-behavior)
10. [Delivery infrastructure](#delivery-infrastructure)
11. [Testing](#testing)
12. [Phasing](#phasing)
13. [Risks and open items](#risks-and-open-items)

## Scope

In scope: every administrator capability the API exposes — secret catalog
browsing, control-revision inspection, secret creation, metadata/path/tag
editing, ACL editing, payload replacement, cluster enrollment, API-leaf
rotation, API-leaf revocation, and issuer/truststore status.

Out of scope, because the API deliberately excludes them:

| Not built | Reason |
| --- | --- |
| Audit log viewer | No audit-query endpoint; the archive lives in a separate audit boundary with its own read role. |
| Secret deletion | No delete route exists. Retirement is ACL removal plus the `REVOKED` tombstone. |
| Issuer-root rotation | Deliberately excluded from v0.2; needs a reviewed overlap protocol. |
| Payload viewing | The administrator API never returns a decrypted payload, and the console will not add a path to one. |
| Cluster-side operations | The cluster API is mTLS-only and has no write surface. |

The console must never imply these exist. Each gets an explicit, documented
empty state rather than a disabled button.

## Decisions

| Decision | Choice | Why |
| --- | --- | --- |
| Frontend stack | Vue 3 + Vite | First-party Vite support, small dependency surface for a secrets console, strong TypeScript story via `<script setup lang="ts">`. |
| Entry topology | Separate origins with CORS on the admin API | Preserves the real client IP in audit events and keeps no proxy in the bearer-token path. See [topology](#why-separate-origins). |
| Payload key visibility | Add `payloadKeys` and `payloadKeyCount` to the control revision | Without it every payload edit is a blind replace-all that silently destroys keys the administrator cannot see. |
| CSR handling | Paste or upload only | Cluster private keys never exist in the admin console, matching the documented enrollment boundary. |
| Console domain | Zone apex, `N.domain.com` | One deployment occupies one zone; the console is the front door and the APIs are subdomains of it. |

### Why separate origins

Three topologies were considered. The deciding factor is audit fidelity.

`requestContext.http.sourceIp` is recorded on every application audit event.
If CloudFront fronts the admin API, that value becomes a CloudFront edge IP.
HTTP APIs do not support resource policies, so the admin API cannot restrict
itself to CloudFront, which means `X-Forwarded-For` can never be trusted to
recover the real address. That is a permanent regression in a product whose
stated purpose is evidence.

Routing the SPA *through* API Gateway instead preserves the client IP, but
either forces per-route authorizers on the API that serves secrets — where one
wrong route pattern exposes an admin path through the unauthenticated
fall-through — or requires base-path mapping gymnastics that change the
`rawPath` the handler matches.

Separate origins keep the admin API exactly as it is today, keep the real
client IP, keep CloudFront out of the credential path, and give the static
bundle full edge caching. The cost is a CORS configuration, whose failure mode
is a browser refusing to make the call. That fails closed.

## Domain layout

One deployment occupies one zone, named for its environment.

```text
N.domain.com            console      CloudFront -> S3 (OAC)
admin.N.domain.com      admin API    API Gateway HTTP API, OIDC JWT authorizer
client.N.domain.com     cluster API  API Gateway HTTP API, mTLS truststore
```

For `environmentName: dev` under `example.com`:

```text
dev.example.com         console
admin.dev.example.com   admin API
client.dev.example.com  cluster API
```

`DeploymentConfig` (`cdk/config.ts`) changes so the convention is the default
and the explicit FQDNs become overrides:

```ts
export interface DeploymentConfig {
  readonly environmentName: string;
  /** N.domain.com — the zone, and the console origin. */
  readonly zoneDomain: string;
  /** Defaults to zoneDomain. */
  readonly consoleFqdn?: string;
  /** Defaults to admin.<zoneDomain>. */
  readonly adminFqdn?: string;
  /** Defaults to client.<zoneDomain>. */
  readonly clusterFqdn?: string;
  readonly oidcIssuer: string;
  readonly oidcAudience: string;
  readonly oidcSubjectClaim: string;
  readonly oidcClientId?: string;   // required when the console is enabled
  readonly secretEnvironments?: readonly string[];
  readonly consoleCertificateArn?: string;  // us-east-1
  readonly existingHostedZoneId?: string;
}
```

Validation changes in `cdk/config.ts`:

- All three FQDNs must be within `zoneDomain`; the console may equal it.
- All three must be mutually distinct.
- `consoleFqdn` at the apex needs no new record-name handling — the existing
  `relativeRecordName` helper (`cdk/stack.ts`) already returns `undefined` for
  `fqdn === zoneDomain`, which Route 53 treats as the zone root.

**This renames the cluster API from `clusters.` to `client.`** For an existing
deployment that is a breaking change: a new ACM SAN, a new alias record, a new
`CLUSTER_CUSTOM_DOMAIN_NAME` / `CLUSTER_API_HOSTNAME`, a re-scoped
`apigateway:PATCH` resource ARN in `grantTruststorePublisher`, a truststore
re-publication against the new domain, and a base-URL change for every enrolled
cluster. The project is pre-1.0, so this is acceptable, but it needs a
migration note in `docs/cdk-integration.md` and the README.

## Gap analysis

What the current API cannot support, in the order it blocks work.

| # | Gap | Evidence | Blocks |
| --- | --- | --- | --- |
| 1 | No CORS on the admin API | `cdk/stack.ts:270-279` — `HttpApi` has no `corsPreflight` | Every browser request |
| 2 | No cluster list, detail, or identity list | `src/handlers/admin.ts` has only enroll/rotate/revoke; `DynamoRepository.getCluster` (`src/repositories/dynamo.ts:143`) reads one by ID; identities are keyed by fingerprint | Cluster screens, ACL cluster picker |
| 3 | Control revision carries no payload key names | `ControlRevision` in `src/domain/types.ts` | Any non-destructive payload editing |
| 4 | No way to enumerate secret environments | `environment` is a required query parameter (`src/handlers/admin.ts:39`) and is free-form per secret | Environment switcher |
| 5 | No issuer or truststore status route | `SYSTEM#ISSUER` and `SYSTEM#TRUSTSTORE` are unexposed | Trust status page |
| 6 | No revision history route | `SECRET#<id> / CONTROL#<version>` records exist but are unexposed | "What changed, when, by whom" |
| 7 | `@clavis/client` is Node-only | `packages/client/src/index.ts` imports `node:https` and `node:crypto` | Reusing the typed contract in the browser |
| 8 | Idempotency semantics differ per route family | Secrets hard-conflict (`src/services/secrets.ts:260`); clusters replay (`src/services/clusters.ts:359`) | Retry handling |
| 9 | Catalog pages are post-filtered | `Limit: 100` then `workflowState = READY` plus tag filters (`src/repositories/dynamo.ts:418-436`) | Pagination UI |
| 10 | Every admin request writes permanent audit objects | `src/handlers/admin.ts:24-38` writes `attempted` and `authorized` before routing | Refresh strategy, N+1 avoidance |

Gaps 8, 9, and 10 are not defects — they are properties of the service the
console has to be designed around. They are covered in
[cross-cutting behavior](#cross-cutting-behavior).

One documentation inaccuracy found while surveying: `docs/api.md` shows
`ctl-01J...` and `pay-01J...`, implying ULIDs, but `src/services/secrets.ts:76`
emits `ctl-${randomUUID()}`. The examples should be corrected, and nothing may
assume revision IDs sort by time.

## Phase 0 — API and data-model prerequisites

No console code starts until this ships. Everything here is independently
useful to the Pulumi provider and the Kubernetes controller.

### 0.1 CORS on the administrator API

```ts
const adminApi = new apigatewayv2.HttpApi(this, "AdminApi", {
  apiName: `${prefix}-admin`,
  defaultAuthorizer: authorizer,
  defaultIntegration: new HttpLambdaIntegration("AdminIntegration", adminFunction),
  createDefaultStage: false,
  disableExecuteApiEndpoint: true,
  corsPreflight: consoleEnabled ? {
    allowOrigins: [`https://${consoleFqdn}`],
    allowMethods: [CorsHttpMethod.GET, CorsHttpMethod.POST,
                   CorsHttpMethod.PUT, CorsHttpMethod.DELETE],
    allowHeaders: ["authorization", "content-type",
                   "idempotency-key", "if-match", "if-none-match"],
    exposeHeaders: ["etag"],
    allowCredentials: false,
    maxAge: Duration.minutes(10),
  } : undefined,
});
```

Notes:

- `allowCredentials` stays false. The bearer token travels in a header; no
  cookies are involved, and `false` keeps a wildcard origin from ever becoming
  usable by accident.
- Exactly one origin. Never a wildcard, never a regex.
- `exposeHeaders: ["etag"]` is required for JavaScript to read the ETag at all,
  but the console will still prefer the `controlVersionId` field in the
  response body as its `If-Match` source, so a CORS misconfiguration cannot
  silently degrade concurrency control into a lost update.
- API Gateway is expected to answer preflight before the JWT authorizer runs.
  MiniStack cannot prove this — it must be confirmed in the isolated AWS
  acceptance environment `PLAN.md` already calls for.

### 0.2 Payload key names on the control revision

Add to `ControlRevision` in `src/domain/types.ts`:

```ts
readonly payloadKeys?: readonly string[];
readonly payloadKeyCount?: number;
```

- Written only by the payload-update path in `src/services/secrets.ts`, from
  the already-validated payload object keys, sorted, before encryption.
- Never written to the payload revision — that stays a bare encrypted envelope.
- Never returned by the cluster API.
- Above a threshold (200 keys), store `payloadKeyCount` and omit
  `payloadKeys`, so an adversarially wide payload cannot inflate the control
  object. Fix the threshold before shipping; it is permanent once revisions
  exist.
- The `HEAD` projection carries `payloadKeyCount` only. Names appear on the
  detail route, not in catalog pages, so the GSI item stays small.
- Both fields are optional. Revisions written before this change have neither;
  the console treats `undefined` as "key set unknown" and falls back to the
  full destructive-replace warning.

Documentation to update: `openapi/cluster-secrets.yaml` `ControlRevision`,
`docs/api.md` control-revision section, `docs/architecture.md` revision
description, and a line in `docs/threat-model.md` recording the deliberate
decision that key names are administrator-visible metadata — administrators
can already write them, and clusters with a read grant already receive them.

### 0.3 Cluster read routes

Four new administrator routes, all GET, all subject to the same
attempted/authorized/succeeded audit triple as existing reads:

```text
GET /v1/admin/clusters?environment=&cursor=
GET /v1/admin/clusters/{clusterId}
GET /v1/admin/clusters/{clusterId}/api-identities
GET /v1/admin/issuer
```

`GET /v1/admin/issuer` returns the root fingerprint, `notBefore`, `notAfter`,
the current truststore object key and version ID, and the anchor count. It
never returns `encryptedPrivateKey`. Leaf and root PEMs are public output and
may be returned.

**Data model: mirror items, not new indexes.** Clusters live at
`CLUSTER#<id> / PROFILE` and identities at `IDENTITY#<sha256> / PROFILE`, so
neither is listable today. Rather than add GSIs, write two mirror items inside
the transactions that already exist:

| Mirror item | Written by | Query |
| --- | --- | --- |
| `DIRECTORY#CLUSTERS#<environment> / CLUSTER#<clusterId>` | the enrollment activation transaction | `pk = DIRECTORY#CLUSTERS#<env>` |
| `CLUSTER#<clusterId> / IDENTITY#<fingerprint>` | enrollment activation, rotation, and revocation | `pk = CLUSTER#<id> AND begins_with(sk, "IDENTITY#")` |

The identity mirror reuses the `CLUSTER#<id>` partition that already holds
`SECRET#<id>` access rows, so it needs no schema change and no index. The
directory partition is one item per cluster per environment; cluster counts are
in the tens, so a single partition is safe. Both are written in the same
`TransactWriteItems` calls as the `PENDING` to `ACTIVE` transitions and the
revocation update, so they cannot drift from the authoritative records. The
existing transactions are far below the 25-operation limit.

The authoritative record for authorization stays `IDENTITY#<sha256> / PROFILE`,
read strongly consistent on every cluster request. Mirrors are for listing
only, and the detail route reads the authoritative record.

Backfill: a greenfield deployment needs none. Any deployment with existing
enrolled clusters needs a one-shot script that walks the identities and writes
the mirrors. Ship the script with the change.

### 0.4 Revision history (recommended, not required)

```text
GET /v1/admin/secrets/{secretId}/revisions?cursor=
```

Returns `READY` control workflow records for the secret: `controlVersionId`,
`payloadVersionId`, `createdAt`, `createdBy`, and the object key — never a
presigned URL and never the payload. This is control-plane state, not audit
evidence, so it does not cross the audit boundary, and it gives the console a
history view without an audit-query API.

Because revision IDs are UUIDs, not ULIDs, the sort key is not time-ordered.
Query the full `SECRET#<id>` partition prefix and sort by `createdAt` in the
handler. Secrets have tens of revisions, so this is acceptable; do not
introduce a time-ordered sort key just for this.

### 0.5 Environment enumeration

Do not add an API. Secret `environment` is a free-form per-secret field, not
the deployment's `CLAVIS_ENVIRONMENT`, and the set is a deployment-level fact
the installer already knows. It ships in the console's runtime `config.json` as
`environments: string[]`, sourced from `DeploymentConfig.secretEnvironments`.

If a directory of observed environments is wanted later, it is another mirror
item written on secret creation. Not now.

### 0.6 `@clavis/client` refactor

The shared client already has the right shape — a `ClavisTransport` interface
with the Node implementation separate. It just needs to stop importing Node
built-ins from the core entry point.

- Subpath exports: `@clavis/client` (isomorphic core — types, `ClavisClient`,
  `ClavisTransport`, `ClavisError`, a new `FetchTransport` on global `fetch`)
  and `@clavis/client/node` (`NodeHttpsTransport`).
- Drop the `randomUUID` default for idempotency keys. Make the key an explicit
  required argument, or accept an id factory in the constructor. A default that
  silently generates a fresh key per call is exactly wrong for retry handling.
- Add the missing methods: `listSecrets` (catalog), `listSecretRevisions`,
  `listClusters`, `getCluster`, `listApiIdentities`, `enrollCluster`,
  `rotateApiIdentity`, `revokeApiIdentity`, `getIssuer`.
- Widen `TransportRequest["method"]` to include `DELETE`. It is currently
  `"GET" | "POST" | "PUT"`, which cannot express identity revocation.
- Keep the package `lib` free of `DOM`; Node 22 and modern browsers both
  provide global `fetch`.
- Version 0.2.0. Pre-1.0, so the subpath split is acceptable churn.

## Console architecture

New workspace `packages/console`, package `@clavis/console`, `private: true`.
It is not published to npm — it ships as built assets inside the root package
so `clavis/cdk` consumers get them, the same way the construct ships Lambda
sources.

Add a row to the table in `docs/monorepo.md`.

### Stack

| Concern | Choice |
| --- | --- |
| Framework | Vue 3.5, `<script setup lang="ts">`, strict TypeScript |
| Build | Vite 6 |
| Routing | Vue Router 4, history mode |
| Client state | Pinia — session and environment context only |
| Server cache | `@tanstack/vue-query` |
| Auth | `oidc-client-ts` |
| Response validation | `zod` at the API boundary |
| Styling | Tailwind, no component library |
| Test | Vitest, `@vue/test-utils`, `@testing-library/vue`, MSW, Playwright |

No component library: an admin console with roughly twelve screens does not
justify the supply chain, and a secrets console benefits from a dependency
tree a reviewer can actually read.

`zod` parsing at the boundary is deliberate — it turns a contract drift into a
loud client-side failure instead of a silently-undefined field in a form that
then submits a destructive payload.

### Layout

```text
packages/console/
  index.html
  public/config.json          # local dev only; CDK writes the deployed one
  src/
    main.ts                   # fetch config.json, then mount
    config.ts                 # runtime config schema + loader
    auth/                     # oidc-client-ts wiring, in-memory token store
    api/                      # @clavis/client + FetchTransport + zod schemas
    stores/                   # session, environment context
    composables/              # useIdempotentMutation, useCursorPages, useEtag
    components/
    views/
    router/
```

### Runtime configuration

The bundle is environment-agnostic. `main.ts` fetches `/config.json` before
mounting:

```json
{
  "deploymentName": "clv-dev",
  "adminApiUrl": "https://admin.dev.example.com",
  "oidc": {
    "authority": "https://login.example.com/tenant/v2.0",
    "clientId": "00000000-0000-0000-0000-000000000000",
    "scopes": ["openid", "profile", "api://clavis/.default"]
  },
  "environments": ["dev", "staging", "prod"]
}
```

It is a fetched JSON file rather than an inlined script tag specifically so the
Content-Security-Policy can forbid inline script entirely. CDK writes it;
CloudFront serves it `no-cache` while hashed assets get a long immutable
max-age.

## Authentication

Authorization Code with PKCE against the external OIDC provider. No client
secret; the console is a public client.

The critical detail: API Gateway's JWT authorizer validates the **access
token**, and `humanActorFromEvent` (`src/auth/actors.ts`) independently
re-checks `iss` and `aud`, accepting `client_id` only when `aud` is absent. So
the console must request a scope that makes the provider mint an access token
whose audience equals the configured `oidcAudience` — `api://clavis/.default`
on Entra, an `audience` parameter on Auth0, a custom API scope on Okta, a
client scope on Keycloak. This is the single most likely first-run failure and
needs a per-provider section in the docs.

Token handling:

- Access token held in memory in a non-persisted Pinia store. Never
  `localStorage`, never `sessionStorage`, never a cookie.
- No refresh token is persisted. Renewal is a silent iframe with `prompt=none`,
  which requires the provider to permit framing from the console origin and the
  CSP to allow `frame-src` for the provider.
- Silent renew failure falls back to a full redirect.
- A tab reload attempts silent auth, then redirects.
- Sign-out clears memory and calls the provider's end-session endpoint.

The console has no authorization model of its own. Clavis has no roles: any
token satisfying issuer and audience is a full administrator, with optional
tenant pinning through `ADMIN_EXPECTED_TENANT_ID` (`src/aws/config.ts`). The UI
must not render per-object permission affordances that do not exist. Who is an
administrator is entirely the identity provider's app-assignment decision, and
the about page should say so.

## Screens

### Shell

Environment switcher (from `config.json`), signed-in subject, deployment name,
global error surface with a copyable `correlationId`, and an explicit refresh
control. No live-updating anything.

### Secrets catalog

Table over `GET /v1/admin/secrets`: secret ID, name, path, tags, state,
payload key count, last updated. Path-prefix navigation and exact tag filters
map to the `pathPrefix` and `tags` query parameters. Sorted by path then secret
ID, matching the index order. Forward-only cursor pagination — see
[pagination](#pagination).

The table renders entirely from the catalog page. It never fetches per-row
detail.

### Secret detail

Control revision: ID, environment, state, `controlVersionId`,
`payloadVersionId`, `createdAt`, `createdBy`, metadata, path, tags, ACL grants,
and payload key names when present. A persistent notice that payload values are
never readable through the API, by design.

Actions: edit metadata, edit ACL, replace payload. Revision history tab when
0.4 ships.

### Create secret

Two API calls presented as one guided flow, because a secret created without a
payload is `PENDING_VALUE` and undeliverable:

1. `POST /v1/admin/secrets` — ID (optional; generated IDs are
   `sec-<uuid>`, so the form should encourage an explicit readable ID),
   environment, name, description, path, tags, ACL.
2. `PUT /v1/admin/secrets/{id}/payload` — the first payload.

If step 2 fails the wizard must not restart at step 1; it resumes with the
returned `controlVersionId` and a fresh idempotency key, and the secret is
listed as `PENDING_VALUE` until it succeeds.

### Payload editor

Key/value rows with a per-row `utf8` / `base64` toggle, masked values with
per-row reveal, and add/remove. Client-side validation mirrors
`src/domain/validation.ts` exactly: key charset `[A-Za-z0-9._-]+`, canonical
RFC 4648 base64 with padding, and a live size meter computing
`TextEncoder().encode(JSON.stringify(payload)).length` against 768,000 bytes —
the same measurement the service makes.

The editor pre-fills key names from `payloadKeys` with empty values and states
plainly that every key must be re-supplied, because the update replaces the
whole payload. Keys present in `payloadKeys` but absent from the form are
listed by name in the confirmation dialog as "will be destroyed". When
`payloadKeys` is absent — a pre-change revision — the dialog degrades to the
generic full-replacement warning.

A `.env` paste import is worth building; a payload export is not, and will not
be added.

### ACL editor

Cluster picker sourced from `GET /v1/admin/clusters` filtered to the secret's
environment, capped at ten grants, `read` the only permission. Removing a
cluster warns that the cluster receives a `REVOKED` tombstone through
`GET /v1/changes` and that the operator must delete the corresponding
Kubernetes Secret — removal here does not delete anything on the cluster.

### Clusters

List: ID, environment, status, created, active identity count. Detail: profile
plus the API identity table — fingerprint, status, validity window, and an
expiring-soon indicator — with rotate and revoke actions.

### Enroll cluster

CSR paste or file upload. Client-side pre-validation before submit: PEM
structure, at most 32 KiB, and an RSA public key of at least 2048 bits parsed
with WebCrypto. Rejecting locally saves a permanent audit write and a round
trip.

The result screen appears once and is the only place the issued certificate is
shown: `apiCertificatePem`, `apiFingerprint`, `rootFingerprint`, with copy and
download for each. It states that Clavis never received a private key and that
the operator pairs this certificate with the key it already holds.

Failure handling is specific to this route:

- `503` means another enrollment holds the truststore publication lease. Retry
  with the **same** idempotency key; the operation resumes.
- A terminal failure — API Gateway rejected the bundle with warnings — requires
  a new CSR *and* a new idempotency key. The UI must say both, because
  resubmitting the same CSR will not work.

### Revoke identity

Confirmation states that revocation takes effect immediately at the
application layer through a strongly consistent DynamoDB read, and that a
replacement leaf should already be distributed if continuity matters. The
dialog shows how many other `ACTIVE` identities the cluster has, and revoking
the last one gets a distinct, harder confirmation.

### Trust status

Issuer root fingerprint and validity, current truststore object key and
version, anchor count. Read-only. States explicitly that issuer-root rotation
is not exposed.

## Cross-cutting behavior

These are the rules that make the console correct against this particular
service. They belong in `packages/console/README.md` so a future contributor
does not helpfully undo them.

### Optimistic concurrency

Every mutation sends `If-Match` built from the `controlVersionId` in the last
response body, not from the ETag header. The handler tolerates quoting
(`requireIfMatch` strips quotes).

A `412` is never retried automatically. It opens a panel that says the secret
changed underneath, preserves the user's draft, and offers reload-and-reapply.
Silently re-reading and resubmitting would defeat the entire optimistic
concurrency design.

### Idempotency, which is asymmetric

This is the sharpest edge in the API and the console must encode both halves:

**Secret routes hard-conflict.** `src/services/secrets.ts:255-261` throws
`409` for any previously used key and does not replay the original response.
So after a network error or timeout on create, update, or payload, the console
must not resubmit with the same key — that is a guaranteed `409` — and must not
resubmit with a new key — that risks a double write. Correct behavior: mark the
submission outcome-unknown, refetch the secret, compare `controlVersionId` and
`payloadVersionId` against the pre-submit values, and report which actually
happened.

**Cluster routes replay.** `src/services/clusters.ts:359` and the enrollment
resume path return the recorded result for a repeated key. Retrying with the
same key is safe and is the correct response to a `503` during truststore
publication.

Keys are generated once per submit intent with `crypto.randomUUID()` and held
in form state. They are never regenerated by a re-render, and never derived
from form content.

### Pagination

- The catalog cursor is HMAC-bound to the actor plus a hash of environment,
  path prefix, and tags (`src/handlers/admin.ts:42`), and expires after fifteen
  minutes. Changing any filter invalidates it — the console resets to the first
  page on any filter change rather than sending a cursor that will `400`.
- Forward-only. No page numbers, no jump-to-page.
- **A page can be empty and still have a `nextCursor`.** The query takes 100
  items then applies the `workflowState = READY` and tag filters
  (`src/repositories/dynamo.ts:418-436`), so matches may be sparse. The console
  must follow the cursor until it is absent and must not render "no results"
  before then. Implement as an auto-continuing fetch with a bounded number of
  hops and a "keep searching" control, not a naive Load More button that
  appears to do nothing.

### Audit write discipline

Every administrator request writes `attempted` and `authorized` audit objects
before the handler even routes (`src/handlers/admin.ts:24-38`), plus a terminal
event. Those objects land in an S3 Object Lock **Compliance** bucket with a
seven-year default retention and **can never be deleted**.

Therefore:

- No polling. No `refetchInterval`, no `refetchOnWindowFocus`, no background
  revalidation. Configure `@tanstack/vue-query` with these off globally.
- `staleTime` of five minutes, cache reused across navigation.
- No N+1. A list view renders from its page response only.
- Refresh is an explicit user action.

Concretely: one catalog render costs three permanent audit objects. Adding
per-row detail fetches to a 100-row page would write three hundred permanent
objects that nobody can ever remove. This constraint is not a performance
preference.

### Payload hygiene

Payload values exist only in the editor component's local state for the
lifetime of that component. Never in the URL, router state, Pinia, the query
cache, browser storage, or an error message. Cleared on unmount and on
navigation. Inputs use `autocomplete="off"` and `spellcheck="false"`, and are
masked by default.

### Error taxonomy

| Status | Console behavior |
| --- | --- |
| `400 bad_request` | Map to an inline field error where the message identifies a field; otherwise a toast with `correlationId`. |
| `403 forbidden` | Distinguish an expired local token (re-authenticate) from a structurally valid token the API rejected (audience or issuer misconfiguration — link the provider setup doc). |
| `404 not_found` | Empty state, not an error toast. |
| `409 conflict` | The idempotency reconciliation flow above. |
| `412 precondition_failed` | The concurrency panel above. |
| `503 service_unavailable` | For enrollment, retry with the same key. Elsewhere, a retry banner. |
| `500 internal_error` | Toast with `correlationId` and nothing speculative about the cause. |

`correlationId` is always surfaced with a copy button — it is the only handle
an operator has for correlating against the audit archive and access logs.

## Delivery infrastructure

Added to `ClavisStack`, created only when the console is enabled.

- **S3 bucket.** Private, `BLOCK_ALL`, S3-managed encryption, versioned,
  `enforceSSL`, `RETAIN`. No Object Lock — static assets are not evidence.
- **CloudFront distribution.** Origin Access Control via
  `S3BucketOrigin.withOriginAccessControl`, HTTP/2 and HTTP/3, minimum TLS
  1.2_2021, `defaultRootObject: index.html`, and 403/404 error responses
  rewritten to `/index.html` with status 200 for SPA routing.
- **Certificate.** CloudFront requires ACM in **us-east-1**; the existing
  regional certificate cannot be reused. Accept `consoleCertificateArn`, or
  create one in a nested us-east-1 stack with `crossRegionReferences: true`.
- **DNS.** A and AAAA aliases at the zone apex.
- **Response headers policy.**

  ```text
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  Referrer-Policy: no-referrer
  X-Frame-Options: DENY
  Permissions-Policy: camera=(), microphone=(), geolocation=()
  Content-Security-Policy:
    default-src 'none';
    script-src 'self';
    style-src 'self';
    img-src 'self' data:;
    font-src 'self';
    connect-src 'self' https://admin.N.domain.com https://login.example.com;
    frame-src https://login.example.com;
    form-action 'none';
    frame-ancestors 'none';
    base-uri 'none';
    object-src 'none'
  ```

  `connect-src` must name the admin API origin because the design is
  deliberately cross-origin. `frame-src` names the identity provider for silent
  renew. Note that `includeSubDomains; preload` at the apex commits
  `admin.` and `client.` too — both are HTTPS-only, so this is fine, but it is
  a deliberate commitment worth recording.

- **Cache behaviors.** `/assets/*` (Vite content-hashed) long `max-age`,
  `immutable`. `/index.html` and `/config.json` `no-cache`.
- **Asset publication.** `BucketDeployment` with the built console output plus
  `Source.jsonData("config.json", ...)`, with `distribution` and
  `distributionPaths: ["/index.html", "/config.json"]` for invalidation. This
  is a CloudFormation custom resource — distinct in kind from the S3
  auto-delete resource the project deliberately avoids, since it never destroys
  data — and it is skipped when the built output is absent from the package,
  following the same `existsSync` pattern the construct already uses to locate
  Lambda entry points. A consumer who wants pipeline control omits the console
  config and syncs the bucket itself.
- **Packaging.** The root `package.json` `files` array must include the built
  console output, and `build:cdk` must depend on the console build.
- **Outputs.** `ConsoleUrl`, `ConsoleBucketName`, `ConsoleDistributionId`.

## Testing

- **Unit (Vitest).** Client-side mirrors of `src/domain/validation.ts` — the
  identifier pattern, path pattern, tag key and value patterns and bounds,
  payload key charset, canonical base64, and the 768,000-byte cap. The
  idempotency reconciliation state machine and the cursor-reset logic.
- **Component (`@testing-library/vue`).** The destructive-replace confirmation
  listing keys by name, the ten-grant ACL cap, the 412 panel preserving a
  draft, the 409 reconciliation path, and the empty-page-with-cursor case.
- **Contract (MSW against `openapi/cluster-secrets.yaml`).** Fixtures generated
  from the spec, plus a test that fails if the console sends a header or
  parameter the contract does not declare. This keeps the console honest as the
  API evolves and catches Phase 0 drift.
- **End-to-end (Playwright, mocked provider and MSW).** Two flows: create,
  set payload, grant ACL; and enroll cluster, download leaf, revoke.
- **Explicitly forbidden.** No automated test may run against a real
  deployment's administrator API. Every request writes permanent audit objects
  into a Compliance-locked bucket. State this in the console README.
- **Acceptance.** MiniStack cannot exercise OIDC, CORS preflight, or the JWT
  authorizer. CORS behavior, preflight-versus-authorizer ordering, the access
  token audience, and the apex CloudFront certificate all need the isolated AWS
  acceptance environment.

## Phasing

| Phase | Content | Ships independently |
| --- | --- | --- |
| 0 | CORS, `payloadKeys`, cluster read routes and mirror items, issuer status, revision history, OpenAPI and docs, client refactor, domain rename | Yes — useful to the Pulumi provider and controller regardless of the console |
| 1 | Console workspace, Vite, `config.json` bootstrap, OIDC, shell, environment switcher, error and `correlationId` plumbing, catalog list, secret detail read-only | Yes, behind a manual bucket sync |
| 2 | Create wizard, metadata/path/tag editing, ACL editor, payload editor, concurrency and idempotency handling | Yes |
| 3 | Cluster list, detail, identities, enroll, rotate, revoke, trust status | Yes |
| 4 | CDK console construct, us-east-1 certificate, CSP, publication, `docs/console.md`, README, monorepo table | Completes the deliverable |
| 5 | CSP report-only to enforce, accessibility pass, error taxonomy completeness, acceptance runbook | Hardening |

Phase 0 is the long pole and the only phase that touches the service. Phases 1
through 3 are additive frontend work with no service risk.

## Risks and open items

- **Preflight versus authorizer.** API Gateway is expected to answer CORS
  preflight before the JWT authorizer. Verify in AWS before Phase 1 depends on
  it; MiniStack cannot.
- **Access token audience.** The most likely first-run failure. Needs a
  per-provider documentation section for Entra, Okta, Auth0, and Keycloak.
- **Silent renew.** Iframe renewal is blocked by some providers and by strict
  third-party cookie policies. The redirect fallback works but interrupts the
  session; decide whether that UX is acceptable before committing to
  no-persisted-refresh-token.
- **`payloadKeys` is permanent.** It becomes part of every future immutable
  control revision. Fix the truncation threshold and confirm the threat-model
  position before the first write.
- **Mirror-item backfill.** Any deployment with clusters already enrolled needs
  the one-shot script; ship it with 0.3.
- **The cluster domain rename.** `clusters.` to `client.` breaks every enrolled
  cluster's base URL and requires truststore re-publication against the new
  domain. Needs a migration note, and it should land in the same release as the
  console rather than trickling out.
- **No delete route.** The console can never remove a secret. Every retirement
  affordance must be honest that ACL removal plus the tombstone is the only
  path.
