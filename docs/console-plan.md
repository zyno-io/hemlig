# Hemlig console plan

This plans **Hemlig Console**, a browser management interface for the
administrator API. The console UI and static-hosting work remain unimplemented;
the API-readiness work recorded below is implemented in v0.3.

The document is organised around one structural rule: **the console is an
ordinary HTTP client of a public API, and nothing else.** Everything in it is
either backend work, frontend work, or work on the seam between them, and it is
filed accordingly. If a proposal cannot be filed on one side of that line, it
is a design error rather than a documentation problem.

An earlier draft of this plan was reviewed against the source by an external
agent. Findings that survived verification are folded in, and the places where
the original draft was wrong are called out inline rather than quietly
corrected.

## Contents

- [The boundary](#the-boundary) — ownership, the wire, and the rules
- [Part I — Backend](#part-i--backend) — the Hemlig service and its CDK
- [Part II — Frontend](#part-ii--frontend) — the console workspace
- [Part III — The seam](#part-iii--the-seam) — client package, hosting, testing, phasing
- [Decision record](#decision-record)
- [Risks](#risks)

---

## The boundary

```text
┌──────────────────────────── FRONTEND ────────────────────────────┐
│  packages/console            static Vue 3 bundle                  │
│  no server, no AWS credentials, no AWS SDK, no direct datastore   │
│                                                                    │
│  browser ── HTTPS + JSON ──┐                                      │
└────────────────────────────┼──────────────────────────────────────┘
                             │
                    THE CONTRACT
       openapi/consumer-secrets.yaml + docs/api.md
       bearer JWT · Idempotency-Key · If-Match · error envelope
                             │
┌────────────────────────────┼──────────────────────────────────────┐
│  admin.N.domain.com ───────┘                                      │
│  root `hemlig` package + cdk/                                     │
│  API Gateway → Lambda → DynamoDB / S3 / KMS / audit archive       │
└──────────────────────────── BACKEND ──────────────────────────────┘
```

### Ownership

| Concern                                        | Owner    | Notes                                                                       |
| ---------------------------------------------- | -------- | --------------------------------------------------------------------------- |
| HTTP routes, request and response shapes       | Backend  | The console never defines a shape.                                          |
| Authentication and authorization               | Backend  | Gateway JWT authorizer plus handler re-check.                               |
| All validation that has consequences           | Backend  | The console may mirror rules for UX; the server decides.                    |
| Encryption, storage, audit, retention          | Backend  | The console has no visibility into any of it.                               |
| `openapi/consumer-secrets.yaml`                | Backend  | Single source of truth for the wire.                                        |
| CORS policy                                    | Backend  | The console's origin is backend configuration.                              |
| Screens, navigation, forms, presentation       | Frontend |                                                                             |
| Token acquisition and lifetime in the browser  | Frontend | The provider is configured by the backend deployment.                       |
| Retry, reconciliation, and pagination behavior | Frontend | Driven by backend properties — see [the leakage table](#what-leaks-across). |
| Static hosting infrastructure                  | Seam     | Defined in backend CDK, serves frontend output.                             |
| `@hemlig/client`                               | Seam     | Typed expression of the contract, used by both.                             |

### Rules

1. **Only HTTPS and JSON cross.** No shared runtime code except the typed
   contract in `@hemlig/client`. No server-rendered anything. No websocket, no
   long poll.
2. **The console holds no AWS credential** and imports no AWS SDK. It cannot
   reach DynamoDB, S3, KMS, or CloudWatch, and no future feature may change
   that. A console that needs AWS access is a console that has become a
   backend.
3. **The server is the authority on every rule.** The console duplicates
   validation only to give fast feedback. A rule enforced in the console but
   not the server is a security bug. A rule enforced in the server but not the
   console is merely poor UX.
4. **The console encodes no business logic the server does not enforce.** It
   may not, for example, decide which consumers are eligible for a grant; it
   asks.
5. **A missing capability is backend work, never a frontend workaround.** If a
   screen needs data no route returns, the answer is a route — not N+1 fetches,
   not client-side aggregation, not scraping a list endpoint. This rule is why
   [Part I](#part-i--backend) exists at all.
6. **Nothing added to the API may return payload plaintext.** The console has
   no path to a decrypted secret and will not grow one.
7. **Contract changes are backend deliverables.** The frontend consumes a
   published version; it never negotiates a shape in code review.

### What leaks across

The console is a thin client, but it is not a naive one. Several properties of
the service dictate frontend behavior, and making that coupling explicit is the
point of this section — each row is a backend fact the frontend is required to
know.

| Backend property                                                                                            | Frontend obligation                                                                                |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Secret mutations hard-conflict on a reused idempotency key and never replay (`src/services/secrets.ts:260`) | An ambiguous outcome must be reconciled by refetching, never retried                               |
| Consumer mutations replay the recorded result for the same key (`src/services/consumers.ts:359`)            | An ambiguous outcome may be retried with the same key                                              |
| Control revisions are the optimistic-concurrency token                                                      | Every mutation carries `If-Match`; a `412` never auto-retries                                      |
| Catalog pages are post-filtered after a `Limit: 100` read (`src/repositories/dynamo.ts:418-436`)            | A page may be empty and still have a cursor; never render "no results" before the cursor is absent |
| Opaque cursors are server-side, bound to actor and filters, and expire in 15 minutes                        | Any filter change resets pagination                                                                |
| Every request writes audit objects into a seven-year Compliance archive (`src/handlers/admin.ts:24-38`)     | No polling, no background refetch, no N+1                                                          |
| Administrator payload reads are explicit, audited requests                                                  | Keep plaintext component-local; never cache or auto-load it                                        |
| The gateway rejects bad tokens with a bare `401` before Lambda                                              | `401` and `403` mean different things and get different handling                                   |
| No delete route exists                                                                                      | Retirement is ACL removal plus a tombstone, and the UI must say so                                 |

### What is deliberately absent

Neither side builds these, because the API excludes them by design.

| Not built                | Reason                                                                   |
| ------------------------ | ------------------------------------------------------------------------ |
| Secret deletion          | No delete route. Retirement is ACL removal plus the `REVOKED` tombstone. |
| Issuer-root rotation     | Excluded from v0.2; needs a reviewed overlap protocol.                   |
| Consumer-side operations | The consumer API is mTLS-only and has no write surface.                  |

Each gets an explicit empty state that explains the absence, not a disabled
button that implies a missing permission.

### Decisions already taken

| Decision               | Choice                                               | Why                                                                                            |
| ---------------------- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Frontend stack         | Vue 3 + Vite                                         | First-party Vite support, small dependency surface, strong TypeScript story.                   |
| Entry topology         | Separate origins with CORS                           | Keeps the real client IP in audit events and no proxy in the bearer-token path.                |
| CSR handling           | Paste or upload, plus an opt-in in-browser generator | Reversed after the original paste-only decision. See [the record](#in-browser-csr-generation). |
| Console origin         | Explicit `consoleFqdn` within the deployment zone    | Enables one exact CORS origin; it does not provision static hosting.                           |
| Payload key visibility | Count only                                           | Provides destructive-replacement warning without disclosing key names.                         |

---

# Part I — Backend

**Owner:** root `hemlig` package and `cdk/`.
**Deliverable:** an administrator API a browser can call, and a contract file
describing it.
**Definition of done:** a frontend developer can build every screen in
[Part II](#part-ii--frontend) against `openapi/consumer-secrets.yaml` alone,
without reading Lambda source and without asking a backend question.

None of this work depends on the console existing. All of it is equally useful
to the Pulumi provider and the Kubernetes controller, and it ships and tests on
its own.

The following v0.3 backend work resolves the console-facing API gaps.

| #   | v0.3 resolution                                                                                                                                           | Blocks                          |
| --- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| 1   | Exact-origin CORS plus explicit unauthenticated `OPTIONS /{proxy+}` when `consoleFqdn` is configured                                                      | Every browser request           |
| 2   | Consumer directory, detail, and identity-list routes backed by sparse GSIs                                                                                | Consumer screens, ACL picker    |
| 3   | `payloadKeyCount` on control revisions and catalog entries                                                                                                | Non-destructive payload editing |
| 4   | Environments are administrator-defined via `GET`/`POST /v1/admin/environments`, not deployment configuration — see [the record](#environment-enumeration) | Environment switcher            |
| 5   | Public issuer and truststore status route                                                                                                                 | Trust status page               |
| 6   | Bounded newest-first revision history route                                                                                                               | "What changed, when, by whom"   |
| 7   | Terminal enrollment failure is `409 enrollment_failed`                                                                                                    | Enrollment retry logic          |
| 8   | Optional scope protection at gateway and handler, activated with console CORS                                                                             | Browser administrator access    |

## API refinement adopted in v0.3

The initial backend plan was useful, but several details would have produced a
bad public contract or an unnecessarily disruptive deployment. These decisions
supersede the relevant proposals below.

- **Use `api.<zone>` for the mTLS delivery endpoint.** The endpoint is useful
  beyond Kubernetes workloads, so its public FQDN and CDK input are `apiFqdn`.
  This is an intentional custom-domain migration for existing deployments.
- **CORS and scope turn on together, only with `consoleFqdn`.** Supplying
  `consoleFqdn` requires `oidcAdminScope`; the stack then permits exactly that
  `https` origin, exposes `ETag`, and requires the scope in API Gateway and the
  Lambda. Existing automation stays audience-only until deliberately migrated.
- **Preflight is unauthenticated but does invoke the Lambda.** AWS requires an
  explicit `OPTIONS /{proxy+}` integration when an authorized `$default` route
  exists. The handler returns `204` before actor resolution or audit writing;
  API Gateway adds CORS headers. The earlier “does not invoke Lambda” criterion
  was not compatible with HTTP API routing.
- **Payload count, never names.** `payloadKeyCount` is copied across every
  control revision and catalog projection. This gives replacement warnings
  without extending the broad control-object metadata disclosure surface.
- **All browse/history indexes are sparse but require an explicit upgrade
  backfill.** New writes populate them atomically. Existing consumer, identity,
  and control-workflow rows need `backfill-console-indexes --apply`; pretending
  GSIs populate absent attributes would have made existing deployments appear
  empty.
- **Revision history is a bounded newest-first view.** A `secret-revision` GSI
  orders immutable control records by `createdAt#controlVersionId`; the route
  returns the newest 500 and `truncated`. UUID-key ordering cannot implement a
  meaningful capped history.
- **Terminal enrollment failure is `409 enrollment_failed`.** A new CSR cannot
  repair a rejected issuer-root truststore bundle; repair the issuer/truststore
  configuration first.
- **Terminal mutation audit events now include `sourceIp`.**

## B1. Existing domain convention

One deployment occupies one zone, named for its environment.

```text
N.domain.com            console      CloudFront → S3 (OAC)
admin.N.domain.com      admin API    API Gateway, OIDC JWT authorizer
api.N.domain.com        delivery API API Gateway, mTLS truststore
```

`DeploymentConfig` (`cdk/config.ts`) takes explicit API FQDNs and an optional
separately hosted console origin:

```ts
export interface DeploymentConfig {
  readonly environmentName: string;
  /** Zone containing both API names and the optional browser origin. */
  readonly zoneDomain: string;
  readonly consoleFqdn?: string; // exact allowed browser origin
  readonly adminFqdn: string;
  readonly apiFqdn: string;
  readonly oidcIssuer: string;
  readonly oidcAudience: string;
  readonly oidcSubjectClaim: string;
  readonly oidcAdminScope?: string; // required with consoleFqdn
  readonly existingHostedZoneId?: string;
}
```

Validation requires every configured FQDN to be distinct and within
`zoneDomain`. The delivery API uses the configured `api.` FQDN because enrolled
identities may represent more than Kubernetes workloads. `consoleFqdn`
identifies one separately hosted browser origin and is paired with
`oidcAdminScope`. This stack does not create the console's hosting resources or
DNS record yet.

Changing an existing deployment from `clusters.<zone>` to `api.<zone>` replaces
the API Gateway custom domain. The scheduled recovery worker reapplies the
current immutable truststore to the replacement domain; wait for that
reconciliation before moving mTLS callers. The root and enrolled leaf
fingerprints are not hostname-bound, so certificates do not need re-issuance.

## B2. CORS, and the preflight route that CORS alone does not give you

```ts
const adminApi = new apigatewayv2.HttpApi(this, "AdminApi", {
  apiName: `${prefix}-admin`,
  defaultAuthorizer: authorizer,
  defaultIntegration: new HttpLambdaIntegration(
    "AdminIntegration",
    adminFunction,
  ),
  createDefaultStage: false,
  disableExecuteApiEndpoint: true,
  corsPreflight: consoleEnabled
    ? {
        allowOrigins: [`https://${consoleFqdn}`],
        allowMethods: [
          CorsHttpMethod.GET,
          CorsHttpMethod.POST,
          CorsHttpMethod.PUT,
          CorsHttpMethod.DELETE,
        ],
        allowHeaders: [
          "authorization",
          "content-type",
          "idempotency-key",
          "if-match",
        ],
        exposeHeaders: ["etag"],
        allowCredentials: false,
        maxAge: Duration.minutes(10),
      }
    : undefined,
});
```

- Exactly one origin. Never a wildcard, never a regex.
- `allowCredentials` stays false — the token is a header, not a cookie.
- `if-none-match` is deliberately absent; only the consumer read uses it.
- `exposeHeaders: ["etag"]` lets JavaScript read the ETag, but the console
  still uses the `controlVersionId` in the response body as its `If-Match`
  source, so a CORS mistake cannot silently degrade concurrency control into a
  lost update.

**`corsPreflight` alone is not sufficient here, and this is the item most
likely to break the console on first deploy.** `defaultIntegration` creates a
`$default` catch-all route and `defaultAuthorizer` authorizes it. `$default`
catches `OPTIONS` too, so the browser preflight is authorized, fails with `401`
because a preflight carries no `Authorization` header, and every cross-origin
call dies before it is made. API Gateway answers preflight itself only for
methods and paths that no route matches.

```ts
adminApi.addRoutes({
  path: "/{proxy+}",
  methods: [apigatewayv2.HttpMethod.OPTIONS],
  authorizer: new apigatewayv2.HttpNoneAuthorizer(),
  integration: new HttpLambdaIntegration("AdminPreflight", adminFunction),
});
```

An explicit route outranks `$default`. A preflight returns `204` with the CORS
headers, invokes the admin Lambda only for its early `OPTIONS` return, and
writes no application audit events. An unauthenticated route reaching
`humanActorFromEvent` would throw `forbidden`, so the handler short-circuits
`OPTIONS` before actor resolution.

MiniStack cannot prove any of this. Confirm it in the isolated AWS acceptance
environment first, before frontend work depends on it.

## B3. Require an administrator scope

Without `consoleFqdn`, the authorizer validates issuer and audience only, and
`humanActorFromEvent` re-checks `iss`, `aud`/`client_id`, the subject claim,
and an optional tenant. When `consoleFqdn` is configured, `oidcAdminScope` is
required by the stack and enforced by both the gateway and handler.

When a browser origin is enabled, the console asks the provider for a correctly
audienced access token with the required scope:

```ts
const authorizer = new HttpJwtAuthorizer("AdminAuthorizer", props.oidcIssuer, {
  authorizerName: `${prefix}-admin`,
  jwtAudience: [props.oidcAudience],
});
const adminApi = new apigatewayv2.HttpApi(this, "AdminApi", {
  defaultAuthorizer: authorizer,
  defaultAuthorizationScopes: [props.oidcAdminScope], // e.g. "hemlig.admin"
  // ...
});
```

This is an opt-in threat-model change. A matching `scp`/`scope` check in
`humanActorFromEvent` prevents gateway drift from silently widening access.
Existing machine-to-machine callers remain audience-only until their deployment
enables both `consoleFqdn` and `oidcAdminScope`.

## B4. Payload key information on the control revision

The shipped shape is count-only:

```ts
readonly payloadKeyCount?: number;
```

- Computed in the payload-update path from the already-validated payload object
  before encryption.
- **Inheritance must be explicit or the field silently disappears.**
  `SecretService.update` builds each control revision fresh
  (`src/services/secrets.ts:99-135`). It inherits `payloadVersionId` from the
  current revision and would inherit nothing it is not told to. A payload
  update computes new values; a metadata-or-ACL-only update **copies the prior
  values forward**, exactly as it already copies `payloadVersionId`. Without
  this, the first description edit after a payload write destroys the
  information and the console silently reverts to blind replace-all. Test
  create → payload → ACL edit → detail read.
- `payloadKeyCount` is carried by the `HEAD` creation and completion paths, the
  catalog projection, and historical control revisions.
- Never written to the payload revision. Never returned by the consumer API.
- The field is optional; revisions written before this change have no count and
  the console treats absence as "unknown".

## B5. Consumer read routes

Four new administrator routes. All `GET`, all requiring `Authorization`, none
requiring `Idempotency-Key`, all emitting the same attempted/authorized/
succeeded audit triple as existing reads.

### Data model: two sparse GSIs

Consumers live at `CONSUMER#<id> / PROFILE` and identities at
`IDENTITY#<sha256> / PROFILE`, so neither is listable today.

An earlier draft proposed mirror items written inside the existing transactions
to avoid new indexes. That was wrong. The enrollment rollback path deletes
`CONSUMER#<consumerId> / PROFILE` outright (`src/repositories/dynamo.ts:723-731`),
so a mirror there would need deleting too; rotation, revocation, and the
recovery worker's resume each need their own handling; and a stale mirror is
worse than no mirror because the console will trust it. Five write paths of
bespoke consistency code plus a backfill script, to avoid two index
definitions.

| Index                | Partition key                                   | Sort key                                        | On                        |
| -------------------- | ----------------------------------------------- | ----------------------------------------------- | ------------------------- |
| `consumer-directory` | `consumerDirectoryPk = CONSUMERS#<environment>` | `consumerDirectorySk = <consumerId>`            | `CONSUMER#<id> / PROFILE` |
| `consumer-identity`  | `identityConsumerPk = CONSUMER#<consumerId>`    | `identityConsumerSk = <notAfter>#<fingerprint>` | `IDENTITY#<fp> / PROFILE` |

Both are sparse — the attributes exist only on those two record types. Deleting
or updating the authoritative record updates the index automatically, avoiding
mirror-record drift. Projection is `ALL`, matching the table's existing
indexes. Adding them is an online table operation, but existing rows require
the explicit `backfill-console-indexes --apply` migration described in the CDK
guide.

Eventual consistency is fine because these are management reads.
**Authorization is untouched:** the consumer handler still strongly reads
`IDENTITY#<fingerprint> / PROFILE` directly, and the consumer detail route reads
the authoritative record rather than the index.

Two values need care because neither exists in the data:

- **`activeApiIdentityCount` is stored nowhere.** Compute it from the
  `consumer-identity` index at read time, including only `ACTIVE` leaves whose
  `notAfter` is in the future. Do not add a counter attribute — an atomic
  counter reintroduces exactly the drift the index avoids.
- **`EXPIRED` is never written.** `IdentityStatus` includes it but no code sets
  it; expiry is evaluated against `notAfter` at authorization time
  (`src/auth/actors.ts`). The API returns the stored status and the frontend
  derives expiry by comparing `notAfter` to now.

Sizing note: an earlier draft cited DynamoDB's transaction limit as 25
operations, which is what `docs/architecture.md:174` says. The real limit has
been **100 actions / 4 MiB** since 2022. The repo's own documentation is stale
and should be corrected in the same change.

### Route contracts

`GET /v1/admin/consumers?environment=<env>&cursor=<opaque>`

```json
{
  "consumers": [
    {
      "consumerId": "prod-east",
      "environment": "prod",
      "status": "ACTIVE",
      "subjectUri": "spiffe://hemlig/consumer/prod-east",
      "createdAt": "2026-08-22T19:37:12.441Z"
    }
  ],
  "nextCursor": "<opaque-cursor-or-omitted>",
  "generatedAt": "2026-08-22T19:37:12.441Z"
}
```

`environment` is required, matching the catalog route. The opaque cursor uses
server-side, actor-bound, fifteen-minute state (`src/services/cursor.ts`), with
the environment in its scope string so it cannot be replayed across
environments.

`GET /v1/admin/consumers/{consumerId}`

```json
{
  "consumerId": "prod-east",
  "environment": "prod",
  "status": "ACTIVE",
  "subjectUri": "spiffe://hemlig/consumer/prod-east",
  "createdAt": "2026-08-22T19:37:12.441Z",
  "createdBy": { "type": "human", "id": "external-oidc-subject" },
  "rootFingerprint": "<sha256-hex>",
  "activeApiIdentityCount": 2
}
```

Reads the authoritative profile record directly, not the index. Identity
details are retrieved through the separately paginated identity-list route.

`GET /v1/admin/consumers/{consumerId}/api-identities`

```json
{
  "consumerId": "prod-east",
  "environment": "prod",
  "rootFingerprint": "<sha256-hex>",
  "apiIdentities": [
    {
      "apiFingerprint": "<sha256-hex>",
      "status": "ACTIVE",
      "kind": "api",
      "notBefore": "2026-08-22T19:37:12.441Z",
      "notAfter": "2027-08-22T19:37:12.441Z",
      "apiCertificatePem": "-----BEGIN CERTIFICATE-----\n..."
    }
  ],
  "generatedAt": "2026-08-22T19:37:12.441Z"
}
```

Every status, not only `ACTIVE` — the console shows revoked leaves for operator
context. `status` is the stored status, which is never `EXPIRED`. The leaf PEM
is public output and is included so a lost certificate can be recovered without
re-issuing.

`GET /v1/admin/issuer`

```json
{
  "rootFingerprint": "<sha256-hex>",
  "rootCertificatePem": "-----BEGIN CERTIFICATE-----\n...",
  "notBefore": "2026-08-22T19:37:12.441Z",
  "notAfter": "2036-08-22T19:37:12.441Z",
  "createdAt": "2026-08-22T19:37:12.441Z",
  "truststore": {
    "objectKey": "truststores/<unique>.pem",
    "versionId": "<s3-version-id>",
    "anchorCount": 1
  }
}
```

Returns `404` before the first enrollment, because the issuer is created
lazily; the console renders that as "no consumers enrolled yet".
`encryptedPrivateKey` is never returned — enforce with an explicit field
allowlist in the handler, not a delete-key on the stored record.

## B6. Revision history

```text
GET /v1/admin/secrets/{secretId}/revisions
```

```json
{
  "secretId": "database-credentials",
  "revisions": [
    {
      "controlVersionId": "ctl-...",
      "payloadVersionId": "pay-...",
      "createdAt": "2026-08-22T19:37:12.441Z",
      "createdBy": { "type": "human", "id": "external-oidc-subject" },
      "isCurrent": true,
      "objectAvailable": true
    }
  ],
  "truncated": false,
  "generatedAt": "2026-08-22T19:37:12.441Z"
}
```

Control-plane state, not audit evidence, so this remains distinct from the
console's separate immutable-audit browser. It never returns a presigned URL
or payload.

The route uses the sparse `secret-revision` GSI, whose
`createdAt#controlVersionId` sort key gives it meaningful newest-first order.
It returns at most 500 entries and sets `truncated` if older history exists;
this is intentionally a bounded management view, not a general audit API.

It includes all control workflow states. Retention removes non-head S3 object
versions after the 90-day Object Lock window and marks the workflow `DELETED`;
the DynamoDB record survives. `objectAvailable` is true only for `READY` rows,
so it is false for deleted and never-committed revisions without hiding either
from history.

## B7. Distinguish terminal enrollment failure from a transient one

`ConsumerService.resume` distinguishes a **terminally failed** enrollment from a
busy truststore lease or transient publication failure. A client told to retry
the latter with the same idempotency key must not loop forever against the
former.

The service's message for the terminal case says to "submit a corrected bundle
with a new idempotency key", and `docs/api.md` repeats it. That appears to be
wrong: the published bundle is assembled from issuer roots
(`listTruststoreRoots`), not from the submitted leaf, so a bundle rejected with
API Gateway warnings indicates an issuer or truststore fault and a different
CSR cannot repair it.

The terminal case is a distinct, non-retryable `409 conflict` with
`code: "enrollment_failed"`; the remediation text directs the administrator to
repair issuer or truststore configuration before retrying.

## B8. Audit and documentation corrections

Found while planning, unrelated to the console but in the same code paths:

- **Successful mutations omit `sourceIp`.** `humanOperation`
  (`src/services/operations.ts`) does not accept or forward it, so the terminal
  `succeeded` event for every create, update, payload write, and enrollment
  lacks the address that the `attempted` and `authorized` events for the same
  request carry. Thread it through.
- `docs/architecture.md:174` states a 25-operation transaction limit; the real
  limit is 100 actions / 4 MiB.
- `docs/api.md` shows `ctl-01J...` and `pay-01J...`, implying ULIDs, but
  `src/services/secrets.ts:76` emits `ctl-${randomUUID()}`. Correct the
  examples, and let nothing assume revision IDs sort by time.

## B9. Environment enumeration

Secret `environment` is an administrator-defined per-secret field, not the
deployment's `HEMLIG_ENVIRONMENT`. The backend exposes
`GET /v1/admin/environments` and `POST /v1/admin/environments`; secret
creation, consumer enrollment, and environment-scoped browsing reject an
unknown environment. The console should source its environment switcher from
that API rather than from deployment runtime configuration.

## B10. Publish the contract

`openapi/consumer-secrets.yaml` gains `ConsumerSummary`, `ConsumerListPage`,
`ConsumerDetail`, `ApiIdentityDetail`, `ApiIdentityListPage`, `IssuerStatus`,
`SecretRevision`, `SecretRevisionPage`, the `enrollment_failed` error code, and
the new `ControlRevision` fields. Docs updated: `docs/api.md`,
`docs/architecture.md`, `docs/threat-model.md`, `docs/cdk-integration.md`,
`README.md`.

**This is the deliverable the frontend consumes.** It lands in the same change
as the handlers, never after, because the contract test in Part III reads it
directly.

---

# Part II — Frontend

**Owner:** `packages/console`, package `@hemlig/console`, `private: true`.
**Deliverable:** a static bundle. No server, no AWS credential, no AWS SDK.
**Consumes:** the contract from [Part I](#part-i--backend), and nothing else.

Not published to npm — it ships as built assets inside the root package so
`hemlig/cdk` installers get them, the same way the construct ships Lambda
sources. Add a row to `docs/monorepo.md`.

## F1. Stack

| Concern             | Choice                                                             |
| ------------------- | ------------------------------------------------------------------ |
| Framework           | Vue 3.5, `<script setup lang="ts">`, strict TypeScript             |
| Build               | Vite 6                                                             |
| Routing             | Vue Router 4, history mode                                         |
| Client state        | Pinia — session and environment context only                       |
| Server cache        | `@tanstack/vue-query`                                              |
| Auth                | `oidc-client-ts`                                                   |
| Response validation | `zod` at the API boundary                                          |
| Styling             | Tailwind, no component library                                     |
| Test                | Vitest, `@vue/test-utils`, `@testing-library/vue`, MSW, Playwright |

No component library: twelve screens do not justify the supply chain, and a
secrets console benefits from a dependency tree a reviewer can read.

`zod` at the boundary is deliberate. It turns contract drift into a loud
client-side failure rather than a silently-undefined field in a form that then
submits a destructive payload.

```text
packages/console/
  index.html
  public/config.json          # local dev only; CDK writes the deployed one
  src/
    main.ts                   # fetch config.json, then mount
    config.ts                 # runtime config schema + loader
    auth/                     # oidc-client-ts wiring, in-memory token store
    api/                      # @hemlig/client + FetchTransport + zod schemas
    stores/                   # session, environment context
    composables/              # useIdempotentMutation, useCursorPages, useEtag
    components/
    views/
    router/
```

## F2. Runtime configuration

The bundle is environment-agnostic. `main.ts` fetches `/config.json` before
mounting:

```json
{
  "deploymentName": "hml-dev",
  "adminApiUrl": "https://admin.dev.example.com",
  "oidc": {
    "authority": "https://login.example.com/tenant/v2.0",
    "clientId": "00000000-0000-0000-0000-000000000000",
    "scopes": ["openid", "profile", "api://hemlig-api/hemlig.admin"]
  }
}
```

A fetched JSON file rather than an inlined script tag, specifically so the CSP
can forbid inline script entirely. The backend writes it — see
[S2](#s2-the-configjson-handoff).

## F3. Authentication

Authorization Code with PKCE. Public client, no secret.

The gateway validates the **access token**, and `humanActorFromEvent`
independently re-checks `iss` and `aud`, accepting `client_id` only when `aud`
is absent. So the console must request a scope that makes the provider mint an
access token whose audience equals the configured `oidcAudience`. The requested
scope and the short claim value can differ: on Entra, request
`api://<application-id>/hemlig.admin` and require `hemlig.admin` in `scp`.
For an Entra v2 token, configure Hemlig's `oidcAudience` with the API
application's bare client ID, because that is the token's `aud` value.
Other providers use their resource-qualified custom API scope, an `audience`
parameter, or a client scope. Once [B3](#b3-require-an-administrator-scope)
lands, the resulting claim must contain the required `hemlig.admin`.

This is the most likely first-run failure and needs a per-provider section in
the docs.

Token handling:

- Access token in memory in a non-persisted Pinia store. Never `localStorage`,
  never `sessionStorage`, never a cookie.
- No persisted refresh token. Renewal is a silent iframe with `prompt=none`.
- Silent renew failure falls back to a full redirect. A tab reload attempts
  silent auth, then redirects.
- Sign-out clears memory and calls the provider's end-session endpoint.

The console has no authorization model of its own. Any token satisfying issuer,
audience, and scope is a full administrator, with optional tenant pinning via
`ADMIN_EXPECTED_TENANT_ID`. The UI must not render per-object permission
affordances that do not exist; the about page says who decides administrator
access.

## F4. Route map

| Path                                  | View                                       | Backend route                                    |
| ------------------------------------- | ------------------------------------------ | ------------------------------------------------ |
| `/`                                   | redirect to last-used or first environment | —                                                |
| `/auth/callback`                      | OIDC redirect handler                      | —                                                |
| `/auth/silent`                        | silent-renew target, renders nothing       | —                                                |
| `/e/:env/secrets`                     | Secrets catalog                            | `GET /v1/admin/secrets`                          |
| `/e/:env/secrets/new`                 | Create wizard                              | `POST /v1/admin/secrets`, then payload `PUT`     |
| `/e/:env/secrets/:secretId`           | Secret detail                              | `GET /v1/admin/secrets/{id}`                     |
| `/e/:env/secrets/:secretId/metadata`  | Metadata and ACL editor                    | `PUT /v1/admin/secrets/{id}`                     |
| `/e/:env/secrets/:secretId/payload`   | Payload editor                             | `GET`, then `PUT /v1/admin/secrets/{id}/payload` |
| `/e/:env/secrets/:secretId/revisions` | History                                    | `GET .../revisions`                              |
| `/e/:env/consumers`                   | Consumer list                              | `GET /v1/admin/consumers`                        |
| `/e/:env/consumers/new`               | Enroll                                     | `POST /v1/admin/consumers`                       |
| `/e/:env/consumers/:consumerId`       | Consumer detail and identities             | `GET /v1/admin/consumers/{id}`                   |
| `/trust`                              | Issuer and truststore status               | `GET /v1/admin/issuer`                           |
| `/about`                              | Deployment info, documented exclusions     | `config.json` only                               |

Environment is a path segment rather than store-only state, so a URL is
shareable and a mis-scoped request is visible in the address bar. Switching
environments is a route change that resets all cursors.

No route carries a secret ID in a query string, and none carries payload
material in any form.

## F5. Screens

**Shell.** Environment switcher, signed-in subject, deployment name, a global
error surface with a copyable `correlationId`, and an explicit refresh control.
Nothing live-updates.

**Secrets catalog.** Table over the catalog route: secret ID, path, tags,
state, payload key count, last updated. Path-prefix navigation and exact tag
filters map to the query parameters. Sorted by path then secret ID, matching
the index order. Rendered entirely from the page response — never per-row
detail fetches.

**Secret detail.** The control revision in full, plus payload key information
when present. Actions: edit metadata, edit ACL, and edit or explicitly load the
current payload. Plaintext never enters shared console state or query caches.

**Create secret.** Two API calls presented as one guided flow, because a secret
created without a payload is `PENDING_VALUE` and undeliverable. If step two
fails the wizard resumes from the returned `controlVersionId` with a fresh
idempotency key; it does not restart at step one. Generated IDs are
`sec-<uuid>`, so the form encourages an explicit readable ID.

**Payload editor.** Key/value rows with a per-row `utf8`/`base64` toggle,
masked values with per-row reveal. Client-side validation mirrors
`src/domain/validation.ts` exactly — key charset `[A-Za-z0-9._-]+`, canonical
RFC 4648 base64, and a live size meter computing
`TextEncoder().encode(JSON.stringify(payload)).length` against 768,000 bytes,
the same measurement the service makes. Mirrored for feedback only; the server
decides.

The confirmation dialog is the safety mechanism. With key names available it
lists by name every key present in the current revision but absent from the
form as "will be destroyed". With only a count it states the arithmetic — "4
entries exist, you are submitting 2". With neither, a generic
full-replacement warning.

A `.env` paste import is worth building. A payload export is not, and will not
be added.

**ACL editor.** Consumer picker sourced from the consumer list filtered to the
secret's environment, capped at forty grants, `read` the only permission.
Removing a consumer warns that the consumer receives a `REVOKED` tombstone
through `GET /v1/changes` and that the operator must delete the corresponding
Kubernetes Secret — removal here deletes nothing on the consumer.

**Consumers.** List, then detail with the identity table: fingerprint, status,
validity window, and an expiring-soon indicator derived from `notAfter`
client-side, since the API never reports `EXPIRED`.

**Enroll consumer.** CSR paste or upload, pre-validated locally for PEM
structure, ≤32 KiB, and RSA ≥2048 via WebCrypto — rejecting locally saves a
permanent audit write and a round trip. The result screen appears once and is
the only place the issued certificate is shown, with copy and download for the
leaf PEM, the leaf fingerprint, and the root fingerprint. It states that Hemlig
never received a private key.

**Revoke identity.** Confirmation states that revocation takes effect
immediately at the application layer via a strongly consistent read, and that a
replacement leaf should already be distributed if continuity matters. Shows how
many other active identities the consumer has; revoking the last one gets a
harder confirmation.

**Trust status.** Root fingerprint and validity, current truststore key and
version, anchor count. Read-only, and explicit that issuer-root rotation is not
exposed.

## F6. Behaviors the backend forces

These implement [the leakage table](#what-leaks-across). They belong in
`packages/console/README.md` so a future contributor does not helpfully undo
them.

### Optimistic concurrency

Every mutation sends `If-Match` built from the `controlVersionId` in the last
response body, not the ETag header. The handler tolerates quoting.

A `412` is never retried automatically. It opens a panel that says the secret
changed underneath, preserves the draft, and offers reload-and-reapply.
Silently re-reading and resubmitting would defeat the entire design.

### Idempotency, which is asymmetric

**Secret routes hard-conflict.** `src/services/secrets.ts:255-261` throws `409`
for any previously used key and does not replay the original response. After a
network error or timeout the console must not resubmit with the same key — a
guaranteed `409` — and must not resubmit with a new key — a possible double
write. Instead: mark the submission outcome-unknown, refetch, compare
`controlVersionId` and `payloadVersionId` against the pre-submit values, and
report what actually happened.

**Consumer routes replay.** `src/services/consumers.ts:359` returns the recorded
result for a repeated key. Retrying with the same key is safe and is the right
response to a transient `503`.

Keys are generated once per submit intent with `crypto.randomUUID()`, held in
form state, never regenerated by a re-render, never derived from form content.

### Ambiguous outcomes are not errors

`500`, `503`, a network failure, and a timeout are all **outcome unknown** on a
mutation. The request may have committed. Secret routes reconcile exactly as
for `409`; only consumer routes may retry. An earlier draft applied
reconciliation only to `409`, which was too narrow.

### Pagination

The catalog cursor is opaque and server-side, bound to the actor plus a hash of
environment, path prefix, and tags, and expires after fifteen minutes. Any
filter change resets to the first page rather than sending a cursor that will
`400`. Forward-only: no page numbers, no jump-to-page.

**A page can be empty and still have a `nextCursor`.** The query takes 100
items then applies the `READY` and tag filters, so matches may be sparse. Keep
following the cursor until it is absent, and do not render "no results" before
then. Implement as an auto-continuing fetch with a bounded hop count and a
"keep searching" control, not a Load More button that appears to do nothing.

### Audit write discipline

Every request writes `attempted` and `authorized` objects before the handler
routes, plus a terminal event, into an Object Lock Compliance bucket whose
default retention is seven years. They cannot be deleted, and their retention
cannot be shortened, until that window expires.

- No polling. No `refetchInterval`, no `refetchOnWindowFocus`, no background
  revalidation. Configure `@tanstack/vue-query` with these off globally.
- `staleTime` five minutes, cache reused across navigation.
- No N+1. A list view renders from its page response only.
- Refresh is an explicit user action.

One catalog render costs three audit objects. Per-row detail fetches on a
100-row page would write three hundred that nobody can remove for seven years.
This is not a performance preference.

### Payload hygiene

Payload values exist only in the editor component's local state, for its
lifetime. Never in the URL, router state, Pinia, the query cache, browser
storage, or an error message. Cleared on unmount and navigation. Inputs use
`autocomplete="off"` and `spellcheck="false"`, masked by default.

### Error taxonomy

| Status                         | Behavior                                                                                                                                                                                     |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401` (no envelope)            | Gateway rejected the token before Lambda — expired, malformed, wrong audience, missing scope. Re-authenticate. **No error envelope and no `correlationId`** — do not try to parse one.       |
| `403 forbidden`                | Gateway accepted the token, the handler rejected it. Gateway and Lambda configuration have drifted. Show a configuration-error state; re-authenticating will not help.                       |
| `400 bad_request`              | Inline field error where the message identifies a field, otherwise a toast with `correlationId`.                                                                                             |
| `404 not_found`                | Empty state, not an error toast. On the issuer route, "no consumers enrolled yet".                                                                                                           |
| `409 enrollment_failed`        | Terminal enrollment failure — stop and surface the operation ID; repair issuer or truststore configuration before retrying. Other `409` responses require normal idempotency reconciliation. |
| `412 precondition_failed`      | The concurrency panel.                                                                                                                                                                       |
| `500`, `503`, network, timeout | Outcome unknown, per above.                                                                                                                                                                  |

Distinguishing `401` from `403` matters and an earlier draft had it wrong. The
authorizer rejects expired and wrong-audience tokens itself, before the Lambda,
with a bare `401`. A `403` can only come from `humanActorFromEvent` — a
deployment configuration problem, not a session problem. Treating it as "log in
again" would produce a redirect loop.

`correlationId` is always shown with a copy button — it is the only handle an
operator has for correlating against the audit archive and access logs.

---

# Part III — The seam

Three things belong to neither side alone. Each has a named owner anyway,
because shared ownership is how contracts rot.

## S1. `@hemlig/client` — the contract in TypeScript

**Owner:** backend, because it expresses the contract. **Consumed by:** the
console, the Pulumi provider, and the Kubernetes controller.

The package already has the right shape — a `HemligTransport` interface with
the Node implementation separate. It needs to stop importing Node built-ins
from the core entry point:

- Subpath exports: `@hemlig/client` (isomorphic core — types, `HemligClient`,
  `HemligTransport`, `HemligError`, a new `FetchTransport` on global `fetch`)
  and `@hemlig/client/node` (`NodeHttpsTransport`).
- Widen `TransportRequest["method"]` to include `DELETE`. It is currently
  `"GET" | "POST" | "PUT"` and cannot express identity revocation.
- Drop the `randomUUID` default for idempotency keys. Make the key explicit, or
  accept an id factory. A default that silently generates a fresh key per call
  is exactly wrong for the retry semantics in
  [F6](#idempotency-which-is-asymmetric).
- Add the missing methods: `listSecrets`, `listSecretRevisions`,
  `listConsumers`, `getConsumer`, `listApiIdentities`, `enrollConsumer`,
  `rotateApiIdentity`, `revokeApiIdentity`, `getIssuer`.
- Keep `lib` free of `DOM`; Node 24 and modern browsers both provide `fetch`.
- Version 0.2.0. Pre-1.0, so the subpath split is acceptable churn.

The console adds no API surface of its own. If it needs a method, the method
belongs here, which means the contract supports it, which means Part I covered
it.

## S2. The `config.json` handoff

**Owner:** backend CDK writes it; frontend reads it.

This is the only place backend deployment values reach frontend code, and it is
deliberately a data file rather than a build-time constant so one immutable
bundle deploys to every environment. Its schema is validated by `zod` on load
(`src/config.ts`); a malformed or missing file is a hard boot failure with a
readable message, never a half-configured app.

CloudFront serves it `no-cache` while hashed assets get a long immutable
max-age.

## S3. Static hosting

**Owner:** backend CDK. **Serves:** frontend output. Created only when the
console is enabled.

- **S3 bucket.** Private, `BLOCK_ALL`, S3-managed encryption, versioned,
  `enforceSSL`, `DESTROY`, with automatic object deletion. No Object Lock —
  static assets are not evidence.
- **CloudFront.** Origin Access Control via
  `S3BucketOrigin.withOriginAccessControl`, HTTP/2 and HTTP/3, minimum TLS
  1.2_2021, `defaultRootObject: index.html`, 403/404 rewritten to
  `/index.html` with status 200 for SPA routing.
- **Certificate.** CloudFront requires ACM in **us-east-1**, and the existing
  regional certificate (`cdk/stack.ts:129`) covers only the admin and consumer
  FQDNs. Accept a validated `consoleCertificateArn`, or create a **sibling
  top-level stack** in `us-east-1` with `crossRegionReferences: true` on both.
  Not a nested stack — a `NestedStack` inherits its parent's region.
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
    frame-src 'self' https://login.example.com;
    form-action 'none';
    frame-ancestors 'none';
    base-uri 'none';
    object-src 'none'
  ```

  `connect-src` must name the admin API origin because the topology is
  deliberately cross-origin — this is the CSP consequence of the boundary
  decision. It assumes the provider's token and JWKS endpoints share the
  issuer's origin, which holds for Entra, Okta, and Auth0 but not for every
  provider (Google issues from `accounts.google.com` and serves tokens from
  `oauth2.googleapis.com`). A provider that splits them needs both origins.

  **`frame-src` must name `'self'` as well as the provider**, and an earlier
  draft of this plan got that wrong. Silent renew points a hidden iframe at the
  provider, and the provider then redirects that iframe back to
  `https://<consoleFqdn>/silent.html`. CSP re-checks `frame-src` against the
  redirect target, so without `'self'` the navigation back is blocked and every
  renewal fails — leaving requests with no bearer token and a `401`, which is
  worse than the full-redirect fallback this was supposed to preserve.
  `frame-ancestors 'self'` on the target document is necessary but not
  sufficient: the parent's `frame-src` governs the navigation, the child's
  `frame-ancestors` governs the embedding. Both are required.

  **`/auth/silent` needs its own header policy.** Silent renew loads the
  provider in a hidden iframe, and the provider redirects back to the console's
  own `/auth/silent`. That callback document is therefore framed by the console,
  which `frame-ancestors 'none'` and `X-Frame-Options: DENY` forbid. `frame-src`
  permits framing the provider; it says nothing about the console being framed.
  With the policy above applied uniformly, silent renew fails every time and
  every session degrades to a full redirect. Add a dedicated cache behavior for
  `/auth/silent` with `frame-ancestors 'self'` and
  `X-Frame-Options: SAMEORIGIN`, keeping `'none'` / `DENY` everywhere else.
  Verify the round trip against a real provider; this cannot be caught locally.

  `includeSubDomains; preload` at the apex commits `admin.` and `api.` too.
  Both are HTTPS-only, so this is fine, but it is a deliberate commitment.

- **Cache behaviors.** The **default** behavior must be uncached, with an
  explicit `/assets/*` behavior carrying the long `immutable` `max-age`.
  Inverting this is a trap: CloudFront selects a behavior from the viewer
  request URI _before_ `defaultRootObject` is applied, so `/` matches the
  default behavior rather than any `/index.html` pattern — an aggressive
  default caches the app shell at the edge, and invalidating `/index.html`
  clears a different cache key. Deep links behave the same way. Give the
  `errorResponses` a zero TTL for the same reason.
  Edge caching is not browser caching: `CACHING_DISABLED` says nothing to the
  viewer, and S3 sends no `Cache-Control`, so the headers policies must set it
  — `no-store` for the shell, `immutable` for hashed assets.
- **Publication.** `BucketDeployment` with the built output plus
  `Source.jsonData("config.json", ...)`, with `distribution` and
  `distributionPaths: ["/index.html", "/config.json"]`. This is a
  CloudFormation custom resource — distinct in kind from the S3 auto-delete
  resource the project avoids, since it destroys no data — and it is skipped
  when the built output is absent, following the same `existsSync` pattern the
  construct already uses for Lambda entry points. An installer preferring
  pipeline control omits the console config and syncs the bucket itself.
- **Packaging.** The root `package.json` `files` array includes the built
  console output; `build:cdk` depends on the console build.
- **Outputs.** `ConsoleUrl`, `ConsoleBucketName`, `ConsoleDistributionId`.

## S4. Testing across the boundary

| Layer         | Owner    | What                                                                                                                                                         |
| ------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Backend unit  | Backend  | Existing Jest suites, extended for B4 inheritance, B5 index queries, B6 `DELETED` inclusion, B7 error code                                                   |
| Frontend unit | Frontend | Mirrors of `src/domain/validation.ts` rules, the idempotency reconciliation state machine, cursor-reset logic                                                |
| Component     | Frontend | Destructive-replace confirmation, ten-grant ACL cap, 412 panel preserving a draft, 409 reconciliation, empty-page-with-cursor                                |
| **Contract**  | **Seam** | MSW fixtures generated from `openapi/consumer-secrets.yaml`, plus a test that fails if the console sends a header or parameter the contract does not declare |
| End-to-end    | Frontend | Playwright with a mocked provider and MSW: create → payload → ACL; enroll → download leaf → revoke                                                           |
| Acceptance    | Backend  | Isolated AWS account                                                                                                                                         |

The contract test is the boundary made executable, and it is the reason B10
ships with the handlers rather than after them. If the console and the service
disagree, that test fails before anything reaches an environment.

**No automated test may run against a real deployment's administrator API.**
Every request writes audit objects into a Compliance-locked bucket. State this
in the console README.

MiniStack cannot exercise OIDC, CORS preflight, or the JWT authorizer. Preflight
versus the `$default` route, the access-token audience, the required scope, the
apex certificate, and the `/auth/silent` framing all need the isolated AWS
acceptance environment `PLAN.md` already calls for.

## S5. Phasing

Two streams. The backend stream is the long pole and the only one that touches
the service; the frontend stream is additive and carries no service risk.

| Phase | Stream   | Content                                                                                                                | Status                                                                                                                    |
| ----- | -------- | ---------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| 0     | Backend  | B1–B10                                                                                                                 | **Done.** B1's domain rename landed as `api.N.domain.com`; see below.                                                     |
| 1     | Frontend | Workspace, Vite, config bootstrap, OIDC, shell, environment switcher, error plumbing, catalog, secret detail read-only | **Done**                                                                                                                  |
| 2     | Frontend | Create wizard, metadata/ACL editing, payload editor, concurrency and idempotency handling                              | **Done**                                                                                                                  |
| 3     | Frontend | Consumers, enrollment, rotation, revocation, trust status                                                              | **Done**                                                                                                                  |
| 4     | Seam     | S3, host construct, us-east-1 certificate, CSP, publication, README, monorepo table                                    | In progress                                                                                                               |
| 5     | Both     | Acceptance runbook (`docs/acceptance.md`)                                                                              | **Done.** CSP is enforced from the outset rather than rolled out report-only, and accessibility is deliberately deferred. |

### What Phase 0 actually shipped, versus this plan

Two places the implementation deliberately diverged, both improvements:

- **B5 predicted no backfill.** Wrong: a sparse GSI only indexes items that
  already carry its key attributes, so pre-existing consumers, identities, and
  revisions stay invisible until they are rewritten.
  `src/scripts/backfill-console-indexes.ts` exists for that, dry-run by default.
  It is unnecessary for a greenfield deployment.
- **B6 said not to add a time-ordered sort key** and to sort history in the
  handler. The implementation added a third sparse index, `secret-revision`,
  keyed `revisionPk = SECRET#<id>` / `revisionSk = <createdAt>#<controlVersionId>`,
  and reads it with `ScanIndexForward: false`. That is strictly better: newest-first
  for free, and a bounded read that does not depend on partition size.

### Local development

MiniStack has no API Gateway and no identity provider, so the console cannot
obtain a token or reach a deployed route locally. `yarn dev:api` provisions
a stable MiniStack environment and invokes the matching administrator or
audit-query handler in process behind a loopback HTTP bridge, fabricating the
JWT claims API Gateway would
have validated. It refuses to run against a non-local `AWS_ENDPOINT_URL`,
unsets any ambient `AWS_PROFILE`, and is never packaged.

The bridge exercises the real handler against real DynamoDB, S3, and KMS. It
cannot exercise mTLS, the JWT authorizer, CORS preflight against the deployed
`$default` route, Object Lock retention, or IAM.

**Phases 1–3 do not wait for Phase 0 to deploy.** They wait only for B10 — the
published contract — because MSW fixtures generated from the OpenAPI file are a
complete substitute for a running service during development. That is the
practical payoff of the boundary: once the contract is written, the two streams
proceed independently, and the contract test tells you when they have drifted.

### Backend work breakdown

| #   | Item                                                          | Touches                                                                                            | Depends on |
| --- | ------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- | ---------- |
| B1  | Preserve delivery FQDN; optional console origin configuration | `cdk/config.ts`, `cdk/stack.ts`, tests, docs                                                       | —          |
| B2  | CORS and the `OPTIONS /{proxy+}` route                        | `cdk/stack.ts`, `cdk/stack.test.ts`                                                                | B1         |
| B3  | Required `hemlig.admin` scope                                 | `cdk/config.ts`, `cdk/stack.ts`, `src/aws/config.ts`, `src/auth/actors.ts`, `docs/threat-model.md` | B1         |
| B4  | Count-only payload information and inheritance                | `src/domain/types.ts`, `src/services/secrets.ts`, `src/repositories/dynamo.ts`, tests              | —          |
| B5  | Two sparse GSIs and four read routes                          | `cdk/stack.ts`, `src/aws/config.ts`, `src/repositories/dynamo.ts`, `src/handlers/admin.ts`         | —          |
| B6  | Revision history route                                        | `src/handlers/admin.ts`, `src/repositories/dynamo.ts`                                              | —          |
| B7  | Terminal enrollment error code                                | `src/services/consumers.ts`, `docs/api.md`                                                         | —          |
| B8  | `sourceIp` through `humanOperation`; stale doc corrections    | `src/services/operations.ts`, handlers, `docs/`                                                    | —          |
| B10 | OpenAPI and docs                                              | `openapi/`, `docs/`, `README.md`                                                                   | B2–B8      |
| S1  | `@hemlig/client` split and new methods                        | `packages/client/`                                                                                 | B10        |

B2 and B3 are opt-in: existing machine-to-machine callers remain audience-only
until `consoleFqdn` and `oidcAdminScope` are configured together. B4–B8 are
independent. A backfill is required for the new sparse index attributes on an
existing table; `backfill-console-indexes --apply` is idempotent and changes no
secret or certificate material.

---

## Decision record

### In-browser CSR generation

**Originally settled as paste-only; later reversed to add an opt-in generator.**

The first decision was that the console would accept a pasted or uploaded CSR
and nothing else, so that a consumer's private key never existed in an
administrator's browser. That remains the stronger option and stays the default
path in the UI.

The reversal was a deliberate usability call: bootstrapping a consumer required
an operator to have OpenSSL to hand and to get the key parameters right, and the
friction was pushing people toward worse workarounds. The generator is
therefore additive and clearly marked, not a replacement.

What keeps the weaker path honest:

- The key is generated with WebCrypto, held only in component state, and offered
  once for download. It is never transmitted, never written to any browser
  storage, and cleared on unmount.
- Closing the modal requires an explicit acknowledgement that the key was saved,
  so nobody walks away having copied only the CSR.
- The UI says plainly that generating on the consumer host is stronger.

### Why the CSR is assembled by hand rather than with a library

WebCrypto can generate an RSA key but cannot build a PKCS#10 CSR — the platform
has no ASN.1 — so something has to write the DER. The console writes it
directly instead of taking `@peculiar/x509` (8+ transitive packages), `pkijs`
(6), or in-browser `node-forge` (zero-dep but pure-JS, so keygen takes seconds).

The decisive argument is that **a DER writer whose output is verified fails
closed.** A bug in an ASN.1 _parser_ is dangerous, because malformed input can
be coerced into something that wrongly validates. A bug in a _writer_ can only
produce bytes that fail to parse — and this output is checked twice, by a unit
test using the same node-forge parser `src/services/issuer.ts` runs
server-side, and by the service itself on submit. No DER bug can yield a weaker
but accepted CSR.

All the actual cryptography is WebCrypto in either design; the DER is only
framing around a key WebCrypto produced. A library would be replacing
envelope-writing code, not crypto code. And this is the one code path where an
administrator's browser holds a consumer private key, so keeping third-party
code out of it is worth more here than it would be in an ordinary application.

The scope stays small because the CSR is deliberately minimal — version 0, one
CN, the SPKI verbatim from WebCrypto, empty attributes. Hemlig sets the SPIFFE
URI SAN and the clientAuth EKU itself and ignores caller-supplied subjects, so
general-purpose ASN.1 is never needed.

**When to revisit:** if the CSR ever has to carry real extensions — SANs, key
usage, challenge attributes — hand-rolling stops being proportionate and
`@peculiar/x509` is the right swap. Everything sits behind the single
`generateCsr()` boundary, so that change touches one module and the tests carry
over unchanged.

### Payload key names

**Settled: do not store or return them.**

The original decision was to add `payloadKeys` on the grounds that
administrators can already write key names, and consumers holding a read grant
already receive them. External review showed that understates the exposure.

Control revision objects are readable by the consumer Lambda role for **every**
secret in the deployment: `revisionBucket.grantRead(consumerFunction)` grants
bucket-wide object read, and the delivery path loads the control document
(`src/services/secrets.ts:201`). A compromised consumer role can read the control
revision of secrets it holds no grant for.

That is already true for `description`, `path`, `tags`, and the
full ACL, so the control revision is already a broad metadata disclosure
surface and `payloadKeys` extends an existing exposure rather than opening a new
one. But key names are more likely than a description to name a system or a
credential, and the field is immutable and retained.

| Option                            | Console capability                                            | Disclosure                                                                         |
| --------------------------------- | ------------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| `payloadKeys` + `payloadKeyCount` | Pre-filled editor; names the exact keys about to be destroyed | Key names in every control revision, readable by the consumer role for all secrets |
| `payloadKeyCount` only            | Confirmation states "4 entries exist, you are submitting 2"   | A count; no names                                                                  |
| Neither                           | Blind replace-all with a generic warning                      | None                                                                               |

Count-only carries most of the safety value — it stops the destructive edit — at
a fraction of the disclosure. Names buy editing convenience, not safety, so
the v0.3 contract stores and returns only `payloadKeyCount`.

### Environment enumeration

**Originally settled as a deployment constant shipped in `config.json`; later
reversed to an administrator-defined runtime API.**

[B9](#b9-environment-enumeration) originally argued the opposite of what it says
today: the set of secret environments was a deployment fact the installer
already knew, so it was threaded through `DeploymentConfig.secretEnvironments`,
baked into the Lambda environment, and copied into the console's `config.json`
at synth time. No route existed to list or create one, and the section was
titled "explicitly not an API" for exactly that reason.

That argument was wrong. An environment turned out to be operator data with a
lifecycle and an author — created after the deployment already exists, by a
specific administrator, through the running system — not a constant fixed at
synth time alongside FQDNs and OIDC settings. Treating it as deployment
configuration meant every new environment required a CDK change and a
redeploy, and the copy baked into `config.json` could silently drift from
whatever the handlers actually accepted.

The reversal replaces all of that with `GET`/`POST /v1/admin/environments`,
backed by DynamoDB records the handlers themselves validate against. A fresh
deployment now starts with no environments at all; an administrator creates the
first one at runtime. `cdk/config.ts`, `cdk/stack.ts`, and
`cdk/console-runtime-config.ts` no longer carry `secretEnvironments` in any
form, and the console sources its environment switcher from the API instead of
`config.json`.

## Risks

- **Preflight versus the `$default` route** is the highest-risk unverified item
  and the most likely cause of a dead console on first deploy. The explicit
  unauthenticated `OPTIONS /{proxy+}` route is in place and synthesises with
  `AuthorizationType: NONE` and no scopes, but whether API Gateway attaches the
  configured CORS headers to an _integration_ response on an explicit OPTIONS
  route cannot be tested locally — MiniStack has no API Gateway. If it does not,
  preflight returns 204 with no `Access-Control-Allow-Origin` and every request
  is blocked. The obvious fallback may not work either: AWS documents that when
  CORS is configured, integration-supplied CORS headers are ignored. The real
  fallback is dropping `defaultIntegration`/`$default` for explicit per-route
  definitions so no route matches OPTIONS. Test this first in the isolated
  account.
- **The required admin scope changes an enabled console deployment.** Configure
  the provider to mint `oidcAdminScope` before setting `consoleFqdn`; existing
  audience-only machine callers are otherwise unaffected.
- **Access-token audience** is the most likely first-run failure and needs
  per-provider documentation.
- **Silent renew** is blocked by some providers and by strict third-party cookie
  policies even with the `/silent.html` header policy correct. The redirect
  fallback works but interrupts the session; confirm that is acceptable before
  committing to no persisted refresh token.
- **Payload key names remain intentionally unavailable.** The console must make
  clear that a payload update is replacement, using `payloadKeyCount` only for
  a destructive-change warning.
- **No delete route** means the console can never remove a secret. Every
  retirement affordance must be honest that ACL removal plus the tombstone is
  the only path.
