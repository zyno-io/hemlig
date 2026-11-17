# Hemlig administrator CLI

`@zyno-io/hemlig-cli` lives in `packages/cli` and exposes the `hemlig` executable. It
uses [`@zyno-io/hemlig-client`](../packages/client/src/index.ts) against the
[administrator API](api.md) and [OpenAPI contract](../openapi/consumer-secrets.yaml).
It requires Node.js 24. It manages existing environments; it does not provision
Hemlig infrastructure, enroll consumers, redeem bootstrap tokens, or manage
Kubernetes `HemligSecretImport` / `HemligSecretExport` resources.

## Build and run from the checkout

```bash
yarn install --immutable
yarn workspace @zyno-io/hemlig-client build
yarn workspace @zyno-io/hemlig-cli build
yarn workspace @zyno-io/hemlig-cli exec hemlig --help
```

`node packages/cli/dist/main.js --help` also works. The package declares the
`hemlig` bin for installation after publication; adding this workspace does not
publish it to a registry.

## Authentication and environment

Set the administrator origin and an existing logical secret environment
explicitly. The delivery origin is for mTLS workloads, not this CLI. There is
no default production endpoint.

```bash
export HEMLIG_ADMIN_URL=https://admin.hml.aws-sec.sgnl24.net
export HEMLIG_ENVIRONMENT=production
export HEMLIG_ADMIN_TOKEN_FILE=/run/secrets/hemlig-admin-oidc-token
```

The file contains only the raw OIDC bearer JWT, with optional surrounding
whitespace. Obtain it from the configured identity provider; the CLI does not
perform a browser login, refresh a token, or prompt. Use a private mounted file
for unattended callers. `HEMLIG_ADMIN_TOKEN` is also supported for callers that
already inject the raw JWT through their process environment. API Gateway
validates issuer, audience, expiry, scopes and configured role requirements.
Bootstrap capabilities (`hmlb_…`) are rejected.

`--admin-url` and `--environment` override their environment variables.
`--token-file` overrides `HEMLIG_ADMIN_TOKEN_FILE`; either file source takes
precedence over `HEMLIG_ADMIN_TOKEN`. There is no raw `--token` argument, so a
token need not appear in a command line. Origins must use HTTPS, except HTTP on
`localhost`, `127.0.0.1` or `[::1]` for local development. URL credentials,
paths, queries and fragments are rejected; redirects are never followed.

## Commands

Every secret command requires `--secret-id`, except an archived metadata read,
which requires `--secret-uid` instead. IDs can contain folder separators.
All commands require an explicit administrator origin, token and environment.

| Command                    | JSON input              | Concurrency            | Typed client method      |
| -------------------------- | ----------------------- | ---------------------- | ------------------------ |
| `secret create`            | `metadata` and `acl`    | New operation key      | `createAdminSecret`      |
| `secret update`            | `metadata` and/or `acl` | ETag and operation key | `updateAdminSecret`      |
| `secret write-payload`     | Raw payload entry map   | ETag and operation key | `putAdminPayload`        |
| `secret read`              | None                    | None                   | `getAdminSecret`         |
| `secret read-payload`      | None                    | None                   | `getAdminSecretPayload`  |
| `secret archive`           | None                    | ETag and operation key | `archiveAdminSecret`     |
| `secret read --secret-uid` | None                    | None                   | `getArchivedAdminSecret` |

Use `--input path.json` or `--input -` for piped JSON. Stdin is not read unless
requested, and a terminal attached to `--input -` is rejected without prompting.
Input is bounded to 768,000 bytes. Payload files and stdin are never echoed in
diagnostics. API error messages are summarized instead of being echoed because
some validation messages include payload entry names.

Create a secret's metadata and ACL before writing its payload:

```bash
printf '%s\n' '{"metadata":{"description":"Payments API","tags":{"owner":"payments"}},"acl":[]}' |
  hemlig secret create --secret-id payments/stripe/api-key --input - > created.json
```

The environment and secret ID come from flags/environment variables, not the
input JSON. The new secret has state `PENDING_VALUE`. A payload write activates
it. `acl` may contain enrolled same-environment consumers with `read` permission.

Read metadata without decrypting the payload:

```bash
hemlig secret read --secret-id payments/stripe/api-key > current.json
```

Use the returned version to update only the ACL:

```bash
etag=$(jq -r .etag current.json)
printf '%s\n' '{"acl":[{"consumerId":"prod-east","permissions":["read"]}]}' |
  hemlig secret update --secret-id payments/stripe/api-key --if-match "$etag" --input - > updated.json
```

Update accepts either field or both. Omitted fields are preserved by the API.
A supplied `metadata` object replaces metadata, including tags; a supplied
`acl` array replaces the whole ACL. Empty objects/arrays intentionally clear
those fields. The CLI rejects unknown top-level fields rather than silently
discarding misspelled configuration. `metadata.path` is unsupported; folders
come from `secretId`.

A payload file is the raw entry map, without a `payload` wrapper:

```json
{
  "username": { "encoding": "utf8", "value": "service-account" },
  "binary": { "encoding": "base64", "value": "AP8=" }
}
```

```bash
etag=$(jq -r .etag updated.json)
hemlig secret write-payload --secret-id payments/stripe/api-key --if-match "$etag" --input payload.json > written.json
```

This replaces the entire payload. Entry names and explicit UTF-8/canonical
base64 values follow the API contract. The serialized request must fit within
768,000 bytes. Mutation receipts contain control metadata, never the written
payload. To deliberately read a decrypted payload:

```bash
hemlig secret read-payload --secret-id payments/stripe/api-key > payload-receipt.json
```

That command returns the payload under `data.payload`. Treat its stdout and any
redirected file as secret material; the CLI does not print it on stderr.

## ETags and idempotency

`update`, `write-payload` and `archive` require `--if-match`. Pass `.etag` from a
receipt or the API's `controlVersionId`; a quoted strong ETag is accepted too.
The typed client supplies the quotes in `If-Match`. Weak ETags and `*` are
rejected. The flag never silently defaults to the latest revision.

If the intent is explicitly to operate on the latest active record, use
`--if-match current`. The CLI makes one metadata GET and one mutation with the
GET's version. A concurrent change returns exit 6 / HTTP 412; the CLI never
refetches or retries. This mode addresses the active record currently holding
the public ID, which may be a replacement after archival. Use a previously
read ETag when the operation must affect the record you inspected earlier.

Every mutation accepts `--idempotency-key` (8–128 printable non-space ASCII
characters). If omitted, the CLI mints a UUID once and returns it in the
success or post-preflight error receipt. Keys identify an intended operation,
not a secret. Nothing is retried automatically, including a timeout or 5xx.

For automation that must retain the key even if the process is killed, mint
and persist it before calling the mutation:

```bash
umask 077
hemlig idempotency-key > archive-operation.json
key=$(jq -r .idempotencyKey archive-operation.json)
etag=$(jq -r .etag written.json)
hemlig secret archive --secret-id payments/stripe/api-key --if-match "$etag" --idempotency-key "$key" > archived.json
```

`idempotency-key` needs no authentication or environment. Supply the same saved
key and ETag if intentionally retrying the same operation. A used key produces
HTTP 409; the API does not replay the initial success response. Retain the
initial receipt. After a lost response, inspect authoritative state and decide
how to reconcile; do not mint a new key just to bypass a conflict.

Archival releases `secretId` for reuse and revokes the old record's grants. Keep
`data.secretUid` from the archive receipt and address the old record by UID:

```bash
uid=$(jq -r .data.secretUid archived.json)
hemlig secret read --secret-uid "$uid" > archived-metadata.json
```

There is no archived payload read or UID mutation command.

## Output and exit codes

Success emits exactly one JSON object plus newline on stdout, with no stderr
output. There are no progress banners, prompts, tables, or automatic retries.
Flags may precede the command. `--help` also returns JSON.

```json
{
  "data": {
    "secretUid": "sec-example",
    "secretId": "payments/stripe/api-key",
    "environment": "production",
    "controlVersionId": "ctl-next",
    "state": "ARCHIVED",
    "metadata": {},
    "acl": []
  },
  "etag": "ctl-next",
  "idempotencyKey": "59fef72b-4e51-4a0d-9f3a-3929e030eb31",
  "ifMatch": "ctl-prior"
}
```

`data` is the API response. `etag` is its raw `controlVersionId` for the next
mutation. Mutation receipts include the operation key; guarded writes include
the raw version they matched. Reads omit those two mutation fields.

Failure leaves stdout empty and emits one JSON object on stderr:

```json
{
  "error": {
    "exitCode": 6,
    "code": "precondition_failed",
    "message": "Control revision changed. Read the current metadata and decide on a new operation.",
    "status": 412,
    "outcome": "rejected"
  },
  "idempotencyKey": "59fef72b-4e51-4a0d-9f3a-3929e030eb31",
  "ifMatch": "ctl-prior"
}
```

Local validation errors may occur before an operation key is minted. Once a
mutation key is chosen, errors include `outcome`: `not_sent` when a version
lookup failed before the mutation, `rejected` for a known client/API rejection,
or `unknown` for service/protocol/network errors after attempting the mutation.
`unknown` requires reconciliation and never means the write definitely failed.

| Exit | Meaning                                                                        |
| ---- | ------------------------------------------------------------------------------ |
| 0    | Success                                                                        |
| 2    | Usage, invalid local JSON/header/configuration, or API 400                     |
| 3    | API 401/403 authentication or authorization failure                            |
| 4    | API 404 secret or active payload missing                                       |
| 5    | API 409 conflict, including a used operation key                               |
| 6    | API 412 stale control revision                                                 |
| 7    | Service failure, unexpected HTTP status, malformed response, or internal error |
| 8    | Network, redirect, or timeout failure                                          |
| 9    | Local input/token file, stdin, or output I/O failure                           |

`--timeout-ms` bounds each HTTP request independently (default 30,000, maximum
300,000). The explicit `current` mode can use two request deadlines. With a
known ETag every operation uses one API call, avoiding unnecessary control
reads and their immutable audit writes.
