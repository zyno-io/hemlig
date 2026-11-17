---
title: Administrator CLI
description: Install and use the hemlig command to create, update, read and archive secrets, with every option, environment variable and exit code.
pageType: reference
---

# Administrator CLI

The `hemlig` command manages secrets on the [administrator API](../reference/glossary.md#administrator-api). Every command prints one JSON object, so it is safe to script.

It lives in `packages/cli` as `@zyno-io/hemlig-cli` and needs Node.js 24. It manages secrets in an existing [environment](../reference/glossary.md#environment). It does not deploy Hemlig, enroll consumers, redeem bootstrap tokens or manage Kubernetes resources.

For a task-oriented walkthrough with the console, curl and Pulumi alongside, see [Manage secrets](managing-secrets.md).

## Build and run from the checkout

The package is not published to a registry. Build it from a checkout:

```sh
yarn install --immutable
yarn workspace @zyno-io/hemlig-client build
yarn workspace @zyno-io/hemlig-cli build
yarn workspace @zyno-io/hemlig-cli exec hemlig --help
```

`node packages/cli/dist/main.js --help` also works.

## Get an administrator token

The CLI has no `login` command and does not open a browser, refresh a token or prompt. You supply a token that you already have.

A token is an OIDC **access token** for the API audience, issued by your identity provider. How you obtain one depends on that provider: use its own tooling or token endpoint, for example a service-account or client-credentials flow for automation. The token must satisfy the audience, scope and role rules in [Identity provider](identity-provider.md).

Put the raw token in a file readable only by you. The file holds the JWT and nothing else.

```sh
umask 077
printf '%s' "$ACCESS_TOKEN" > "$HOME/.hemlig-token"
```

Access tokens expire. Replace the file's contents when the token does. A bootstrap token (`hmlb_...`) is rejected here.

## Configuration

Set the administrator origin, an existing environment and a token source.

```sh
export HEMLIG_ADMIN_URL=https://admin.example.com
export HEMLIG_ENVIRONMENT=prod
export HEMLIG_ADMIN_TOKEN_FILE=$HOME/.hemlig-token
```

| Setting | Flag | Environment variable | Notes |
| --- | --- | --- | --- |
| Administrator origin | `--admin-url` | `HEMLIG_ADMIN_URL` | No default. HTTPS only, except HTTP to `localhost`, `127.0.0.1` or `[::1]`. No credentials, path, query or fragment. Redirects are never followed. |
| Environment | `--environment` | `HEMLIG_ENVIRONMENT` | The runtime environment. Not the deployment name; see [Configuration](../reference/configuration.md). |
| Token file | `--token-file` | `HEMLIG_ADMIN_TOKEN_FILE` | Path to a file holding the raw JWT |
| Token value | none | `HEMLIG_ADMIN_TOKEN` | Used only when no token file is set |
| Timeout | `--timeout-ms` | none | Per request, 1 to 300,000. Default 30,000. |

A file source beats `HEMLIG_ADMIN_TOKEN`. There is no `--token` flag, so a token never appears in a process list.

## Commands

Every `secret` command needs `--secret-id`, except an archived read, which needs `--secret-uid`.

| Command | Input | `--if-match` | Client method |
| --- | --- | --- | --- |
| `secret create` | JSON `metadata` and `acl` | No | `createAdminSecret` |
| `secret update` | JSON `metadata` and/or `acl` | Required | `updateAdminSecret` |
| `secret write-payload` | Raw payload entry map | Required | `putAdminPayload` |
| `secret read` | None | No | `getAdminSecret` |
| `secret read-payload` | None | No | `getAdminSecretPayload` |
| `secret archive` | None | Required | `archiveAdminSecret` |
| `secret read --secret-uid UID` | None | No | `getArchivedAdminSecret` |
| `idempotency-key` | None | No | Prints a new key; needs no configuration |

### Options

| Option | Applies to | Description |
| --- | --- | --- |
| `--secret-id` | Secret commands | Active secret ID. Folder separators allowed. |
| `--secret-uid` | `secret read` | Archived secret UID, from an archive receipt |
| `--input` | create, update, write-payload | A file path, or `-` to read piped stdin. A terminal on `-` is rejected. Limited to 768,000 bytes. |
| `--if-match` | update, write-payload, archive | A known ETag, or `current` (see below) |
| `--idempotency-key` | Mutations | 8 to 128 printable, non-space ASCII characters. Default: a new UUID. |

Input rules:

- The environment and secret ID come from flags, not from the JSON.
- A `metadata` value replaces all metadata, tags included. An `acl` array replaces the whole ACL. Empty values clear the field.
- Unknown top-level fields are rejected. `metadata.path` is not supported.
- A payload file is the bare entry map, with no `payload` wrapper.

Payloads and stdin are never echoed in diagnostics. A payload read prints the value under `data.payload`, so treat stdout as secret.

## ETags and idempotency

Every update, payload write and archive needs `--if-match`. Pass the `etag` field of the last receipt, or a quoted strong ETag. Weak ETags and `*` are rejected.

`--if-match current` makes one metadata read, then one mutation with that version. It is for deliberately acting on whatever record holds the ID now. A concurrent change returns exit 6 and the CLI does not retry.

Every mutation carries an idempotency key. If you omit it, the CLI creates one and returns it in the receipt. A used key returns HTTP 409, and nothing is retried automatically, including timeouts. The rules are in the [API idempotency table](../reference/api/index.md#idempotency).

To keep a key across a crash, create and save it first:

```sh
umask 077
hemlig idempotency-key > archive-operation.json
key=$(jq -r .idempotencyKey archive-operation.json)
etag=$(jq -r .etag written.json)
hemlig secret archive --secret-id payments/stripe/api-key --if-match "$etag" --idempotency-key "$key" > archived.json
```

After a lost response, read the secret to see what happened. Do not mint a new key just to get past a `409`.

## Output

Success prints exactly one JSON object on stdout and nothing on stderr. There are no banners, prompts or tables. `--help` also prints JSON.

| Field | Meaning |
| --- | --- |
| `data` | The API response |
| `etag` | The raw `controlVersionId`, ready for the next `--if-match` |
| `idempotencyKey` | The key used (mutations only) |
| `ifMatch` | The version matched (guarded writes only) |

A failure leaves stdout empty and prints one JSON object on stderr:

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

For a mutation, `outcome` says what happened:

| `outcome` | Meaning |
| --- | --- |
| `not_sent` | A preparatory read failed before the mutation was attempted |
| `rejected` | The API refused it |
| `unknown` | The attempt may or may not have applied. Reconcile by reading the secret. |

## Exit codes

| Exit | Meaning |
| --- | --- |
| 0 | Success |
| 2 | Usage, bad local JSON, header or configuration, or API 400 |
| 3 | API 401 or 403 |
| 4 | API 404 (secret or active payload missing) |
| 5 | API 409, including a used idempotency key |
| 6 | API 412, stale control revision |
| 7 | Service failure, unexpected status, malformed response or internal error |
| 8 | Network, redirect or timeout failure |
| 9 | Local input, token file, stdin or output I/O failure |

Exit codes map to API statuses. The API's own code names are in [Errors](../reference/api/errors.md).
