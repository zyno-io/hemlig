---
title: Administrator CLI
description: Install and use the hemlig command to create, update, read and archive secrets, list consumers and revoke client certificates, with every option, environment variable and exit code.
pageType: reference
---

# Administrator CLI

The `hemlig` command manages secrets on the [administrator API](../reference/glossary.md#administrator-api). Every command prints one JSON object, so it is safe to script.

It lives in `packages/cli` as `@zyno-io/hemlig-cli` and needs Node.js 24 or later. It manages secrets in an existing [environment](../reference/glossary.md#environment), and reads consumers and revokes their client certificates. It does not deploy Hemlig, enroll consumers, redeem bootstrap tokens or manage Kubernetes resources.

For a task-oriented walkthrough with the console, curl and Pulumi alongside, see [Manage secrets](managing-secrets.md).

## Build and run from the checkout

Install the published package from npm:

```sh
npm install --global @zyno-io/hemlig-cli
hemlig --help
```

To build it from a checkout instead:

```sh
yarn install --immutable
yarn workspace @zyno-io/hemlig-client build
yarn workspace @zyno-io/hemlig-cli build
yarn workspace @zyno-io/hemlig-cli exec hemlig --help
```

`node packages/cli/dist/main.js --help` also works.

## Get an administrator token

Two ways:

| Use                        | How                                                                                  |
| -------------------------- | ------------------------------------------------------------------------------------ |
| Interactive, at a terminal | [`hemlig login`](#sign-in-with-hemlig-login), which borrows your web console sign-in |
| Scripts and CI             | Supply a token you already have, in a file or variable (below)                       |

### Sign in with `hemlig login`

```sh
export HEMLIG_CONSOLE_URL=https://console.example.com
hemlig login     # add --no-browser to only print the URL; --no-localhost for SSH
hemlig logout    # deletes the cached login
```

1. The CLI opens `<console>/cli-login` in your browser and prints a confirmation code, such as `1W07-71DP`, on stderr.
2. Sign in to the console if asked. Check that the page shows the same code, then click **Authorize**.
3. The console hands its access token to the CLI, which listens on `127.0.0.1` only. The CLI reads the admin API address from the console's published `/config.json`.
4. stdout prints `{"loggedIn":true,"adminUrl":"…","expiresAt":"…"}`.

| Detail            | Behavior                                                                                                           |
| ----------------- | ------------------------------------------------------------------------------------------------------------------ |
| Cache file        | `~/.config/hemlig/admin-token` (`$XDG_CONFIG_HOME`, or `%APPDATA%` on Windows). Mode `0600` in a `0700` directory. |
| Lifetime          | The console's access token, usually about an hour. Run `hemlig login` again when it expires.                       |
| Admin URL         | Defaults to the cached login's API. A different `--admin-url` exits `3` rather than send the token elsewhere.      |
| Timeout           | 5 minutes waiting for Authorize                                                                                    |
| Identity provider | No change. The CLI does no OAuth itself.                                                                           |

#### Remote sessions (SSH)

Over SSH, your browser's `127.0.0.1` is not the machine running the CLI, so the localhost callback cannot work. The CLI then uses the copy-the-code sign-in: no listener, and no callback to localhost.

| Flag             | Effect                                                                          |
| ---------------- | ------------------------------------------------------------------------------- |
| (none)           | Copy-the-code when `SSH_CONNECTION` or `SSH_TTY` is set; otherwise localhost.   |
| `--no-localhost` | Force copy-the-code. Opens a browser only when not over SSH and not `--no-browser`. |
| `--localhost`    | Force the localhost callback. Cannot be combined with `--no-localhost`.         |

1. The CLI prints `<console>/cli-login?mode=code&state=…` and a confirmation code on stderr, then asks for the code.
2. Open the URL in any browser. Check that the code matches, then click **Authorize**.
3. The console shows a login code starting `hemlig1.`. Click **Copy**, paste it into the terminal and press Enter. The code is not echoed when stdin is a terminal. `ssh host hemlig login` without `-t` also picks this flow but has no terminal, so the paste would echo; use `ssh -t`.
4. The CLI checks the code, then prints the same stdout JSON as the localhost flow.

The code is bound to this attempt: a code from another `hemlig login` run is refused and nothing is saved. It is a bearer token for full administrator access until it expires. Paste it only into the terminal showing the matching confirmation code, and never share it. The console clears it after 5 minutes or when you click **Hide**.

How the hand-off is protected is in the [threat model](../security/threat-model.md#access-and-identity).

### Supply a token

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

| Setting              | Flag            | Environment variable      | Notes                                                                                                                                                                                          |
| -------------------- | --------------- | ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Administrator origin | `--admin-url`   | `HEMLIG_ADMIN_URL`        | Defaults to the cached login's API; otherwise required. HTTPS only, except HTTP to `localhost`, `127.0.0.1` or `[::1]`. No credentials, path, query or fragment. Redirects are never followed. |
| Environment          | `--environment` | `HEMLIG_ENVIRONMENT`      | The runtime environment. Not the deployment name; see [Configuration](../reference/configuration.md).                                                                                          |
| Token file           | `--token-file`  | `HEMLIG_ADMIN_TOKEN_FILE` | Path to a file holding the raw JWT                                                                                                                                                             |
| Token value          | none            | `HEMLIG_ADMIN_TOKEN`      | Used only when no token file is set                                                                                                                                                            |
| Console origin       | `--console-url` | `HEMLIG_CONSOLE_URL`      | `hemlig login` only. HTTPS origin with a plain hostname.                                                                                                                                       |
| Timeout              | `--timeout-ms`  | none                      | Per request, 1 to 300,000. Default 30,000.                                                                                                                                                     |

Token sources, first match wins: `--token-file`, `HEMLIG_ADMIN_TOKEN_FILE`, `HEMLIG_ADMIN_TOKEN`, then the cached login. There is no `--token` flag, so a token never appears in a process list.

## Commands

Every `secret` command needs `--secret-id`, except an archived read, which needs `--secret-uid`.

| Command                        | Input                        | `--if-match` | Client method                            |
| ------------------------------ | ---------------------------- | ------------ | ---------------------------------------- |
| `secret create`                | JSON `metadata` and `acl`    | No           | `createAdminSecret`                      |
| `secret update`                | JSON `metadata` and/or `acl` | Required     | `updateAdminSecret`                      |
| `secret write-payload`         | Raw payload entry map        | Required     | `putAdminPayload`                        |
| `secret read`                  | None                         | No           | `getAdminSecret`                         |
| `secret read-payload`          | None                         | No           | `getAdminSecretPayload`                  |
| `secret archive`               | None                         | Required     | `archiveAdminSecret`                     |
| `secret read --secret-uid UID` | None                         | No           | `getArchivedAdminSecret`                 |
| `idempotency-key`              | None                         | No           | Prints a new key; needs no configuration |

### Options

| Option              | Applies to                     | Description                                                                                       |
| ------------------- | ------------------------------ | ------------------------------------------------------------------------------------------------- |
| `--secret-id`       | Secret commands                | Active secret ID. Folder separators allowed.                                                      |
| `--secret-uid`      | `secret read`                  | Archived secret UID, from an archive receipt                                                      |
| `--input`           | create, update, write-payload  | A file path, or `-` to read piped stdin. A terminal on `-` is rejected. Limited to 768,000 bytes. |
| `--if-match`        | update, write-payload, archive | A known ETag, or `current` (see below)                                                            |
| `--idempotency-key` | Mutations                      | 8 to 128 printable, non-space ASCII characters. Default: a new UUID.                              |

Input rules:

- The environment and secret ID come from flags, not from the JSON.
- A `metadata` value replaces all metadata, tags included. An `acl` array replaces the whole ACL. Empty values clear the field.
- Unknown top-level fields are rejected. `metadata.path` is not supported.
- A payload file is the bare entry map, with no `payload` wrapper.

Payloads and stdin are never echoed in diagnostics. A payload read prints the value under `data.payload`, so treat stdout as secret.

## Consumers and identities

`hemlig consumer` reads consumers and revokes their client certificates. Only `list` needs an environment.

| Command                    | Options                                                        | Client method       |
| -------------------------- | -------------------------------------------------------------- | ------------------- |
| `consumer list`            | `--environment`, optional `--cursor`                           | `listConsumers`     |
| `consumer get`             | `--consumer-id`                                                | `getConsumer`       |
| `consumer identities`      | `--consumer-id`, optional `--cursor`                           | `listApiIdentities` |
| `consumer revoke-identity` | `--consumer-id`, `--fingerprint`, optional `--idempotency-key` | `revokeApiIdentity` |

`list` and `identities` return one page. Pass `nextCursor` from the receipt as `--cursor` for the next.

`--fingerprint` is the full 64-hex SHA-256 or a unique prefix of at least 12 hex characters. A prefix is resolved against that consumer's identities. No match, or several, exits 2 and nothing is revoked; several matches also list the candidates.

After the workload uses its new certificate, check the identities, then revoke the superseded one by prefix:

```sh
hemlig consumer identities --consumer-id payments-prod |
  jq -r '.data.apiIdentities[] | [.apiFingerprint[0:16], .status, .notAfter] | @tsv'
hemlig consumer revoke-identity --consumer-id payments-prod --fingerprint 41ab9c0d7e12
```

The receipt holds the identity with status `REVOKED`. Revoke only after the replacement is in place; see [Identity and trust](identity-and-trust.md#revocation).

## PKI

`hemlig pki` manages external and Hemlig-held CAs and their CRLs, consumer issuance grants, issued certificates and bulk revocation. It uses the same administrator token, endpoint and receipt format as the other commands. Every command takes `--admin-url`, `--token-file` and `--timeout-ms`. Roles and CA states are in the [PKI guide](pki.md).

| Command                                         | Options                                                                           | Client method                      |
| ----------------------------------------------- | --------------------------------------------------------------------------------- | ---------------------------------- |
| `pki ca list`                                   | `--environment`, optional `--cursor`                                              | `listPkiCas`                       |
| `pki ca get <ca>`                               | `--environment` when `<ca>` is a name                                             | `getPkiCa`                         |
| `pki ca create`                                 | See below                                                                         | `createPkiCa`                      |
| `pki ca activate <ca>`                          | `--certificate`, `--chain`, optional `--root-crl`, `--accept-broader-constraints` | `activatePkiCa`                    |
| `pki ca update <ca>`                            | `--if-match ETAG\|current`, policy flags, `--display-name`                        | `getPkiCa`, `updatePkiCa`          |
| `pki ca retire <ca>`, `pki ca destroy-key <ca>` | optional `--idempotency-key`                                                      | `retirePkiCa`, `destroyPkiCaKey`   |
| `pki ca revoke <ca>`                            | optional `--reason`, `--invalidity-date ISO`                                      | `revokePkiCa`                      |
| `pki ca delete <ca>`                            | `--if-match ETAG\|current`                                                        | `deletePkiCa`                      |
| `pki ca crl publish <ca>`                       | optional `--idempotency-key`                                                      | `publishPkiCrl`                    |
| `pki ca crl get <ca\|ext-id>`                   | `--out FILE`, optional `--format der\|pem`, `--if-none-match`                     | `getAdminCrl`                      |
| `pki external-ca list`, `get <ext-id>`          | optional `--cursor` (list)                                                        | `listExternalCas`, `getExternalCa` |
| `pki external-ca upload-crl`                    | `<ext-id>` or `--for-ca <ca>`, and `--crl FILE`                                   | `uploadExternalCaCrl`              |

`<ca>` is a `ca-<uuid>` ID, used as given, or a CA name. A name needs `--environment` or `HEMLIG_ENVIRONMENT` and is matched exactly against the environment's CAs (up to 10 pages). No match exits 4. `--for-ca` resolves the CA and uses its `parent` external CA.

`pki ca create` options:

- `--environment`, `--name`, `--key-algorithm` (`ECDSA_P256`, `ECDSA_P384`, `RSA_3072`, `RSA_4096`, `ED25519`) and `--subject 'CN=Issuing CA 1,O=Example'`. The subject takes `C`, `ST`, `L`, `O`, `OU` and `CN`; `CN` is required and a key may appear once.
- Repeatable constraint flags: `--permit-dns`, `--exclude-dns`, `--permit-ip`, `--exclude-ip`, `--permit-uri`, `--exclude-uri`, and `--eku serverAuth|clientAuth`.
- Policy flags: `--max-leaf-lifetime 90d`, repeatable `--leaf-key-algorithm`, `--capacity`, `--issuance-per-hour`, `--crl-validity 7d`, and `--display-name`. A duration is an integer of seconds, or an integer with an `s`, `m`, `h` or `d` suffix. The server enforces the ranges.
- `--csr-out FILE` writes the CSR to the file and keeps it out of the receipt. The command exits 9 without creating the CA if the file already exists. Without the flag, the CSR is in `data.csrPem`.
- `--kind EXTERNAL_INTERMEDIATE|ROOT|INTERMEDIATE` (default `EXTERNAL_INTERMEDIATE`). A `ROOT` or `INTERMEDIATE` is `ACTIVE` at once and has no CSR. `--parent <ca>` is required for an `INTERMEDIATE` and refused otherwise. `--validity 365d` sets the certificate validity of a `ROOT` or `INTERMEDIATE`. `--csr-out` is only for the external kind, and a `ROOT` refuses `--max-leaf-lifetime` and `--leaf-key-algorithm`. All of these exit 2 before any request.
- `--rollover-from <ca>` copies the old CA's environment, key algorithm, constraints, policy and CRL validity, and increments the trailing integer of the name and the CN. If either has none, supply `--name` or `--subject`. Explicit flags override the copied values. See the [CA rollover runbook](../operations/pki-ca-rollover.md).

An Ed25519 key writes a `warning:` line to stderr, and the `warnings` array is in the receipt. Creating a `ROOT` also writes the `external_root_recommended` warning to stderr, from the server's warning or, if it is missing, a built-in copy of the same text.

`pki ca revoke` sends `--reason` (`unspecified` by default, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`; not `keyCompromise`). `--invalidity-date` needs `--reason caCompromise`. An `INTERMEDIATE` goes on its root's CRL, and a `ROOT` is distrusted locally with its children. The receipt has `revokedCaIds` and `complete`. `pki ca update` on a `ROOT` refuses the leaf policy flags.

`pki ca update` fetches the CA, overlays the flags on its policy and sends the full policy with the matched version. `--if-match current` uses the version just fetched.

Certificates and chains may be PEM or DER. A file whose text starts with `-----BEGIN` is sent as PEM. A DER file is wrapped as a `CERTIFICATE` PEM. A CRL (`--root-crl`, `--crl`) is sent as PEM, or as base64 DER.

`pki ca crl get` writes the exact CRL bytes to `--out` (PEM uses the `X509 CRL` label) and overwrites an existing file. The receipt has `data.id`, `bytes`, `sha256`, `etag`, `path` and `notModified`; the CRL never goes to stdout. With `--if-none-match` and an unchanged CRL, the file is not written and `notModified` is `true`.

### Issuance grants, certificates and revocation

| Command                                       | Options                                                                                                                                            | Client method                                                          |
| --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| `pki grant list <consumer>`                   | optional `--include-deleted`, `--cursor`                                                                                                           | `listAdminIssuanceGrants`                                              |
| `pki grant list --ca <ca>`                    | optional `--cursor`                                                                                                                                | `listCaIssuanceGrants`                                                 |
| `pki grant get <consumer> <name>`             |                                                                                                                                                    | `getAdminIssuanceGrant`                                                |
| `pki grant create <consumer> <name>`          | `--file FILE`, `--ca <ca>` unless the file has `caId`, optional `--validate-only`                                                                  | `createIssuanceGrant`, `validateIssuanceGrantCreate`                   |
| `pki grant update <consumer> <name>`          | `--file FILE`, `--ca`, `--if-match ETAG\|current`, optional `--validate-only`                                                                      | `updateIssuanceGrant`, `validateIssuanceGrantUpdate`                   |
| `pki grant delete <consumer> <name>`          | `--if-match ETAG\|current`                                                                                                                         | `deleteIssuanceGrant`                                                  |
| `pki grant evaluate <consumer> <name>`        | `--csr FILE`, or `--key-algorithm A` with `--dns`, `--ip`, `--uri`, `--cn`; optional `--duration`, `--usage`                                       | `evaluateIssuanceGrant`                                                |
| `pki grant migrate`                           | `--from <ca>`, `--to <ca>`, optional `--dry-run`                                                                                                   | `listCaIssuanceGrants`, `getAdminIssuanceGrant`, `updateIssuanceGrant` |
| `pki cert list <ca>`                          | optional `--status ISSUED\|REVOKED\|EXPIRED`, `--expiring-before ISO\|duration`, `--cursor`                                                        | `listPkiCertificates`                                                  |
| `pki cert list --consumer <id>`               | optional `--grant NAME`, `--include-expired`, `--cursor`                                                                                           | `listConsumerPkiCertificates`                                          |
| `pki cert get <ca> <serial>`                  | optional `--out FILE`                                                                                                                              | `getPkiCertificate`                                                    |
| `pki cert issue <ca>`                         | `--csr FILE`, and `--use-csr-names` or `--dns`, `--ip`, `--uri`, `--subject`; optional `--duration`, `--usage`, `--out`, `--chain-out`, `--ca-out` | `issuePkiCertificate`                                                  |
| `pki cert revoke <ca> <serial>`               | optional `--reason`, `--invalidity-date ISO`                                                                                                       | `revokePkiCertificate`                                                 |
| `pki consumer revoke-certificates <consumer>` | optional `--grant NAME`, `--reason`                                                                                                                | `revokeConsumerPkiCertificates`                                        |

Consumer IDs and grant names match `[a-z][a-z0-9-]{2,63}`. Mutations take an optional `--idempotency-key`. Reads and `--validate-only` do not.

- **Grant file.** `--file` is JSON of at most 64 KiB: the grant policy fields (`names`, `subject`, `keyAlgorithms`, `keyUsages`, `extendedKeyUsages`, `lifetime`, `forced`, `quotas`) plus optional `caId`, `displayName`, `expiresAt` and `status` (`ACTIVE` or `DISABLED`). A `name` in the file must equal the `<name>` operand. `--ca` accepts a CA ID or name; if the file also has a `caId` that resolves to a different CA, the command exits 2. `grant update` replaces the whole grant, so the file must hold every field to keep.
- **Validation.** `--validate-only` sends `?validateOnly=true`, writes nothing and sends no idempotency key (`grant update` still needs `--if-match`). The receipt holds `valid`, `errors` and `warnings`. It exits 5 when `valid` is `false`.
- **Evaluate.** `grant evaluate` runs the policy engine without issuing. Pass a CSR, or a key algorithm with names, not both. A `--csr` file that holds a private key is refused and never sent.
- **Issue.** `cert issue` is administrator issuance. Names come from the CSR with `--use-csr-names`, or from `--dns`, `--ip`, `--uri` and `--subject 'CN=..,O=..'` (the CN is optional here). `--out`, `--chain-out` and `--ca-out` write the leaf, the chain and the anchor to separate files and keep them out of the receipt. Like `--csr-out`, each file is created before the request and the command exits 9 without sending it if the file exists. Without the flags the PEMs are in `data`. The CLI never handles private keys.
- **Revoke.** `--reason` is one of `unspecified`, `keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation` or `privilegeWithdrawn`. `--invalidity-date` needs `--reason keyCompromise`. `--expiring-before` takes a timestamp or a duration counted from now.
- **Bulk revoke.** `consumer revoke-certificates` revokes every live certificate of the consumer, or of one grant. A run that hits the server deadline answers `complete: false`. The CLI repeats the call with the same idempotency key until `complete` is `true`, at most 20 times, and then exits 7 with `revoke_incomplete`. Repeat the command with the same `--idempotency-key` to continue. The receipt adds `attempts`.
- **Migrate.** `grant migrate` moves every grant of one CA to another, step 5 of the [CA rollover runbook](../operations/pki-ca-rollover.md). It lists the old CA's grants (up to 50 pages), reads each grant, skips deleted grants and grants that are no longer on `--from`, and sends a `PUT` with `If-Match` set to the version it read. Each key is `migrate-` plus a hash of the CAs, consumer, grant name and version, so a rerun replays finished moves. `--dry-run` sends `?validateOnly=true` without a key and changes nothing. CA names resolve in `--environment` as usual. The receipt has `results` with `consumerId`, `name`, `uid` and an `outcome` of `migrated`, `valid`, `invalid`, `skipped` or `failed`, with `errors` and `warnings`, and `remainingListed`, the number of grants still listed under `--from`. It exits 5 if any result is `invalid` or `failed`.

A PKI failure's `error` object also carries `apiCode` and `apiDetails` (for example `{"reason": "ca_not_active"}`), the API's code and machine-readable reason. The message is never copied from the API.

### Offline root (`pki ez`)

`hemlig pki ez` creates and runs the offline root that signs `EXTERNAL_INTERMEDIATE` CAs. It replaces the [manual OpenSSL recipe](../operations/pki-offline-root.md#manual-openssl) with commands that validate the CSR, sign the certificate, keep the root CRL current and activate the CA.

The root key is a software key in an encrypted file, or a key in a [YubiKey PIV slot](#yubikey-root-key). A software root needs no OpenSSL binary and no extra package; a YubiKey root needs `ykman` 5.x.

| Command                       | What it does                                                                  | Network |
| ----------------------------- | ----------------------------------------------------------------------------- | ------- |
| `pki ez generate-ca`          | Creates the root key, the self-signed root, CRL number 1 and the state file    | No      |
| `pki ez import-key`           | Imports the root's backup key into a (another) YubiKey and records the device   | No      |
| `pki ez sign-cert <ca>`       | Fetches the pending CA's CSR, shows it, signs it, syncs the root CRL, activates | Yes     |
| `pki ez sign-cert <ca> --offline` | Signs a CSR file and writes the files to carry to an online machine         | No      |
| `pki ez activate <ca>`        | Uploads the root CRL and activates from the offline files; no state, no key    | Yes     |
| `pki ez revoke-cert`          | Revokes an intermediate: records it, signs a new CRL and uploads it            | Yes     |
| `pki ez renew-crl`            | Signs a new root CRL and uploads it (the recurring step)                       | Yes     |
| `pki ez upload-crl`           | Uploads the current root CRL (a retry, or another deployment)                  | Yes     |
| `pki ez status`               | Shows the local state, deployments and a comparison with the server            | Optional |

Common options:

- `--dir DIR` is the root directory and defaults to the current directory. Relative file flags are relative to it. `--state-file NAME` (default `hemlig-ez.json`) and `--break-stale-lock` also apply.
- Online commands take `--admin-url`, `--token-file` and `--timeout-ms`, and use the cached `hemlig login`. `--environment` (or `HEMLIG_ENVIRONMENT`) is needed to resolve a CA by name and to check the CA's environment.
- `generate-ca` takes `--subject`, `--key-algorithm` (`ECDSA_P384` by default, `ECDSA_P256`, `RSA_3072`, `RSA_4096`), `--validity 20y`, `--intermediate-validity 730d`, `--crl-validity 180d`, `--path-len N`, and `--key-file`, `--cert-file` and `--crl-file` (default `root.key.pem`, `root.pem`, `root.crl.pem`).
- `sign-cert` takes `--validity`, `--crl-validity`, `--renew-before 45d` and `--key FILE`. Offline it also takes `--csr FILE`, `--expect-spki-sha256 HEX`, `--out`, `--chain-out` and `--crl-out`.
- `activate` takes `--certificate FILE`, `--chain FILE` and optional `--crl FILE`.
- `revoke-cert` takes a `<ca>` or `--serial HEX`, a required `--reason` and optional `--invalidity-date`. Offline it takes `--offline --crl-out FILE`.
- `renew-crl` takes `--if-due` (renew only inside the renewal window), `--renew-before`, `--crl-validity` and `--expect-ext-id ext-...`, which refuses a deployment whose external root is another one.

Files in `--dir`: the state file, the encrypted key, `root.pem`, the CRL copy, `crls/` (every CRL ever signed), `issued/` (every certificate ever signed) and a lock file while a command runs. The state file records the CRL numbers, issued serials and revocations, so a second copy of the directory forks the root. Keep one active copy and back the directory up.

#### YubiKey root key

A root key can live in a YubiKey PIV slot. EZ drives the YubiKey with `ykman script --force` and an embedded yubikit script, so `ykman` 5.x must be on the `PATH` (or set `HEMLIG_YKMAN` to its absolute path).

The script is piped to `ykman script -` on its stdin together with the request, so no script file is written. The PIN, the management key and the key to import travel only on that stdin, never in an argument or the environment. After every signature the CLI verifies the result against the root's public key, exactly as it does for a software key.

Two modes, both chosen with `generate-ca --yubikey`:

- **Import (default).** EZ generates the key in software, writes the passphrase-encrypted backup file (`root.key.pem`), then imports the key into the slot. With `--second-yubikey-serial N` it imports into a second YubiKey in the same run. The backup stays the recovery path: `import-key` restores it into a replacement device.
- **On device (`--on-device --accept-no-backup`).** The key is generated inside the YubiKey and can never be exported. There is no key file and no recovery: if the YubiKey is lost, damaged or locked, the root is gone. EZ prints a loud warning, and you must also type `no backup` at the terminal.

YubiKey options for `generate-ca` and `import-key`:

- `--yubikey-serial N` selects the device; it is required when more than one YubiKey is connected. `--second-yubikey-serial N` (generate-ca, import mode) names a second device.
- `--slot 9c` (default). Allowed: `9a`, `9c`, `9d` and `82` to `95`. `9e` and `f9` are refused. The PIN policy is always `always`.
- `--touch-policy always|cached|never` (default `always`). EZ prints `Touch the YubiKey` when a signature is waiting for a touch.
- `--overwrite-slot 9c` replaces a key or certificate that is already in the slot. It must name the same slot as `--slot`, and without it an occupied slot is refused (`slot_occupied`).
- `--no-slot-certificate` skips storing the root certificate in the slot.
- `--protect-management-key` replaces a factory-default management key with a random one kept behind the PIN. It changes the whole device, so EZ asks you to type `protect management key`. A non-default management key is never rotated.
- `--pin-stdin` reads the PIN from the next line of a pipe (after `--passphrase-stdin`). `--allow-last-pin-attempt` permits using a PIN with one attempt left.

Rails that run before any YubiKey is written, with no override except where named:

- Firmware 5.3 or later is required. RSA-3072, RSA-4096 and Ed25519 need 5.7. Below 5.7 a key cannot be deleted, only overwritten, and EZ says so before an overwrite.
- A default PIN is refused (`yubikey_default_pin`). One remaining attempt is refused unless `--allow-last-pin-attempt`. A wrong PIN is never retried.
- A factory management key triggers a warning. A non-default one is read from the terminal (hex) after the YubiKey is checked, and a wrong key stops before any file is written.
- You must type each device's serial number at the terminal before it is written, and `--yes` never skips it.
- Every request names exactly one slot. EZ never touches another slot and never deletes, moves or resets anything.

`sign-cert`, `revoke-cert` and `renew-crl` use the YubiKey transparently. After the typed `confirm`, EZ reads the PIN (showing the attempts left), checks it against the device before reserving a serial or a CRL number, and then signs. `--yubikey-serial` picks the device when several of the root's YubiKeys are connected, and `--key` does not apply.

**Settings form.** On a terminal, `generate-ca` and `sign-cert` show a numbered list of the settings: key algorithm, validities, file names and, for `generate-ca`, the subject. Type a number to edit a row, or press Enter to accept. Flags pre-fill the form. `--yes`, or a stdin that is not a terminal, skips it. The key derivation (PBKDF2-HMAC-SHA256, 1,000,000 iterations) is shown and cannot be edited.

**Passphrase.** The key file passphrase is typed at the terminal with no echo, twice for a new key, and must be at least 12 bytes. `--passphrase-stdin` reads it from the first line of a pipe instead, and is refused when stdin is a terminal. A passphrase is never taken from an argument or an environment variable.

**Typed confirmation.** Before `sign-cert` signs (online or offline) and before `revoke-cert` revokes, the command prints the details to stderr and asks you to type `confirm`. For a signature it shows the CA ID, environment, subject, name constraints, extended key usage, key algorithm and SPKI SHA-256, validity, serial and the root that signs. For a revocation it shows the CA, serial and reason.

Anything else, Ctrl-C or end of input aborts with no change. `--yes` does not skip it. With a piped stdin (for example `--passphrase-stdin`) the word is read from the controlling terminal, and with none the command exits 2 `terminal_required`.

**Online signing.** `sign-cert` checks the CSR before it asks for anything: its signature, the key against the CA record's SPKI, the subject, the name constraints and extended key usages against the record, and an extension list limited to what a Hemlig CA requests. It then finds the root on the server, compares the CRL numbers with the local state, and checks the clock against the server's.

A rerun after a failure reuses the signed certificate and replays the activation with the same idempotency key, so it asks for no confirmation and no passphrase unless the CRL also needs signing.

**Offline signing.** Pass `--expect-spki-sha256` with the value the console shows for the CA. It binds the CSR file to the CA: without it the command warns and the receipt carries `csr_unbound`. The receipt's `next` lists the `pki ez activate` command to run on the online machine with the certificate, the root and the CRL.

**Root CRL.** The CRL is renewed when fewer than 45 days remain (and always after a revocation). `sign-cert` renews it in the same signing step. A root the server has not seen is registered by the first activation, which carries CRL number 1; afterwards the CLI uploads the CRL first and activates without it.

Receipts have one `data` object, and `next` lists follow-up commands. A failure in the middle of a run adds an `ez` object to the error with `completed` (the finished steps), `files` and `rerun`. The state file, not the receipt, is the source of truth.

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

Success prints exactly one JSON object on stdout and nothing on stderr, except `hemlig login`, which prints its URL and confirmation code on stderr (with `--no-localhost` it also prints a prompt on stderr and reads the login code from stdin), `hemlig pki ca create`, which prints a `warning:` line for an Ed25519 key or a `ROOT`.

`hemlig pki ez` also prints its settings form, review and prompts on stderr, and reads passphrases, YubiKey PINs and the typed `confirm` from the terminal. There are no banners or tables, and no other prompts. `--help` also prints JSON.

| Field            | Meaning                                                     |
| ---------------- | ----------------------------------------------------------- |
| `data`           | The API response                                            |
| `etag`           | The raw `controlVersionId`, ready for the next `--if-match` |
| `idempotencyKey` | The key used (mutations only)                               |
| `ifMatch`        | The version matched (guarded writes only)                   |

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

| `outcome`  | Meaning                                                                   |
| ---------- | ------------------------------------------------------------------------- |
| `not_sent` | A preparatory read failed before the mutation was attempted               |
| `rejected` | The API refused it                                                        |
| `unknown`  | The attempt may or may not have applied. Reconcile by reading the secret. |

## Exit codes

| Exit | Meaning                                                                           |
| ---- | --------------------------------------------------------------------------------- |
| 0    | Success                                                                           |
| 2    | Usage, bad local JSON, header or configuration, or API 400                        |
| 3    | API 401 or 403, or a cached login that is expired, unreadable or for another API  |
| 4    | API 404 (secret, active payload, consumer or identity missing)                    |
| 5    | API 409, including a used idempotency key, or an invalid grant check or migration |
| 6    | API 412, stale control revision                                                   |
| 7    | Service failure, unexpected status, malformed response or internal error          |
| 8    | Network, redirect or timeout failure                                              |
| 9    | Local input, token file, stdin or output I/O failure                              |

For `hemlig login --no-localhost`: an invalid or mismatched code exits `2`, a timeout `8`, and Ctrl-C `9`.

`hemlig pki ez` reports its own conditions with these codes, in the same envelope:

| Exit | Codes                                                                                                                                                                                                                                                                                                                         |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2    | `invalid_input`, `subject_invalid`, `csr_invalid`, `csr_unexpected_extension`, `crl_invalid`, `pem_invalid`, `der_invalid`, `certificate_invalid`, `key_file_invalid`, `key_invalid`, `key_storage_unsupported`, `passphrase_mismatch`, `terminal_required`, `confirmation_declined`, `unknown_serial`, `slot_not_allowed`, `yubikey_multiple`, `yubikey_algorithm_unsupported`                        |
| 3    | `passphrase_invalid`, `pin_invalid`, `pin_blocked`, `management_key_invalid`, plus API 401 and 403                                                                                                                                                                                                                                                                                      |
| 5    | `already_exists`, `state_missing`, `state_locked`, `state_conflict`, `state_behind_server`, `state_forked`, `root_mismatch`, `key_mismatch`, `root_profile_invalid`, `root_not_valid`, `validity_too_short`, `csr_key_mismatch`, `csr_subject_mismatch`, `csr_subject_is_root`, `csr_constraints_mismatch`, `issued_conflict`, `revocation_pending`, `revocation_conflict`, `environment_mismatch`, `ca_not_external`, `ca_not_pending`, `ca_activated_elsewhere`, `revocation_not_applied`, `clock_skew`, `clock_regressed`, `slot_occupied`, `slot_empty`, `yubikey_default_pin`, `pin_last_attempt`, `yubikey_not_recorded`, `key_not_exportable`, `management_key_not_default`, plus API 409 |
| 7    | `signature_self_check_failed`, `invalid_response`                                                                                                                                                                                                                                                                              |
| 9    | `state_io_error`, `state_corrupt`, `input_io_error`, `prompt_cancelled`, `tool_missing`, `tool_failed`, `yubikey_not_found`, `yubikey_firmware_unsupported`, `touch_timeout`                                                                                                                                                                                                                                                        |

Exit codes map to API statuses. The API's own code names are in [Errors](../reference/api/errors.md).
