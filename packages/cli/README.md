# Hemlig administrator CLI

`@zyno-io/hemlig-cli` is a small, machine-friendly CLI for the Hemlig
**administrator API**. It installs the `hemlig` executable (Node.js 24 or later), emits
exactly one JSON object per invocation, and never retries. It prompts only for the login code in `hemlig login --no-localhost`.

```sh
npm install --global @zyno-io/hemlig-cli
export HEMLIG_ADMIN_URL=https://admin.example.com
export HEMLIG_ENVIRONMENT=production
export HEMLIG_ADMIN_TOKEN_FILE=/run/secrets/hemlig-admin-oidc-token   # raw OIDC JWT

printf '%s\n' '{"metadata":{"description":"Payments API"},"acl":[]}' |
  hemlig secret create --secret-id payments/stripe/api-key --input -
hemlig secret read --secret-id payments/stripe/api-key
```

Interactive sign-in reuses your web console SSO session and caches a short-lived
token (no OAuth in the CLI):

```sh
export HEMLIG_CONSOLE_URL=https://console.example.com
hemlig login     # opens a browser; confirm the code shown matches your terminal
hemlig login --no-localhost   # default over SSH: copy the login code from the console and paste it here
hemlig logout
```

`--console-url` overrides `HEMLIG_CONSOLE_URL`; `--no-browser` only prints the URL.
Token sources, in order: `--token-file`, `HEMLIG_ADMIN_TOKEN_FILE`,
`HEMLIG_ADMIN_TOKEN`, then the cached login (bound to its admin API).

Commands: `secret create | update | write-payload | read | read-payload | archive`,
`consumer list | get | identities | revoke-identity`, `login`, `logout` and
`idempotency-key`. `update`, `write-payload` and `archive` take `--if-match <etag>`
(or `current`) and an optional `--idempotency-key`. `consumer revoke-identity` takes
`--idempotency-key` only, not `--if-match`. Run `hemlig --help` for the JSON command reference.

It uses the typed [`@zyno-io/hemlig-client`](https://github.com/zyno-io/hemlig/tree/main/packages/client),
does not provision Hemlig infrastructure, enroll consumers, redeem bootstrap tokens,
or manage Kubernetes resources.

Consumers and identities (`consumer list` needs `--environment`; the others take
`--consumer-id`):

```sh
hemlig consumer identities --consumer-id payments-prod
hemlig consumer revoke-identity --consumer-id payments-prod --fingerprint 41ab9c0d7e12
```

`--fingerprint` is the full 64-hex SHA-256 or a unique prefix of at least 12 hex
characters; an unknown or ambiguous prefix exits 2 without revoking anything.

Offline root (`hemlig pki ez`): `generate-ca`, `adopt-ca` (bring an existing OpenSSL or YubiKey root under EZ), `import-key`, `sign-cert`, `activate`,
`revoke-cert`, `renew-crl`, `upload-crl` and `status` create and run the offline root that signs
`EXTERNAL_INTERMEDIATE` CAs, with a software key in an encrypted file or a key in a YubiKey PIV slot (`--yubikey`,
needs `ykman` 5.5 or later). On a terminal,
`generate-ca` and `sign-cert` show a settings form, and signing or revoking always
asks you to type `confirm` (`--yes` does not skip it). Run `hemlig pki ez --help`.

## Documentation

- [CLI guide](https://zyno-io.github.io/hemlig/guide/cli): authentication, JSON
  formats, ETags and idempotency, exit codes.
- [HTTP API reference](https://zyno-io.github.io/hemlig/reference/api/)
- [Hemlig repository](https://github.com/zyno-io/hemlig) (MIT licensed package)
