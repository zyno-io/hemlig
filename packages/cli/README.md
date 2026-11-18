# Hemlig administrator CLI

`@zyno-io/hemlig-cli` is a small, machine-friendly CLI for the Hemlig
**administrator API**. It installs the `hemlig` executable (Node.js 24), emits
exactly one JSON object per invocation, and never prompts or retries.

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
token (no OAuth in the CLI, no prompts):

```sh
export HEMLIG_CONSOLE_URL=https://console.example.com
hemlig login     # opens a browser; confirm the code shown matches your terminal
hemlig logout
```

`--console-url` overrides `HEMLIG_CONSOLE_URL`; `--no-browser` only prints the URL.
Token sources, in order: `--token-file`, `HEMLIG_ADMIN_TOKEN_FILE`,
`HEMLIG_ADMIN_TOKEN`, then the cached login (bound to its admin API).

Commands: `secret create | update | write-payload | read | read-payload | archive`
`login`, `logout` and `idempotency-key`. `update`, `write-payload` and `archive` take `--if-match <etag>` (or `current`) and an
optional `--idempotency-key`. Run `hemlig --help` for the JSON command reference.

It uses the typed [`@zyno-io/hemlig-client`](https://github.com/zyno-io/hemlig/tree/main/packages/client),
does not provision Hemlig infrastructure, enroll consumers, redeem bootstrap tokens,
or manage Kubernetes resources.

## Documentation

- [CLI guide](https://zyno-io.github.io/hemlig/guide/cli): authentication, JSON
  formats, ETags and idempotency, exit codes.
- [HTTP API reference](https://zyno-io.github.io/hemlig/reference/api/)
- [Hemlig repository](https://github.com/zyno-io/hemlig) (MIT licensed package)
