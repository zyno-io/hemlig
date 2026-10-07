# Hemlig administrator CLI

See the [administrator CLI guide](https://github.com/zyno-io/hemlig/blob/main/docs/cli.md) in the Hemlig repository
for commands, JSON formats, authentication, concurrency and exit codes.

Requires Node.js 24. The executable is `hemlig`; run `hemlig --help` for its
JSON command reference. This package uses the typed `@hemlig/client` and never
enrolls Kubernetes resources or redeems cluster bootstrap tokens.
