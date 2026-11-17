---
title: OpenAPI contract
description: Where to find the machine-readable Hemlig OpenAPI 3.1 contract.
---

# OpenAPI contract

The HTTP API is described by an OpenAPI 3.1 document in the repository:

[`openapi/consumer-secrets.yaml`](https://github.com/zyno-io/hemlig/blob/main/openapi/consumer-secrets.yaml)

It is MIT-licensed (see [licensing](https://github.com/zyno-io/hemlig/blob/main/LICENSING.md)) so you may generate clients from it. It defines both servers
(administrator and delivery), the three security schemes (administrator JWT,
consumer mTLS, bootstrap capability), all routes, and the error envelope.

The prose pages under [HTTP API](api/index.md) explain behavior that a schema
cannot express (idempotency, ETags, revocation semantics). When the two disagree,
the OpenAPI file and the handlers are authoritative; please open an issue.

The typed `@zyno-io/hemlig-client` package is the maintained TypeScript client
for these routes; the CLI, controller and Pulumi provider are built on it.
