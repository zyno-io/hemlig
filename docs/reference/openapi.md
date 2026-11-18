---
title: OpenAPI contract
description: Where to find the machine-readable OpenAPI 3.1 contract for the Hemlig HTTP API and how to use it.
pageType: reference
---

# OpenAPI contract

The HTTP API is described by one OpenAPI 3.1 document in the repository: [`openapi/consumer-secrets.yaml`](https://github.com/zyno-io/hemlig/blob/main/openapi/consumer-secrets.yaml).

The file is MIT-licensed (see [licensing](https://github.com/zyno-io/hemlig/blob/main/LICENSING.md)), so you may generate clients from it.

## What it contains

| Part | Content |
| --- | --- |
| Servers | The administrator API and the delivery API |
| Security schemes | Administrator JWT, consumer mTLS, bootstrap token |
| Paths | Every route, one operation per method |
| Schemas | Request and response bodies and the error envelope |

## Where behavior is explained

The [HTTP API](api/index.md) pages explain what a schema cannot: [idempotency](api/index.md#idempotency), ETags, revocation and audit behavior. Each route appears on exactly one page.

When the document and the handlers disagree, the handlers in `src/handlers/` are authoritative. Open an issue.

## Typed client

[`@zyno-io/hemlig-client`](https://github.com/zyno-io/hemlig/tree/main/packages/client) is the maintained TypeScript client. The CLI, the Kubernetes controller and the Pulumi provider are built on it.
