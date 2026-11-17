---
title: Concepts
description: Environments, secrets, revisions and UIDs, consumers, agent grants, imports and exports, and MQTT hints.
---

# Concepts

## Environments

A logical namespace for secrets and consumers (for example `staging`, `prod`).
Administrators create them at runtime with `POST /v1/admin/environments`; a fresh
deployment has none. A consumer belongs to exactly one environment and can only
see secrets in it. Environments are not infrastructure: all of them share one
Hemlig deployment.

## Secrets, revisions and UIDs

A **secret** has an external `secretId` (for example `payments/stripe/api-key`;
slashes form folders) and metadata, an ACL and an encrypted payload.

- **Control revision**: metadata, ACL, state and a pointer to a payload revision.
  Its version ID is the HTTP **ETag** used for `If-Match`.
- **Payload revision**: an encrypted envelope only. Changing metadata or the ACL
  creates a new control revision without decrypting the payload.
- **secretUid**: a random immutable ID assigned at creation. DynamoDB records,
  S3 paths and KMS bindings use it. Archiving a secret releases its `secretId`
  for reuse, but the old UID and history stay separate, so a reused name never
  inherits grants.
- **Lifecycle**: `PENDING_VALUE` (created) -> `ACTIVE` (payload written) ->
  `ARCHIVED`. There is no public delete.

Every mutation takes an `Idempotency-Key` and (for updates) an `If-Match` ETag.
See [HTTP API](../reference/api/index.md).

## Consumers and API identities

A **consumer** is a workload identity. Its **API identity** is a TLS client
certificate (a "leaf") issued from one online, self-signed **issuing root** per
deployment. The consumer generates its private key locally and submits a CSR;
Hemlig signs it and stores the public leaf and its SHA-256 fingerprint. On every
request API Gateway validates the chain against a truststore containing the root,
and the Lambda looks up the fingerprint in DynamoDB and requires it to be `ACTIVE`
and in its validity window.

- Leaf lifetime is 365 days. Rotation is additive (overlapping leaves).
- Revocation is a DynamoDB state change and applies on the next request.
- Leaves never carry a consumer ID chosen by the caller: identity comes from the
  fingerprint lookup.

## Agent grants and bootstrap capabilities

Kubernetes clusters and other constrained automation do not hold an administrator
token. Instead an administrator creates an **AgentGrant**: a new consumer ID, an
environment, `read` and/or `write` capabilities, and a list of exact
`secretGrants` (secret ID plus permissions, resolved to immutable UIDs). Then the
administrator issues a one-use **bootstrap capability** (`hmlb_...`, valid
30 minutes, stored only as a SHA-256 digest).

The agent redeems the capability once with a CSR at `POST /v1/bootstrap/redeem`
and receives its mTLS leaf. The grant becomes `ACTIVE`. From then on the identity
is bound to the grant: it cannot fall back to broad consumer access. A folder name
never implicitly authorizes its children.

## Imports and exports

- **Import**: a granted remote secret is materialized as a Kubernetes Secret.
- **Export**: an application-owned Kubernetes Secret is pushed to a Hemlig secret
  through the agent's write scope. Exports cannot change ACLs.

## The Kubernetes controller

The controller (`hemlig.io/v1beta1`) turns four custom resources
(`HemligProvider`, `HemligConsumer`, `HemligSecretImport`, `HemligSecretExport`)
into the bootstrap, import and export behavior above. See
[Kubernetes controller](kubernetes.md) and the [CRD reference](../reference/crds.md).

## MQTT change hints

When a secret changes, Hemlig publishes a payload-free hint to a private AWS IoT
MQTT topic per consumer. Hints only tell the controller to look sooner. The
controller still verifies everything over mTLS, and also resyncs every ten minutes,
so a lost or duplicated hint cannot change authorization or inject data.
The IoT policy lets a consumer connect only as itself and receive only its own
topic; it grants no publish.

## Audit

Mutations and secret-value reads emit `attempted`, `authorized` and
`succeeded`/`failed` events to a separate Object Lock archive. A conditional
`304` read delivers nothing and is not recorded. Events never
contain payloads, tokens or private keys.
