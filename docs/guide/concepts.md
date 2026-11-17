---
title: Concepts
description: "The Hemlig access model in one page: environments, secrets and revisions, direct consumers versus agents, ACLs versus AgentGrants, imports and exports."
pageType: explanation
---

# Concepts

Hemlig stores secrets in environments and lets two kinds of workload read them: direct consumers through a per-secret ACL, and agents through an AgentGrant.

Terms are defined once in the [glossary](../reference/glossary.md). This page shows how they fit together.

## Environments

An [environment](../reference/glossary.md#environment) is a runtime namespace for secrets and consumers, such as `prod`. An administrator creates it with `POST /v1/admin/environments`. A fresh deployment has none.

A consumer belongs to exactly one environment and sees only its secrets. All environments share one Hemlig deployment.

::: tip Environment or deployment name?
The [deployment name](../reference/glossary.md#deployment-name) (CDK `environmentName`) names the AWS resources. It is not an environment. The CLI reads `HEMLIG_ENVIRONMENT` as the runtime environment; the Lambdas read the same variable name as the deployment name.
:::

## Secrets, revisions and UIDs

A [secret](../reference/glossary.md#secret) has a [secret ID](../reference/glossary.md#secret-id) such as `payments/stripe/api-key`, metadata, an ACL and an encrypted [payload](../reference/glossary.md#payload). The slashes make [folders](../reference/glossary.md#folder), which are for browsing only.

Two kinds of revision make up a secret:

| Revision | Holds | Changes when |
| --- | --- | --- |
| [Control revision](../reference/glossary.md#control-revision) | Metadata, ACL, [state](../reference/glossary.md#secret-state) and a pointer to a payload revision | You change metadata, the ACL or the payload |
| [Payload revision](../reference/glossary.md#payload-revision) | The encrypted payload and nothing else | You write a new value |

The control revision's version ID is the [ETag](../reference/glossary.md#etag). Updates send it in `If-Match`, and every change also needs an [idempotency key](../reference/glossary.md#idempotency-key).

The [secret UID](../reference/glossary.md#secret-uid) is a random ID fixed at creation. Storage, encryption and grants bind to the UID. Archiving a secret frees its ID for reuse, but a new secret with that ID starts with no access.

A secret moves from `PENDING_VALUE` to `ACTIVE` when its first value is written, and to `ARCHIVED` when archived. There is no delete. See [Secrets and encryption](secrets-and-encryption.md).

## Direct consumer or agent?

A [consumer](../reference/glossary.md#consumer) is a workload identity. It proves who it is with a [client certificate](../reference/glossary.md#client-certificate) issued by Hemlig. How it gets that certificate, and what it may read, decides which kind it is.

| | [Direct consumer](../reference/glossary.md#direct-consumer) | [Agent](../reference/glossary.md#agent) |
| --- | --- | --- |
| Typical workload | A VM, CI job or service you configure yourself | The Kubernetes controller |
| Who holds an OIDC token | An administrator enrolls it on the workload's behalf | Nobody on the workload; an administrator issues a [bootstrap token](../reference/glossary.md#bootstrap-token) |
| How it enrolls | Administrator submits its [CSR](../reference/glossary.md#csr) to `POST /v1/admin/consumers` | Agent redeems the bootstrap token with its own CSR |
| What grants access | Entries in each secret's [ACL](../reference/glossary.md#acl) | Its [AgentGrant](../reference/glossary.md#agentgrant) |
| Can write secrets | No, read only | Yes, if the grant has the `write` capability |
| Access can be changed by | Editing a secret's ACL | Updating the grant |
| How-to | [Connect a workload without Kubernetes](direct-consumers.md) | [Give a cluster access](agent-grants.md) |

Choose an agent for a Kubernetes cluster. Choose a direct consumer for anything else that holds a client certificate.

## ACL versus AgentGrant

The two access lists never mix:

- An ACL entry names a direct consumer and grants `read`. A secret holds at most 40 entries.
- An AgentGrant names an agent and lists the exact secrets it may use, with `read` or `write` for each. A grant holds up to 1,000 secrets.
- **An administrator cannot add an agent to a secret's ACL.** The API rejects it: "Agent consumer access is managed by its AgentGrant, not the secret ACL." Hemlig derives the agent's ACL row from the grant itself.
- A folder never grants access. A grant names exact secrets, so adding a secret under `payments/` gives the agent nothing until you list it.

An agent also cannot fall back to the ordinary delivery routes. Its AgentGrant is its only boundary, so a compromised namespace cannot guess its way to another secret. Numbers are in [Limits and timings](../reference/limits.md#secrets-and-grants).

## How an agent gets its identity

1. An administrator creates an AgentGrant for an unused consumer ID. It starts as `PENDING`.
2. The administrator issues one [bootstrap token](../reference/glossary.md#bootstrap-token) (`hmlb_...`). It is shown once and valid for 30 minutes.
3. The agent generates its own private key, redeems the token once with a CSR and receives its client certificate. The grant becomes `ACTIVE`.

From then on the agent renews its certificate by [identity rotation](../operations/identity-rotation.md). An `ACTIVE` grant cannot be bootstrapped again. Mechanics are in [Identity and trust](identity-and-trust.md).

## Imports and exports

In Kubernetes, the controller turns grants into Secrets and back.

- An **import** copies one granted secret into a Kubernetes Secret. Each payload entry becomes a key of that Secret.
- An **export** pushes an application-owned Kubernetes Secret to an existing Hemlig secret. It needs a `write` grant and cannot change ACLs.

Four custom resources drive this: [`HemligProvider`](../reference/glossary.md#hemligprovider), [`HemligConsumer`](../reference/glossary.md#hemligconsumer), [`HemligSecretImport`](../reference/glossary.md#hemligsecretimport) and [`HemligSecretExport`](../reference/glossary.md#hemligsecretexport). See the [Kubernetes controller](kubernetes.md) and the [CRD reference](../reference/crds.md).

## Staying up to date

Hemlig sends a [change hint](../reference/glossary.md#change-hint) over AWS IoT when a secret changes. The hint carries no data. It only tells the controller to sync now.

The controller still verifies everything over mTLS and resyncs every 10 minutes, so a lost or forged hint cannot change access or inject data. Details are in [Sync and change hints](sync-and-notifications.md).

## Audit

Administrator requests and consumer reads write [audit events](../reference/glossary.md#audit-event) to a separate write-once archive. Events never contain payloads, tokens or private keys. [Audit evidence](audit-evidence.md) lists exactly what is and is not recorded.
