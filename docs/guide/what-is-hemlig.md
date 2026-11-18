---
title: What is Hemlig
description: Hemlig is a serverless secrets manager you deploy in your own AWS account, and how it compares with AWS Secrets Manager.
pageType: explanation
---

# What is Hemlig

Hemlig is a serverless secrets manager you deploy in your own AWS account. It keeps AWS KMS, S3 and DynamoDB as the system of record, and puts a simpler layer on top: one place to decide who can read which secret, with no per-secret fee and changes pushed to your clusters.

## Why not AWS Secrets Manager

AWS already stores secrets. Using it well still means:

- **A monthly fee per secret.** Splitting credentials finely costs more every month.
- **IAM for every reader.** Each workload needs a role and a policy, and "who can read this secret?" is answered by reading policies.
- **An AWS identity on every workload.** Off AWS that means [IAM Roles Anywhere](https://aws.amazon.com/iam/roles-anywhere/), which needs a certificate authority of your own (or AWS Private CA), trust anchors, profiles and certificate renewal on each host.
- **Polling.** Kubernetes add-ons such as External Secrets Operator refresh on an interval.

Hemlig answers each one:

- **No per-secret fee.** It runs on pay-per-request services with a single KMS key.
- **Access lives on the secret.** Use an [ACL](../reference/glossary.md#acl) for a single workload or an [AgentGrant](../reference/glossary.md#agentgrant) for a cluster, from the console, CLI or Pulumi.
- **Identity is built in.** Hemlig is the certificate authority. A one-time bootstrap token enrolls a cluster, and the controller rotates its own certificate.
- **Changes are pushed.** A [change hint](../reference/glossary.md#change-hint) tells clusters to fetch new values within seconds. Clusters can also export their own Secrets back.

## Compared with AWS Secrets Manager

| | AWS Secrets Manager | Hemlig |
| --- | --- | --- |
| Pricing | Per secret per month, plus API calls | Per request only: Lambda, DynamoDB, S3, one KMS key |
| Who can read a secret | IAM roles and policies per workload | ACL or AgentGrant on the secret, in the console, CLI or Pulumi |
| Workload credential off AWS | IAM Roles Anywhere plus your own CA | A Hemlig client certificate, enrolled with a one-time token |
| Credential renewal | Your PKI renews host certificates | The controller rotates its own certificate |
| Kubernetes | Add-ons such as External Secrets Operator | Built-in controller |
| Getting changes | Clients poll | Pushed change hints, with a resync safety net |
| Cluster to store (export) | External Secrets `PushSecret` | `HemligSecretExport`, under the same grants |
| History | Versions with staging labels | Immutable revisions under S3 Object Lock |
| Audit | CloudTrail | A separate write-once audit archive |

## When AWS Secrets Manager fits better

- **Workloads inside AWS that use native integrations**: ECS task definitions, Lambda, CloudFormation dynamic references or RDS-managed passwords. Hemlig has none of these.
- **Managed credential rotation** for RDS and other supported services. Hemlig stores what you write.
- **Multi-Region replication.** A Hemlig deployment lives in one Region.
- **A handful of secrets.** Hemlig has a small fixed monthly cost of its own, so a few dozen secrets is roughly break-even.
- **No appetite to operate it.** You deploy and upgrade Hemlig yourself, and it is pre-1.0.

## How it works in one picture

```mermaid
flowchart LR
  admin["Administrator<br/>console, CLI, Pulumi, API"]
  workload["Workload or<br/>Kubernetes controller"]
  subgraph aws["Your AWS account (one Hemlig deployment)"]
    adminapi["Administrator API<br/>adminFqdn"]
    deliveryapi["Delivery API<br/>apiFqdn"]
    lambdas["Lambda functions"]
    ddb[("DynamoDB<br/>current state")]
    s3rev[("S3 revisions<br/>Object Lock")]
    kms["KMS<br/>one key"]
    s3audit[("S3 audit archive<br/>Object Lock")]
    iot["AWS IoT Core"]
  end
  admin -->|OIDC access token| adminapi
  workload -->|client certificate, mTLS| deliveryapi
  adminapi --> lambdas
  deliveryapi --> lambdas
  lambdas --> ddb
  lambdas --> s3rev
  lambdas --> kms
  lambdas --> s3audit
  lambdas --> iot
  iot -.->|change hint| workload
```

Everything inside the box is in your AWS account.

The [Administrator API](../reference/glossary.md#administrator-api) and the [Delivery API](../reference/glossary.md#delivery-api) are two separate hosts with two separate credentials. A change hint is a small notification that tells a workload to look for updates sooner. It carries no secret.

## The life of a secret

1. **An administrator creates a secret and writes its value.** Each write is a new immutable revision. It is encrypted with a fresh KMS data key, so no two revisions share a key.
2. **An administrator grants access.** For a single workload, add it to the secret's [ACL](../reference/glossary.md#acl). For a Kubernetes cluster, create an [AgentGrant](../reference/glossary.md#agentgrant). [Concepts](concepts.md#direct-consumer-or-agent) explains the choice.
3. **The workload proves its identity with a [client certificate](../reference/glossary.md#client-certificate)** issued by Hemlig's own certificate authority. Hemlig checks the certificate's [fingerprint](../reference/glossary.md#fingerprint) on every request, so revoking it works at once.
4. **The [Kubernetes controller](../reference/glossary.md#kubernetes-controller) writes the value into a Kubernetes Secret.** A change hint makes updates prompt. A [10-minute resync](../reference/limits.md#controller) is the safety net.

```mermaid
sequenceDiagram
  participant A as Administrator
  participant H as Hemlig
  participant C as Controller in cluster
  participant K as Kubernetes
  A->>H: Create secret, write value, create grant (OIDC token)
  A->>C: Hand over a one-time bootstrap token
  C->>H: Redeem token, receive client certificate (bootstrap token)
  C->>H: Read granted secrets (client certificate, mTLS)
  C->>K: Write Kubernetes Secret
  A->>H: Write a new value (OIDC token)
  H-->>C: Change hint (AWS IoT)
  C->>H: Read the new revision (client certificate, mTLS)
  C->>K: Update Kubernetes Secret
```

Follow this path end to end in [Tutorial: your first secret in Kubernetes](first-secret.md).

## Who does what

| Role | Works with | Credential | Typical tasks |
| --- | --- | --- | --- |
| Platform engineer | CDK, Helm | AWS deploy rights, cluster-admin | Deploy the stack, install the controller |
| Administrator | Console, CLI, Pulumi, API | OIDC access token | Create secrets, grants and bootstrap tokens |
| App team | `HemligSecretImport` and Kubernetes RBAC | Kubernetes RBAC only | Ask for a secret in their namespace |
| Security reviewer | Audit route, threat model | OIDC access token | Review who read what |

## What you get

| You get | In plain words | Read more |
| --- | --- | --- |
| Encryption at rest | Every revision has its own KMS-protected key | [Secrets and encryption](secrets-and-encryption.md) |
| Immutable history | Changes add a revision; none is overwritten | [Secrets and encryption](secrets-and-encryption.md) |
| Access without IAM | Grants live on the secret, not in IAM policies | [Concepts](concepts.md#direct-consumer-or-agent) |
| No AWS credentials on workloads | Workloads hold a Hemlig certificate only | [Identity and trust](identity-and-trust.md) |
| An audit trail | Events go to a separate write-once archive | [Audit evidence](audit-evidence.md) |
| Kubernetes integration | A controller imports and exports Secrets | [Kubernetes controller](kubernetes.md) |
| Your choice of tool | Console, CLI, Pulumi provider or HTTP API | [Manage secrets](managing-secrets.md) |

## What Hemlig does not do

- It does not rotate database or service credentials for you. You write new values; consumers pick them up.
- It has no delete route. Secrets are archived, not deleted.
- It does not manage your identity provider, users or administrator groups.
- It does not rotate the issuing root certificate.
- Its console and CLI cannot create AgentGrants or bootstrap tokens. Use the API or the Pulumi provider.
- Local emulation proves nothing about IAM, API Gateway mTLS or Object Lock. See the [acceptance runbook](../operations/acceptance.md).

::: warning Pre-1.0
Hemlig is pre-1.0. Run the [acceptance gates](../operations/acceptance.md) in an isolated AWS account before you deliver production credentials with it.
:::

## Choose your path

| I want to... | Go to |
| --- | --- |
| Try it on my laptop | [Quickstart](quickstart.md) |
| Evaluate the security model | [Threat model](../security/threat-model.md) |
| Deploy it to AWS | [Deploy Hemlig to AWS](deploying.md) |
| Get a secret into my namespace | [Import a secret](import-secret.md) |
| Automate secret management | [Manage secrets](managing-secrets.md) |
| Understand the vocabulary | [Concepts](concepts.md) and the [glossary](../reference/glossary.md) |
