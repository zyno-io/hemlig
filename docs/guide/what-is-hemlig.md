---
title: What is Hemlig
description: What Hemlig does, who it is for, and what it deliberately does not do.
---

# What is Hemlig

Hemlig delivers secrets to workloads that run **outside AWS** (Kubernetes
clusters, VMs, CI) without giving those workloads an AWS credential. You deploy
it into your own AWS account as an AWS Lambda service. Administrators define
encrypted secrets and say which consumers may read them. Workloads authenticate
with a client certificate (mTLS) and receive only the payloads they are allowed
to read.

## Who it is for

- Platform and security teams running Kubernetes or other infrastructure outside
  AWS that still wants AWS KMS, S3 Object Lock and DynamoDB as the system of
  record for secrets.
- Teams that want immutable revisions, optimistic concurrency and an
  Object-Lock audit trail rather than an ad-hoc secrets file in Git.

## What you get

| Capability            | How                                                                                         |
| --------------------- | ------------------------------------------------------------------------------------------- |
| Encrypted at rest     | A fresh KMS data key per payload revision; AES-256-GCM envelope                              |
| Immutable history     | Every change is a new S3 Object Lock revision; the DynamoDB head is the ETag                |
| No AWS creds on consumers | mTLS leaf from one online Hemlig issuing root; fingerprint checked on every request     |
| Audited               | Application audit events in a separate Object Lock archive                                  |
| Kubernetes native     | A controller imports secrets into Kubernetes Secrets and exports app-owned Secrets          |
| Administered by humans or code | OIDC console, JSON CLI, Pulumi provider, or the HTTP API                          |

## What it does not do

- It is not a general KV store with a public delete route: secrets are archived,
  not deleted.
- It does not manage your OIDC identity provider, users or administrator groups.
- Issuer-root rotation is deliberately out of scope.
- Local emulation (MiniStack) is not evidence that IAM, API Gateway mTLS or
  Object Lock behave correctly in AWS. Run the
  [AWS acceptance runbook](/operations/acceptance) before production use.

::: warning Pre-1.0
Hemlig is pre-1.0. Do not deliver production credentials with it without an
isolated AWS acceptance test of your OIDC and mTLS configuration.
:::

## Where to go next

- [Concepts](concepts.md): the vocabulary used everywhere else.
- [Architecture](architecture.md): the security model in depth.
- [Quickstart](quickstart.md): run it locally.
- [Deploying with CDK](deploying.md): run it in AWS.
- [Kubernetes controller](kubernetes.md): the main client.
