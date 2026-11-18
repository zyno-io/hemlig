---
layout: home
title: Hemlig
description: A serverless secrets manager you deploy in your own AWS account. No per-secret fees, access granted on the secret instead of an IAM role per workload, and changes pushed to Kubernetes.
hero:
  name: Hemlig
  text: Serverless secrets, without the IAM sprawl
  tagline: A secrets manager that runs in your own AWS account. No per-secret fees, one console for who can read what, and delivery to Kubernetes or any server.
  actions:
    - theme: brand
      text: What is Hemlig
      link: /guide/what-is-hemlig
    - theme: alt
      text: Quickstart
      link: /guide/quickstart
    - theme: alt
      text: First secret in Kubernetes
      link: /guide/first-secret
features:
  - title: Access without a role per workload
    details: Grant a secret to a workload or a whole cluster from the console, CLI or Pulumi. No IAM policies to write, and workloads never hold AWS credentials.
    link: /guide/managing-secrets
    linkText: Manage secrets
  - title: No per-secret fee
    details: Lambda, DynamoDB, S3 and a single KMS key, billed per request. Adding a secret adds no monthly charge.
    link: /guide/what-is-hemlig#compared-with-aws-secrets-manager
    linkText: Compare with Secrets Manager
  - title: Immutable, audited history
    details: Every change is a new revision that cannot be altered or deleted early. Audit events go to a separate locked archive.
    link: /guide/secrets-and-encryption
    linkText: Secrets and encryption
  - title: Pushed, in both directions
    details: Changes reach clusters in seconds through change hints, not a polling interval. Clusters can also export their own Secrets back, under the same grants.
    link: /guide/kubernetes
    linkText: Install the controller
---

## Start by role

| You are a... | Start with | Then |
| --- | --- | --- |
| Platform engineer | [Deploy Hemlig to AWS](guide/deploying.md) | [Install the Kubernetes controller](guide/kubernetes.md) |
| Administrator | [Manage secrets](guide/managing-secrets.md) | [Give a cluster access](guide/agent-grants.md) |
| App team | [Import a secret into your namespace](guide/import-secret.md) | [Troubleshooting](operations/troubleshooting.md) |
| Security reviewer | [Threat model](security/threat-model.md) | [Audit evidence](guide/audit-evidence.md) |

New to the terms? See the [Glossary](reference/glossary.md).
