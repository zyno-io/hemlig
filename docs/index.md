---
layout: home
title: Hemlig
description: A secrets service you deploy in your own AWS account. Workloads outside AWS fetch secrets over mutual TLS and never hold an AWS credential.
hero:
  name: Hemlig
  text: Secrets for workloads outside AWS
  tagline: Deploy it in your own AWS account. Your clusters and servers fetch secrets over mutual TLS, with no AWS credentials on them.
  actions:
    - theme: brand
      text: How it works
      link: /guide/architecture
    - theme: alt
      text: Quickstart
      link: /guide/quickstart
    - theme: alt
      text: First secret in Kubernetes
      link: /guide/first-secret
features:
  - title: No AWS credentials on consumers
    details: Workloads prove who they are with a client certificate issued by Hemlig. Everything else stays behind API Gateway, Lambda and KMS.
    link: /guide/identity-and-trust
    linkText: Identity and trust
  - title: Immutable, audited revisions
    details: Every change is a new revision that cannot be altered or deleted early. Audit events go to a separate locked archive.
    link: /guide/secrets-and-encryption
    linkText: Secrets and encryption
  - title: Kubernetes native
    details: A controller copies granted secrets into Kubernetes Secrets, and can push application-owned Secrets back, with change hints for fast updates.
    link: /guide/kubernetes
    linkText: Install the controller
  - title: Operable
    details: Overlapping identity rotation, revocation, explicit upgrade paths, and an AWS acceptance runbook for what emulators cannot prove.
    link: /operations/acceptance
    linkText: Validate in AWS
---

## Start by role

| You are a... | Start with | Then |
| --- | --- | --- |
| Platform engineer | [Deploy Hemlig to AWS](guide/deploying.md) | [Install the Kubernetes controller](guide/kubernetes.md) |
| Administrator | [Manage secrets](guide/managing-secrets.md) | [Give a cluster access](guide/agent-grants.md) |
| App team | [Import a secret into your namespace](guide/import-secret.md) | [Troubleshooting](operations/troubleshooting.md) |
| Security reviewer | [Threat model](security/threat-model.md) | [Audit evidence](guide/audit-evidence.md) |

New to the terms? See the [Glossary](reference/glossary.md).
