---
title: Reporting vulnerabilities
description: How to report a suspected security issue in Hemlig.
---

# Reporting vulnerabilities

Hemlig is pre-1.0 and has no supported production release yet. The canonical
policy is [`SECURITY.md`](https://github.com/zyno-io/hemlig/blob/main/SECURITY.md) at the repository root.

- **Do not** file public issues containing credentials, certificate private keys,
  bearer tokens, secret payloads, or details that would enable access to a live
  deployment.
- Report suspected vulnerabilities **privately** to the maintainers
  with a minimal reproduction and the affected version or commit.
- Do not treat local AWS emulation as evidence that IAM, API Gateway mTLS, Object
  Lock Compliance, or cross-account policies are correct in AWS. Use the
  [acceptance runbook](/operations/acceptance).

See also the [threat model](threat-model.md) and
[architecture](/guide/architecture) for the intended security properties.
