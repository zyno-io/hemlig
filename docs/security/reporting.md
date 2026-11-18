---
title: Reporting vulnerabilities
description: How to report a suspected security issue in Hemlig privately, and what never to put in a public issue.
pageType: reference
---

# Reporting vulnerabilities

Report a suspected vulnerability privately to the maintainers, with a minimal reproduction and the affected version or commit.

Hemlig is pre-1.0 and has no supported production release yet. The canonical policy is [`SECURITY.md`](https://github.com/zyno-io/hemlig/blob/main/SECURITY.md) at the repository root.

## Do not post publicly

Never put any of these in a public issue, pull request or discussion:

- credentials or bearer tokens;
- certificate private keys;
- secret payloads;
- details that would let someone reach a live deployment.

## What to include

1. The Hemlig version or commit.
2. The smallest steps that reproduce the problem.
3. What you expected and what happened.
4. Which [threat-model](threat-model.md) row you think is affected, if any.

## Testing guidance

Local AWS emulation is not evidence that IAM, API Gateway mTLS or Object Lock Compliance are correct in AWS. Check those in a real account with the [acceptance runbook](../operations/acceptance.md).

## Next steps

- [Threat model](threat-model.md)
- [Architecture](../guide/architecture.md)
