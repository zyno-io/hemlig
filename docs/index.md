---
layout: home
hero:
  name: Hemlig
  text: Secrets delivery for workloads outside AWS
  tagline: mTLS-authenticated, KMS-encrypted, immutable and audited. No AWS credentials on the consumer.
  actions:
    - theme: brand
      text: What is Hemlig
      link: /guide/what-is-hemlig
    - theme: alt
      text: Quickstart
      link: /guide/quickstart
    - theme: alt
      text: HTTP API
      link: /reference/api/
features:
  - title: No AWS credentials on consumers
    details: Workloads authenticate with a client certificate issued by one online Hemlig root. Everything else stays behind API Gateway, Lambda and KMS.
  - title: Immutable, audited revisions
    details: Every change is a new S3 Object Lock revision. Payloads use per-revision KMS envelope keys. Audit events go to a separate locked archive.
  - title: Kubernetes native
    details: A controller materializes granted secrets into Kubernetes Secrets and can export application-owned Secrets, with MQTT hints for fast convergence.
  - title: Operable
    details: Overlapping identity rotation, revocation, explicit upgrade paths, and an AWS acceptance runbook for what emulators cannot prove.
---
