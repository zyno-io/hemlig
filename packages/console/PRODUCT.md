# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

Platform and security administrators of a Hemlig deployment. They use the
console occasionally and carefully, to manage secrets, environments, consumers
and their mTLS certificates, and to read the audit log. Correctness and clarity
matter more than speed (confirmed 2026-11-17).

## Product Purpose

The Hemlig console is the browser interface to the Hemlig administrator API:
a serverless secrets manager in the operator's own AWS account. It lets an administrator create and
update secrets and their payloads, organize them in folders and tags, enroll
consumers and rotate or revoke their certificates, check truststore status, and
browse the immutable audit archive. Success means an administrator can make a
change confidently and see exactly what state a secret or identity is in.

## Operating Context

- An ordinary HTTP client of the public administrator API, nothing more: no
  server, no AWS credentials (see `README.md`).
- Every screen is scoped to one administrator-defined environment, chosen in the
  top bar.
- Sign-in is through the deployment's OIDC provider; local development uses a
  loopback-only dev bridge.
- Writes use optimistic concurrency (`If-Match`) and idempotency keys, so stale
  and conflicting edits surface as explicit states.

## Capabilities and Constraints

- Secrets: browse by folder, filter by tags, search, view and edit metadata and
  ACLs, write payloads, view revisions, archive.
- Consumers: list, enroll (with an optional in-browser CSR generator), rotate
  and revoke API identities, revoke a secret from an agent grant.
- PKI: list CAs and offline roots; create an external, root or intermediate
  CA (with the external-root recommendation); activate a pending external CA;
  download certificates and CRLs; upload a root CRL; retire, abandon and
  destroy the key of a CA; edit issuance grants with validate and a tester for
  the saved grant; revoke a certificate; revoke a consumer's certificates in
  bulk. PKI reads are audited, so these views do not refetch on focus.
- Environments, audit log, truststore status, about.
- Creating agent grants and issuing bootstrap capabilities are not in the
  console.
- Not in the console, by decision: CA policy edit, CA revoke and local
  distrust, admin certificate issuance, and bulk grant migration. Use the CLI
  or Pulumi.
- Behavior and tests in `src/**/*.test.ts` are the contract; visual work must
  not change them.

## Brand Commitments

- Name: Hemlig.
- Visual system: the PixelCI design system, adopted as-is, so Zyno tools look
  like one family (confirmed by Sean, 2026-11-17). See `DESIGN.md`.

## Evidence on Hand

No marketing claims, testimonials or imagery. The console shows only the
administrator's own data.

## Product Principles

1. State is always explicit: every secret, identity and operation shows exactly
   what state it is in, in words.
2. Destructive or irreversible actions are deliberate and confirmed.
3. Machine values (IDs, fingerprints, version IDs) are exact and copyable.
4. Quiet by default; the one committing action per screen is obvious.
