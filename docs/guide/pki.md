---
title: "PKI: certificate authorities and CRLs"
description: "How Hemlig holds an intermediate CA signed by your offline root, grants consumers the right to issue leaf certificates, revokes them and publishes CRLs."
pageType: explanation
---

# PKI: certificate authorities and CRLs

Hemlig can hold an intermediate certificate authority (CA) that your offline root signs, and publishes that CA's certificate revocation lists (CRLs).

Consumers get leaf certificates through issuance grants. [cert-manager](cert-manager.md) can request and renew them unattended. [Trust bundles](trust-bundles.md) deliver CA anchors, intermediates and CRLs to Kubernetes. This page covers the CA lifecycle, grants, issuance, revocation and CRLs.

## The topology

Your organization keeps a root offline. Hemlig generates the intermediate's key, hands you a certificate signing request (CSR), and never sees the root key.

```mermaid
flowchart LR
  root["Offline root (your machine)"]
  csr["CSR: CA:TRUE, pathlen 0"]
  ca["Hemlig CA: prod-issuing-1"]
  crl["Generated CRL"]
  rcrl["Root CRL (uploaded)"]
  ca -->|"admin JWT: create"| csr
  csr -->|"you carry it"| root
  root -->|"signed certificate"| ca
  root -->|"openssl ca -gencrl"| rcrl
  rcrl -->|"admin JWT: upload"| ca
  ca --> crl
```

The CA is an `EXTERNAL_INTERMEDIATE`: its path length is 0, so it can sign leaf certificates but not other CAs. Its key is wrapped by KMS and decrypted only to sign.

## Create, sign and activate

All steps use the [CLI](cli.md). Set the environment once:

```sh
export HEMLIG_ENVIRONMENT=prod
```

1. **Create the CA.** Hemlig returns a CSR. Name constraints and extended key usages in the request limit what the CA may ever certify.

   ```sh
   hemlig pki ca create --name prod-issuing-1 --key-algorithm ECDSA_P256 \
     --subject 'CN=Example Prod Issuing CA 1,O=Example Corp' \
     --permit-dns example.com --csr-out issuing.csr
   ```

2. **Sign it offline** with the root, then issue the root's first CRL. The recipe is in [Offline root recipe](../operations/pki-offline-root.md).
3. **Activate** with the signed certificate, the root certificate and the root CRL:

   ```sh
   hemlig pki ca activate prod-issuing-1 --certificate issuing.pem \
     --chain root.pem --root-crl root.crl.pem
   ```

Activation checks the chain, the CA certificate, its constraints and the root CRL before anything is written. Then it signs the CA's empty CRL number 1. A failed check returns `chain_invalid` or `crl_invalid` with a `details.reason`; see [Admin: PKI](../reference/api/admin-pki.md#errors).

Hemlig CA names and subject DNs are claimed permanently, so a new CA, even after a failed one, needs a new DN.

## CA states

| State                 | Meaning                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------- |
| `PENDING_CERTIFICATE` | Created, waiting for the signed certificate. `DELETE` moves it to `FAILED` and destroys its key   |
| `ACTIVE`              | Activated and able to publish CRLs                                                                |
| `RETIRED`             | Retired by an administrator, or its certificate expired. CRLs keep publishing until it is drained |
| `REVOKED`             | Your root's CRL lists the CA. Its key is disabled and its last CRL stays served                   |
| `FAILED`              | Abandoned while pending                                                                           |

A retired CA is drained once every certificate it could have issued has expired. Hemlig then disables its key. `destroy-key` removes the wrapped key for good, and works only after the key is disabled.

## Grant a consumer

An issuance grant says what one consumer may get from one CA. The consumer is a direct consumer or an agent's consumer. A grant can be created before an agent bootstraps. Everything is denied unless the grant allows it.

Write the policy as JSON. This one lets a consumer request server certificates for one DNS zone:

```json
{
  "names": { "dns": { "allow": ["*.payments.example.com"] }, "maxSans": 10 },
  "keyUsages": ["digitalSignature", "keyEncipherment"],
  "extendedKeyUsages": { "allow": ["serverAuth"], "default": ["serverAuth"] },
  "lifetime": { "defaultSeconds": 7776000, "maxSeconds": 7776000, "minSeconds": 3600 },
  "quotas": { "perHour": 100, "perDay": 1000 }
}
```

```sh
hemlig pki grant create payments-prod web --ca prod-issuing-1 --file grant.json --validate-only
hemlig pki grant create payments-prod web --ca prod-issuing-1 --file grant.json
```

`--validate-only` writes nothing and prints errors and warnings. A rule outside the CA's name constraints is an error, and a partial overlap is a warning. See the [grant fields](../reference/api/admin-pki.md#issuance-grants).

Before you rely on a grant, dry-run a request against it. `evaluate` returns the decision, the engine trace and the planned certificate without issuing anything:

```sh
hemlig pki grant evaluate payments-prod web --dns api.payments.example.com --key-algorithm ECDSA_P256
```

A consumer can hold up to 20 grants. A delete leaves a tombstone, and creating the name again makes a new grant identity, so old certificates never point at a different policy. Disable a grant by updating its `status` to `DISABLED`.

## Issue and renew

The consumer sends a CSR with its mTLS client certificate. Hemlig takes the names from the CSR, checks them against the grant and the CA's constraints, signs, and returns the leaf, the chain and the anchor.

```sh
curl --cert consumer.crt --key consumer.key -H 'content-type: application/json' \
  -H 'idempotency-key: web-renew-0001' --data @request.json \
  https://api.example.com/v1/pki/issuance-grants/web/certificates
```

Use one `Idempotency-Key` per intended certificate. Retrying with it returns the same certificate while it is valid, and never charges the quota twice. A replay of a certificate that was revoked or is about to expire fails instead of redelivering it. Renewal is a new request with a new key and a new CSR, ideally with a new key pair.

Hemlig clamps the lifetime to the grant's maximum, the CA's maximum and the CA certificate's remaining validity. The response says so with `lifetimeClamped`. The details are in [PKI consumer routes](../reference/api/pki.md).

## Admin issuance

An administrator can issue a certificate without a grant, for infrastructure that has no consumer:

```sh
hemlig pki cert issue prod-issuing-1 --csr server.csr --dns api.example.com \
  --duration 24h --out leaf.pem --chain-out chain.pem --ca-out root.pem
```

Use `--use-csr-names` to take the names from the CSR. The CA's constraints, the Hemlig ceilings and the reserved names still apply. Administrators have their own quota of 100 certificates per hour per CA.

## Revoke

Revoke one certificate, or every certificate of a consumer:

```sh
hemlig pki cert revoke prod-issuing-1 4f1c --reason keyCompromise
hemlig pki consumer revoke-certificates payments-prod --reason keyCompromise
```

Revocation is one transaction that marks the certificate, writes its CRL entry and publishes a fresh CRL, usually within seconds. If inline publication fails, the next maintenance pass publishes it within 15 minutes. Expired certificates, and certificates under a revoked CA, are only marked in the inventory because no CRL needs them.

A consumer-wide revoke commits in batches and stops after about 20 seconds. The CLI repeats the call with the same idempotency key until it reports `complete`. Revoking a consumer's leaves does not revoke its client certificate: do that too if the consumer itself is compromised.

List what a CA or consumer holds with `hemlig pki cert list`, and read one certificate with `hemlig pki cert get`.

## Capacity and rate

A CRL must stay deliverable, so Hemlig bounds how many certificates a CA can hold.

| Setting | Default | Meaning |
| --- | --- | --- |
| `capacity` | 8,000 | Issuance is refused (`ca_capacity_exceeded`) once the CA's count reaches this. The count covers certificates of every status that are not yet expired |
| `issuancePerHour` | 2,000 | Certificates per clock hour for the whole CA, across all grants and administrators (`ca_hour`) |

`capacity + 2 x issuancePerHour` stays at or below 12,000, so no CRL exceeds 12,000 entries.

- Maintenance recounts every active CA each pass. An issuance recounts when the stored count is older than 30 minutes.
- The per-CA hourly counter bounds what is issued between counts.
- The CA detail shows `capacity.count` and `capacity.countedAt`. The `pki-capacity-high` alarm fires above 80%.
- Revocation is never refused for capacity.

See [Limits](../reference/limits.md#pki).

Grants also have their own `perHour` and `perDay` quotas, 100 and 1,000 by default. They are per grant only. Deleting and recreating a grant cannot bypass the CA's hourly counter.

## Roles

Two optional identity-provider roles narrow who may change PKI state. Reads need only the normal administrator token.

| Role setting          | Required for                                                              |
| --------------------- | ------------------------------------------------------------------------- |
| `oidcPkiCaAdminRole`  | Create, update, delete, activate, retire, destroy-key and root CRL upload |
| `oidcPkiOperatorRole` | Issuance grants, administrator issuance, revoke, bulk revoke, CRL publish |

When a role is unset, any administrator may perform those operations. See [Configuration](../reference/configuration.md).

## The root CRL

Relying parties check your root's CRL as well as the CA's. Hemlig stores the latest root CRL you upload and revokes any CA that CRL lists, whatever the reason, including `certificateHold`. A hold is permanent in Hemlig: removing it later does not restore the CA.

Refresh the root CRL before its `nextUpdate`:

```sh
openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
hemlig pki external-ca upload-crl --for-ca prod-issuing-1 --crl root.crl.pem
```

An upload must be newer than the stored CRL. An identical retry succeeds without changes. Maintenance alarms 30 days before the stored CRL's `nextUpdate`, and when a CA has had no root CRL for 24 hours. This is the one recurring offline step.

## Generated CRLs

Hemlig signs a full CRL for each CA and stores each one as an immutable object. It refreshes a CRL well before `nextUpdate`: a third of its validity before, within 45 minutes and half of the validity. With the 7-day default that is about 2.3 days. Maintenance runs every 15 minutes, and `hemlig pki ca crl publish` forces a publication. See [Limits](../reference/limits.md#pki).

Download a CRL, for either a CA or a root, with `hemlig pki ca crl get`. A [trust bundle](trust-bundles.md) delivers the generated and root CRLs to your workloads.

## If the intermediate's key is compromised

Revoke the intermediate at the root (`openssl ca -revoke`), regenerate the root CRL and upload it. Hemlig marks the CA `REVOKED` and disables its key. A [trust bundle](trust-bundles.md) picks up the new root CRL on its next refresh, so workloads reject the revoked CA's certificates. Then roll over to a new CA; see [Roll over a CA](../operations/pki-ca-rollover.md).

## Alarms

| Alarm                                             | Fires when                                                              |
| ------------------------------------------------- | ----------------------------------------------------------------------- |
| `pki-generated-crl-stale`                         | An active or undrained CA's CRL is close to its `nextUpdate`            |
| `pki-external-crl-stale`                          | A root CRL with a live dependent is within 30 days of `nextUpdate`      |
| `pki-external-crl-missing`                        | A root with a live dependent has had no CRL for 24 hours                |
| `pki-ca-expiring`                                 | An active CA is within its longest leaf lifetime plus 30 days of expiry |
| `pki-capacity-high`                               | An active CA holds more than 80% of its capacity                        |
| `pki-crl-over-capacity`                           | A CRL carries more entries than the CA's capacity                       |
| `pki-ca-key-unavailable`, `pki-kms-access-denied` | Signing failed because the key or KMS access is unusable                |
| `pki-maintenance-errors`                          | A maintenance pass failed for at least one CA                           |

## Next steps

- [Offline root recipe](../operations/pki-offline-root.md)
- [Roll over a CA](../operations/pki-ca-rollover.md)
- [Admin: PKI](../reference/api/admin-pki.md)
