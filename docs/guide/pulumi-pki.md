---
title: Manage PKI with Pulumi
description: Declare certificate authorities and issuance grants in Pulumi, activate a CA in two applies, and roll over without replacing anything.
pageType: how-to
---

# Manage PKI with Pulumi

Declare a [PKI](pki.md) certificate authority and its issuance grants in a Pulumi program, and activate an offline-signed CA in two applies.

`hemlig.CertificateAuthority` and `hemlig.IssuanceGrant` ship in the same package as the [secret resources](pulumi.md). They call the administrator PKI routes with the token in `HEMLIG_ADMIN_TOKEN`, and they hold no private key: a CA key never leaves Hemlig.

**Before you start**

- Role: administrator with the PKI CA role (CAs) and the PKI operator role (grants). Without the optional PKI roles, the administrator role covers both.
- The `prod` [environment](../reference/glossary.md#environment) exists, and an [offline root](../operations/pki-offline-root.md) that can sign a CSR.
- The setup from [Pulumi provider](pulumi.md): the package installed and `HEMLIG_ADMIN_TOKEN` exported.
- A consumer for the grants, for example `payments-prod`. See [Direct consumers](direct-consumers.md) or [Agent grants](agent-grants.md).

## 1. Declare the CA

An external CA is created in two phases. The first apply creates it `PENDING_CERTIFICATE` and outputs a CSR. You sign the CSR offline, put the signed certificate in config, and the second apply activates the CA.

```ts
import * as pulumi from "@pulumi/pulumi";
import { Provider } from "@zyno-io/hemlig-pulumi-provider";

const config = new pulumi.Config();
const hemlig = new Provider("hemlig", { adminUrl: "https://admin.example.com" });

const issuing1 = hemlig.certificateAuthority(
  "prod-issuing-1",
  {
    environment: "prod",
    name: "prod-issuing-1",
    kind: "EXTERNAL_INTERMEDIATE",
    keyAlgorithm: "ECDSA_P256",
    subject: { commonName: "Example Prod Issuing CA 1", organization: "Example Corp" },
    requestedConstraints: { nameConstraints: { permitted: { dns: ["example.com"] } } },
    // Unset on the first apply; set after the root has signed the CSR.
    signedCertificatePem: config.get("issuing1Certificate"),
    chainPem: config.get("issuing1Chain"),
  },
  { protect: true },
);

export const csrPem = issuing1.csrPem;
export const issuing1Status = issuing1.status;
```

`protect: true` makes Pulumi refuse to remove the CA until you unprotect it. Keep it on every CA.

## 2. Create the CA and read the CSR

```sh
pulumi up
pulumi stack output csrPem > issuing1.csr
```

Expected output: `issuing1Status` is `PENDING_CERTIFICATE`, and `issuing1.csr` holds a PEM certificate request.

## 3. Sign it offline

Have the root sign the CSR and issue the root's CRL, as in [Offline root recipe](../operations/pki-offline-root.md#sign-a-hemlig-csr). Then store both certificates in config:

```sh
pulumi config set issuing1Certificate "$(cat issuing1.pem)"
pulumi config set issuing1Chain "$(cat root.pem)"
```

The provider never sends a root CRL. If this root is new to Hemlig, activate its first CA with the CLI or console and `--root-crl` instead. Pulumi then finds the CA `ACTIVE` with the same certificate and changes nothing. Later CAs under the same root activate from Pulumi.

## 4. Activate

```sh
pulumi up
```

Expected output: `issuing1Status` is `ACTIVE`. Activation is write-once: the certificate and chain can never change or be removed afterwards.

## 5. Declare grants after activation

Create grants only once the CA is `ACTIVE`, so they depend on it.

```ts
hemlig.issuanceGrant(
  "payments-web",
  {
    consumerId: "payments-prod",
    name: "web",
    caId: issuing1.caId,
    names: { dns: { allow: ["*.payments.example.com"] }, maxSans: 10 },
    keyUsages: ["digitalSignature", "keyEncipherment"],
    extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
    lifetime: { defaultSeconds: 7776000, maxSeconds: 7776000, minSeconds: 3600 },
    quotas: { perHour: 100, perDay: 1000 },
  },
  { dependsOn: [issuing1] },
);
```

## Verify

```sh
hemlig pki ca get prod-issuing-1
hemlig pki grant get payments-prod web
```

Expected output: the CA is `ACTIVE` with its key `ACTIVE`, and the grant is `ACTIVE`. See the [CLI](cli.md).

## The root CRL stays manual

Pulumi never uploads a root CRL. Refresh it before its `nextUpdate` with the CLI or the [console](console.md#pki):

```sh
hemlig pki external-ca upload-crl --for-ca prod-issuing-1 --crl root.crl.pem
```

## Reference

### CertificateAuthority inputs

| Input | Required | Change rule |
| --- | --- | --- |
| `environment`, `name`, `kind`, `keyAlgorithm`, `subject` | yes | Immutable. A change fails at preview with the rollover message |
| `parentCaId` | `INTERMEDIATE` only | Immutable |
| `validitySeconds` | `ROOT` and `INTERMEDIATE` | Immutable. Used only at create |
| `requestedConstraints` | no | Immutable |
| `policy` | no | In place, while the CA is `PENDING_CERTIFICATE` or `ACTIVE` |
| `displayName` | no | In place when set. Omitting it keeps the stored value |
| `signedCertificatePem`, `chainPem` | no | `EXTERNAL_INTERMEDIATE` only. Write-once activation, set together after the first apply |
| `acceptBroaderConstraints` | no | Sent only with activation. Write-once |

`policy` takes `maxLeafLifetimeSeconds`, `leafKeyAlgorithms`, `capacity`, `issuancePerHour` and `crlValiditySeconds`. An omitted key keeps the stored value, so removing a key is not a change. `leafKeyAlgorithms` is compared as a set. A `ROOT` cannot declare leaf fields. The server's limits apply: `capacity + 2 × issuancePerHour` must not exceed 12,000.

### CertificateAuthority outputs

| Output | Meaning |
| --- | --- |
| `caId` | The resource ID, used as a grant's `caId` |
| `status`, `version`, `keyState`, `subjectDn` | Current state of the CA |
| `csrPem` | The CSR to sign offline (external kind) |
| `certificatePem`, `issuerChainPem` | The activated certificate and its chain |
| `fingerprint`, `serial`, `notBefore`, `notAfter` | Certificate identity and validity |
| `rootCrlExtId`, `rootCrlState` | The root CRL record and its state |
| `warnings` | Warnings recorded at create, such as Ed25519 compatibility |

Every output is public material, so none is a secret.

### IssuanceGrant inputs

The resource ID is `consumerId/name`.

| Input | Required | Change rule |
| --- | --- | --- |
| `consumerId`, `name` | yes | Replace. The replacement is created first and always has a different identity |
| `caId` | yes | In place. A new `caId` migrates the grant |
| `displayName` | no | In place. Omitting it clears it, because an update replaces the whole grant |
| `status` | no | In place. Defaults to `ACTIVE` and is always sent |
| `expiresAt` | no | In place. Compared as an instant |
| `names`, `keyUsages`, `extendedKeyUsages`, `lifetime` | yes | In place. Compared verbatim |
| `subject`, `keyAlgorithms`, `forced`, `quotas` | no | In place. Compared verbatim |

The policy fields are the [grant fields](../reference/api/admin-pki.md#issuance-grants). Outputs: `uid`, `version`, `environment`, `expired`, `policyDigest` and `resolvedQuotas`.

## Delete means retire

Destroying a CA resource retires an `ACTIVE` CA and never destroys its key. Before it retires, the provider lists the CA's grants, re-reads each one and refuses while any live grant still points at the CA. It lists up to 10 and tells you to migrate or delete them. More than 20 listed grants also refuses.

For a CA in any other status (`PENDING_CERTIFICATE`, `RETIRED`, `REVOKED`, `FAILED`), destroy makes no remote call. A pending CA keeps its key, so an accidental removal can be undone with `import`. Abandoning it, revoking it and destroying its key are human actions in the console or CLI. The provider cannot call them.

Use `protect: true` on every CA. `retainOnDelete: true` removes a CA from state without touching Hemlig, which is the safe way to hand a CA to another stack.

Destroying a grant deletes it and leaves a tombstone. It never revokes certificates; use [bulk revoke](pki.md#revoke) for that.

## Recover from interrupted runs

| Error | Cause | Action |
| --- | --- | --- |
| `A CA named X already exists` | An earlier run created the CA, or the name is taken | Add `{ import: "caId" }` to the resource options with the ID in the message. Otherwise choose a new name and DN |
| `ca_subject_in_use` | The DN is claimed forever | Choose a new DN |
| `Grant X exists` | A grant of that name is live | Import it with `{ import: "consumerId/name" }`, or delete it and run again. Declare the policy the way `hemlig pki grant get` prints it |
| `changed outside Pulumi` | A grant was disabled or migrated out of band | Run `pulumi refresh`, then update the program |
| `deleted outside Pulumi` | The grant was deleted elsewhere | Run `pulumi refresh` |
| `not found at` on refresh | `adminUrl` points at another deployment | Fix `adminUrl`. The provider never drops a CA or grant from state on a 404 |

The provider never adopts an existing CA or live grant by itself.

## Idempotency and concurrent edits

Every mutation carries a random idempotency key. A key is reused only to retry a network error or a 5xx within one call, up to three attempts. Keys are never derived from the request, because PKI replay records have no expiry.

Grant updates read the grant, send the change with its `If-Match` version, and on a `412` read again and retry with a new key, up to three times. A drift guard refuses to undo an out-of-band `DISABLED` status or a changed `caId` that your program did not make. The console never retries a `412` automatically; the difference is deliberate, because Pulumi state is declarative.

## Roll over a CA

Never rename or replace a CA resource. Roll over in four runs:

1. Add a second CA resource with a new name and DN, and apply. Sign and activate it as above.
2. Add the new `caId` to your [trust bundles](trust-bundles.md).
3. Change each grant's `caId` to the new CA and apply. This migrates the grants in place.
4. Unprotect and remove the old CA resource. Destroy retires it once no grant references it.

Then follow [Roll over a CA](../operations/pki-ca-rollover.md) to wait for drain and destroy the old key with the CLI.

## Next steps

- [Pulumi provider](pulumi.md)
- [PKI](pki.md)
- [Roll over a CA](../operations/pki-ca-rollover.md)
