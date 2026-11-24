---
title: "Roll over a CA"
description: "Replace an intermediate CA before it expires, or as the follow-up to revoking a compromised one, without a gap in trust."
pageType: how-to
---

# Roll over a CA

Replace `prod-issuing-1` with `prod-issuing-2` while the old CA drains.

::: warning Key compromise is not fixed by a rollover
Retiring, draining or destroying a CA's key does not stop a copied key from signing. A relying party that still trusts the root accepts a fresh leaf signed with the stolen key, presented with the old intermediate. If the key may be compromised, first revoke the intermediate at its parent, then roll over:

- Hemlig parent (`INTERMEDIATE` under a Hemlig root): `hemlig pki ca revoke prod-issuing-1 --reason caCompromise`. See [A Hemlig root and intermediates](../guide/pki.md#a-hemlig-root-and-intermediates).
- External offline root: revoke the intermediate in the root's CRL and upload that CRL. See [Revoke an intermediate](pki-offline-root.md#revoke-an-intermediate) and [If the intermediate's key is compromised](../guide/pki.md#if-the-intermediate-s-key-is-compromised).

Then check that a relying party rejects at depth 1: see [Verify the revocation](#verify-the-revocation).

Then move traffic to a healthy CA. Under an external root, do steps 1 to 6 below. Under a Hemlig parent, create the successor as in [Hemlig hierarchy](#hemlig-hierarchy), then do steps 3 to 6. In both cases skip [Retire the old CA](#retire-the-old-ca): retiring needs an ACTIVE CA, and a revoked CA never drains. Keep the revoked CA in every bundle's `spec.caIds`, so its anchor and CRL stay mounted and chains it issued keep failing on the CRL.
:::

**Role:** administrator with the PKI CA role and the PKI operator role (to migrate grants), and the root key holder. **Before you start:** an active `prod-issuing-1` and the [offline root recipe](pki-offline-root.md). Allow about an hour.

## Create the replacement

1. Create a CA with a new DN. A subject DN is claimed forever, so never reuse one. The CLI's `--rollover-from` copies the old CA's settings and increments the trailing number of the name and common name.

   ```sh
   hemlig pki ca create --rollover-from prod-issuing-1 --csr-out issuing2.csr
   ```

2. Have the root sign it, then activate it as in [Offline root recipe](pki-offline-root.md#sign-a-hemlig-csr).

In the console, "Roll over" on the CA pre-fills the same settings. It increments the trailing number of the name and common name, and disables Create while the subject DN equals the old CA's. In Pulumi, add a second `certificateAuthority` resource with a new name and DN: never rename or replace the old one, because the provider refuses immutable changes. See [Manage PKI with Pulumi](../guide/pulumi-pki.md#roll-over-a-ca).

## Move trust and grants

3. Add the new `caId` to every [trust bundle](../guide/trust-bundles.md)'s `spec.caIds`, then wait for `Ready`. Check that `status.crls` lists `<target>-crl-<newCaId>` as `Current`, and read the CRL.

   ```sh
   kubectl get configmap <target>-crl-<newCaId> -o jsonpath='{.binaryData.crl\.der}' | base64 -d | openssl crl -inform DER -noout -text
   ```

4. Add the successor's CRL ConfigMap to every workload's projected volume, roll the workloads out, and check from inside a running pod. A projection lists each ConfigMap explicitly, so adding the CA to `spec.caIds` does not change what pods mount. See [Mount it](../guide/trust-bundles.md#mount-it).

   ```sh
   kubectl exec <pod> -- ls /trust/crls/
   ```

   Expected output: a file for the new CA's CRL (for example `issuing2.der`) next to the old CA's. Do not migrate grants until every workload shows it.

5. Issue a test leaf under the new CA and verify it with full-chain CRL checking against the files mounted in a running pod. Copy them out first, then convert the CRLs. Using separately downloaded CRLs proves nothing about what workloads mount.

   ```sh
   kubectl exec <pod> -- cat /trust/ca.crt > ca.crt
   kubectl exec <pod> -- cat /trust/chain.crt > chain.crt
   kubectl exec <pod> -- cat /trust/crls/issuing2.der > issuing2.der
   kubectl exec <pod> -- cat /trust/crls/root.der > root.der

   openssl crl -inform DER -in issuing2.der -out issuing2.crl.pem
   openssl crl -inform DER -in root.der -out root.crl.pem

   hemlig pki cert issue prod-issuing-2 --csr test.csr --use-csr-names --out leaf.pem
   openssl verify -x509_strict -crl_check_all -CAfile ca.crt -untrusted chain.crt \
     -CRLfile issuing2.crl.pem -CRLfile root.crl.pem leaf.pem
   ```

   Use the file names that `ls /trust/crls/` showed in step 4. Expected output: `leaf.pem: OK`.

6. Migrate each issuance grant to the new CA, then check that the old CA lists no grants.

   ```sh
   hemlig pki grant migrate --from prod-issuing-1 --to prod-issuing-2 --dry-run
   hemlig pki grant migrate --from prod-issuing-1 --to prod-issuing-2
   hemlig pki grant list --ca prod-issuing-1
   ```

   The migration re-validates each grant against the new CA and exits with code 5 when any grant is invalid or fails. A grant that fails stays on the old CA. A rerun skips grants already moved. Certificates issued before the move stay valid until they expire or you revoke them.

## Retire the old CA

7. Retire the old CA. Hemlig keeps publishing its CRL until it is drained.

   ```sh
   hemlig pki ca retire prod-issuing-1
   ```

Keep the old CA in bundles until `hemlig pki ca get prod-issuing-1` shows `drained: true` for that CA (and its key is disabled), then remove it from `spec.caIds`.

Do not gate on the bundle's `CaDrained` reason: the controller sets it when any accepted CA is drained, so an earlier drained generation in the bundle makes it true while `prod-issuing-1` still has valid leaves. The bundle status has no per-CA drained field, so `ca get` is the check.

Removing the CA deletes its CRL ConfigMap, so first update or make optional any mount of it. Once its key is disabled, `hemlig pki ca destroy-key prod-issuing-1` removes the wrapped key.

## Verify

```sh
hemlig pki ca get prod-issuing-1
```

Expected output: `status` is `RETIRED`, and `drained` becomes `true` after the drain point (`drainAt`).

## Verify the revocation

After revoking a compromised intermediate, check from a running pod that a leaf under the old CA now fails at depth 1.

```sh
openssl verify -CAfile /trust/ca.crt -untrusted /trust/chain.crt -crl_check_all \
  -CRLfile issuing.crl.pem -CRLfile root.crl.pem leaf-from-old-ca.pem
```

Expected output: `certificate revoked` at depth 1. Convert the mounted CRLs first, as in [Verify](../guide/trust-bundles.md#verify). The new root CRL reaches pods after the controller refresh and the kubelet update; see [How fast a revocation arrives](../guide/trust-bundles.md#how-fast-a-revocation-arrives).

## Hemlig hierarchy

For a Hemlig `INTERMEDIATE`, roll it under the same root with `--rollover-from`. It copies the kind and the parent, so the new intermediate needs no CSR and is `ACTIVE` at once. It shares the root's hourly counters and capacity.

```sh
hemlig pki ca create --rollover-from prod-int-1 --validity 365d
```

Then follow steps 3 to 7 above: add the new `caId` to the bundles, migrate the grants and retire the old intermediate. A bundle that already lists the root needs only the new intermediate.

A new Hemlig root needs a new DN and new intermediates under it. List both hierarchies in the bundles during the cutover, move the grants, then retire the old root. A retired root keeps signing its CRL and drains after its longest intermediate lifetime has passed. An external offline root is still strongly recommended for production.

## Next steps

- [PKI](../guide/pki.md)
- [Admin: PKI](../reference/api/admin-pki.md)
