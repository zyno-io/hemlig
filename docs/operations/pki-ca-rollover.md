---
title: "Roll over a CA"
description: "Replace an intermediate CA before it expires or after its key is compromised, without a gap in trust."
pageType: how-to
---

# Roll over a CA

Replace `prod-issuing-1` with `prod-issuing-2` while the old CA drains.

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

4. Issue a test leaf under the new CA and verify it with full-chain CRL checking against the mounted bundle files (`ca.crt`, `chain.crt` and the CRLs), or against your root and both CRLs.

   ```sh
   hemlig pki cert issue prod-issuing-2 --csr test.csr --use-csr-names --out leaf.pem --chain-out chain.pem
   openssl verify -x509_strict -crl_check_all -CAfile root.pem -untrusted chain.pem \
     -CRLfile issuing2.crl.pem -CRLfile root.crl.pem leaf.pem
   ```

5. Migrate each issuance grant to the new CA, then check that the old CA lists no grants.

   ```sh
   hemlig pki grant migrate --from prod-issuing-1 --to prod-issuing-2 --dry-run
   hemlig pki grant migrate --from prod-issuing-1 --to prod-issuing-2
   hemlig pki grant list --ca prod-issuing-1
   ```

   The migration re-validates each grant against the new CA and exits with code 5 when any grant is invalid or fails. A grant that fails stays on the old CA. A rerun skips grants already moved. Certificates issued before the move stay valid until they expire or you revoke them.

## Retire the old CA

6. Retire the old CA. Hemlig keeps publishing its CRL until it is drained.

   ```sh
   hemlig pki ca retire prod-issuing-1
   ```

Keep the old CA in bundles until the bundle reports `CaDrained`, then remove it from `spec.caIds`. Removing it deletes its CRL ConfigMap, so first update or make optional any mount of it. Once its key is disabled, `hemlig pki ca destroy-key prod-issuing-1` removes the wrapped key.

## Verify

```sh
hemlig pki ca get prod-issuing-1
```

Expected output: `status` is `RETIRED`, and `drained` becomes `true` after the drain point (`drainAt`).

## Hemlig hierarchy

For a Hemlig `INTERMEDIATE`, roll it under the same root with `--rollover-from`. It copies the kind and the parent, so the new intermediate needs no CSR and is `ACTIVE` at once. It shares the root's hourly counters and capacity.

```sh
hemlig pki ca create --rollover-from prod-int-1 --validity 365d
```

Then follow steps 3 to 6 above: add the new `caId` to the bundles, migrate the grants and retire the old intermediate. A bundle that already lists the root needs only the new intermediate.

A new Hemlig root needs a new DN and new intermediates under it. List both hierarchies in the bundles during the cutover, move the grants, then retire the old root. A retired root keeps signing its CRL and drains after its longest intermediate lifetime has passed. An external offline root is still strongly recommended for production.

## Next steps

- [PKI](../guide/pki.md)
- [Admin: PKI](../reference/api/admin-pki.md)
