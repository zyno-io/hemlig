---
title: "Distribute trust bundles"
description: "Write the anchors, intermediates and CRLs of your Hemlig CAs to Kubernetes ConfigMaps with a HemligTrustBundle, mount them, verify a chain and understand revocation latency."
pageType: how-to
---

# Distribute trust bundles

A `HemligTrustBundle` keeps a set of ConfigMaps up to date with the CA certificates and CRLs that your workloads need to verify peers. The controller reads them from Hemlig, so a new intermediate or a revocation reaches your pods with no manual step.

**Role:** platform team. **Before you start:** the [controller](kubernetes.md) with a `Ready` `HemligConsumer`, the PKI CRDs from `crds/hemlig.zyno.io-pki.yaml`, and the IDs of your CAs from `hemlig pki ca list`. The consumer needs no issuance grant, and a PKI-only AgentGrant is enough. cert-manager is not required.

## Create a bundle

```yaml
apiVersion: hemlig.zyno.io/v1alpha1
kind: HemligTrustBundle
metadata:
  name: payments-trust
  namespace: payments
spec:
  consumerRef: payments
  caIds: [ca-0a1b2c3d]
  target:
    name: payments-trust
```

| Field | Description |
| --- | --- |
| `consumerRef` | The `HemligConsumer`. Set `consumerNamespace` to use one in another namespace, as for a [HemligIssuer](cert-manager.md#create-a-hemligissuer) |
| `caIds` | 1 to 50 CA IDs. List the CA you issue from now and, during a rollover, the next one |
| `target.name` | The ConfigMap to write, in the bundle's namespace. At most 165 characters |
| `includeCrl` | Default `true`. Set `false` to write no CRLs |
| `crlFormat` | `der` (default) or `pem` |

`consumerRef`, `consumerNamespace` and `target.name` cannot be changed. Create a new bundle to change them. `caIds`, `includeCrl` and `crlFormat` can change at any time.

## What it writes

The target ConfigMap holds two keys. `ca.crt` has the trusted anchors, deduplicated: your external roots. `chain.crt` has every CA certificate and any intermediate that is not an anchor. Either can be empty.

For each CRL a verifier needs, the bundle writes one more ConfigMap named `<target>-crl-<issuerId>`. It holds the Hemlig CA's own CRL and the CRL of its external root, once per issuer however many CAs share the root.

| ConfigMap | Key | Content |
| --- | --- | --- |
| `payments-trust` | `ca.crt`, `chain.crt` | PEM certificates |
| `payments-trust-crl-ca-0a1b2c3d` | `crl.der` in `binaryData`, or `crl.pem` in `data` | The CRL |
| `payments-trust-crl-ext-<40 hex>` | The same | The root's CRL |

Each ConfigMap has the label `hemlig.zyno.io/managed-by: trust-bundle`, an owner annotation, and an owner reference to the bundle, so deleting the bundle deletes them. CRL ConfigMaps also carry annotations for the issuer, source, SHA-256, number and validity. The full list is in the [CRD reference](../reference/crds.md#hemligtrustbundle-namespaced).

A Hemlig root is an anchor in `ca.crt`, and a Hemlig intermediate adds its own CRL and its root's CRL as two `GENERATED` slots. Listing a root alone gives its anchor and its CRL, with no chain. A locally distrusted root leaves `ca.crt` through every listed CA, and its CRL stops being required once no listed child can still validate.

The controller never overwrites a ConfigMap it does not own. A foreign target gives `ConfigMapConflict` and is left as it is.

## Mount it

Use a projected volume. It puts the target and each CRL under one directory, and kubelet refreshes it in place.

```yaml
volumes:
  - name: trust
    projected:
      sources:
        - configMap: { name: payments-trust }
        - configMap:
            name: payments-trust-crl-ca-0a1b2c3d
            optional: true
            items: [{ key: crl.der, path: crls/issuing.der }]
        - configMap:
            name: payments-trust-crl-ext-0123456789abcdef0123456789abcdef01234567
            optional: true
            items: [{ key: crl.der, path: crls/root.der }]
```

A projection lists each ConfigMap by name. Adding a CA to `spec.caIds` creates its CRL ConfigMap, but running pods mount it only after you add it to the projection and roll the workload out. Check with `kubectl exec <pod> -- ls /trust/crls/`.

Never use `subPath` for these files. Kubelet does not refresh a `subPath` mount, so a revocation would never arrive. Make the CRL sources `optional`, or update the mounts before you remove a CA from the bundle, because removing it deletes its CRL ConfigMap.

## Verify

Convert the CRLs and check a leaf with full-chain CRL checking, as an application would.

```sh
openssl crl -inform DER -in /trust/crls/issuing.der -out issuing.crl.pem
openssl crl -inform DER -in /trust/crls/root.der -out root.crl.pem
openssl verify -CAfile /trust/ca.crt -untrusted /trust/chain.crt -crl_check_all \
  -CRLfile issuing.crl.pem -CRLfile root.crl.pem leaf.pem
```

Expected output: `leaf.pem: OK`. A revoked leaf prints `certificate revoked` at depth 0, and a revoked intermediate at depth 1.

## PEM for Envoy and nginx

Set `crlFormat: pem` and each CRL ConfigMap holds `crl.pem` in `data`, with `-----BEGIN X509 CRL-----` and 64-column lines. Envoy and nginx each read one CRL file, so build a combined file, and rebuild it whenever the projection changes. Concatenating once at startup leaves the daemon on a stale snapshot, and a reload only rereads that stale file.

Kubelet updates a projected volume through an atomic symlink swap of the directory, so watch the directory's content, not one file's modification time. Build the file once before nginx starts, because nginx fails to start when `ssl_crl` names a missing file. Do it in an initContainer or the entrypoint, then run a sidecar that only handles updates:

```sh
# initContainer or entrypoint, before nginx starts
cat /trust/crls/*.pem > /run/crl.pem.tmp && mv /run/crl.pem.tmp /run/crl.pem
```

```sh
# sidecar: compares a checksum, rebuilds atomically and reloads
last="$(cat /trust/crls/*.pem | sha256sum)"
while true; do
  sum=$(cat /trust/crls/*.pem | sha256sum)
  if [ "$sum" != "$last" ]; then
    cat /trust/crls/*.pem > /run/crl.pem.tmp && mv /run/crl.pem.tmp /run/crl.pem \
      && nginx -s reload && last="$sum"
  fi
  sleep 30
done
```

The temporary file and `mv` keep a reader from ever seeing a partial file. The sidecar needs a shared process namespace or equivalent to signal the daemon. Envoy can instead watch the combined file through a filesystem SDS config.

PEM is a third larger than DER, so it fits fewer entries in a 1 MiB ConfigMap, about 9,600 revoked certificates. A CRL that does not fit is `CrlRejected` and the previous copy stays mounted.

## Check the status

```sh
kubectl -n payments get hmltrustbundle
kubectl -n payments get hmltrustbundle payments-trust -o jsonpath='{.status.crls}'
```

`READY` is `True` when the target and every required CRL are written and current. `status.acceptedCaIds` lists the CAs whose material is mounted, and each `status.crls` entry has a `state`: `Current`, `Stale`, `Missing`, `Rejected` or `Conflict`. The reasons and fixes are in [CRDs](../reference/crds.md#hemligtrustbundle-condition-ready).

A revoked CA stays in the bundle with its anchor, so chains issued earlier still fail on the CRL rather than on a missing root. A drained retired CA gives `Ready=True` with reason `CaDrained`, but that reason is set when any accepted CA is drained. Before you remove a CA from `caIds`, check that `hemlig pki ca get <ca>` shows `drained: true` for that CA.

## Roll over a CA

Add the new CA to `caIds` before you move grants to it, and remove the old one only after it is drained. The steps are in [Roll over a CA](../operations/pki-ca-rollover.md).

## How fast a revocation arrives

| Stage | Delay |
| --- | --- |
| Hemlig serves the new CRL on the [CRL route](../reference/api/pki.md#crls) | Seconds after a revoke, or an upload of the root CRL |
| The controller refreshes the bundle | Up to the refresh interval, 5 minutes by default (`trustBundles.refreshIntervalMilliseconds`) |
| Kubelet updates the mounted files | About a minute |

Your application must also reload the file. Refreshes use conditional GETs, so an unchanged CRL costs one `304`.

## Limits

- The controller runs as one replica. It writes only to the bundle's own namespace.
- A bundle lists at most 50 CAs, and a ConfigMap holds at most 1 MiB. A CRL is at most 1,000,000 bytes in DER.
- While the target is rejected, a newly listed CA gets nothing, but the CAs already mounted keep refreshing their CRLs.
- A ConfigMap changed by hand is put back at the next refresh. A deleted CA's CRL ConfigMap is removed.
- The target name is at most 165 characters, so every CRL ConfigMap name stays valid.
- If every listed CA becomes unavailable, the bundle keeps the last mounted content and reports `CaNotFound` or `CaNotActive`.

Constants are in [Limits and timings](../reference/limits.md#controller).

## Next steps

- [CRD reference](../reference/crds.md#hemligtrustbundle-namespaced)
- [PKI consumer routes: bundles and CRLs](../reference/api/pki.md#ca-bundles)
- [Roll over a CA](../operations/pki-ca-rollover.md)
