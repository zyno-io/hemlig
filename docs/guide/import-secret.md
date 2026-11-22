---
title: "Import a secret into your namespace"
description: "Copy a granted Hemlig secret into a Kubernetes Secret with one HemligSecretImport."
pageType: how-to
---

# Import a secret into your namespace

Create one `HemligSecretImport` and Hemlig keeps a Kubernetes Secret in your namespace up to date.

**Role:** application team. **Before you start:** your platform team has installed the controller and given your namespace a `HemligConsumer`. Ask them for the consumer name and for the secret ID you need to be granted read access to. Allow about five minutes.

## Create the import

1. Declare the import. Replace the names with the ones your platform team gave you.

   ```yaml
   apiVersion: hemlig.zyno.io/v1beta1
   kind: HemligSecretImport
   metadata:
     name: stripe-api-key
     namespace: payments
   spec:
     consumerRef: payments
     secretId: payments/stripe/api-key
     target:
       name: stripe-api-key
       type: Opaque
   ```

2. Apply it.

   ```sh
   kubectl apply -f import.yaml
   ```

## Verify

```sh
kubectl -n payments wait --for=condition=Ready hmlimport/stripe-api-key --timeout=120s
kubectl -n payments get hmlimport stripe-api-key -o jsonpath='{.status.conditions}'
kubectl -n payments get secret stripe-api-key -o jsonpath='{.data}'
```

Expected output: `condition met`, and one key per payload entry. A secret with entry `api-key` produces a Secret with a key `api-key`.

## Use it in a Pod

```yaml
env:
  - name: STRIPE_API_KEY
    valueFrom:
      secretKeyRef: { name: stripe-api-key, key: api-key }
```

## What to know

- The import owns the target Secret. If a Secret with that name already exists and something else owns it, the import stops with `TargetOwnershipConflict`. Choose another `target.name`.
- Changes in Hemlig arrive through a notification, and the controller also checks every ten minutes. Pods do not restart on their own; mount the Secret as a file or use a reloader.
- If the secret has no value yet, the status is `AwaitingValue`. It completes by itself once a value is set.
- Do not edit the target Secret. The controller overwrites it.

::: warning Deleting the import keeps the Secret
Deleting a `HemligSecretImport` does not delete its target Secret. Delete the Secret yourself if you want it gone. If your platform team removes the secret from your grant, the Secret is deleted.
:::

## Troubleshooting

Find the `REASON` in [Status reasons](../reference/crds.md#status-reasons). `AccessRevoked` means the grant no longer includes the secret; ask your platform team.

## Next steps

- [Export a Kubernetes Secret to Hemlig](export-secret.md)
- [Status reasons](../reference/crds.md#status-reasons)
