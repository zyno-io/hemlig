---
title: "Export a Kubernetes Secret to Hemlig"
description: "Push an application-owned Kubernetes Secret into Hemlig through a write grant."
pageType: how-to
---

# Export a Kubernetes Secret to Hemlig

Create one `HemligSecretExport` and the controller writes your Kubernetes Secret into an existing Hemlig secret.

**Role:** application team, with an administrator for the first step. **Before you start:** the controller is installed and your namespace has a ready `HemligConsumer`.

An export never creates the Hemlig secret and never sets who can read it. It only writes the value, and the description and tags you declare.

## Prepare the Hemlig secret

An administrator must do two things first, because the controller cannot:

1. Create the secret, for example `payments/stripe/webhook-source`.
2. Add it to the namespace's [AgentGrant](agent-grants.md#change-the-grant-scope) with the `write` permission.

Without the write grant, the export reports `ReconcileFailed` ("Hemlig returned 403."). `RemoteSecretNotFound` appears only when the control fetch returns `404`.

## Create the export

1. Declare the export.

   ```yaml
   apiVersion: hemlig.io/v1beta1
   kind: HemligSecretExport
   metadata:
     name: webhook-source
     namespace: payments
   spec:
     consumerRef: payments
     secretId: payments/stripe/webhook-source
     source:
       name: webhook-source
     metadata:
       description: Stripe webhook signing secret
       tags:
         owner: payments
   ```

2. Apply it.

   ```sh
   kubectl apply -f export.yaml
   ```

## Verify

```sh
kubectl -n payments wait --for=condition=Ready hmlexport/webhook-source --timeout=120s
kubectl -n payments get hmlexport webhook-source -o jsonpath='{.status}'
```

Expected output: the wait prints `condition met`. The status shows reason `RemoteReady` and the new `payloadVersionId`.

## What to know

- Every key in the source Secret becomes one payload entry, stored as base64.
- The controller updates remote metadata when `spec.metadata` differs, and writes a new payload when the source content changes.
- The source must be a Secret your application owns. A Secret created by an import is rejected with `SourceIsImportManaged`.
- `spec.metadata` is required, but may be `{}`.

## Troubleshooting

Look up the `REASON` in [Status reasons](../reference/crds.md#status-reasons). If the controller itself is unhealthy, see [Troubleshooting](../operations/troubleshooting.md#controller).

## Next steps

- [Import a secret into your namespace](import-secret.md)
- [Give a cluster access](agent-grants.md)
