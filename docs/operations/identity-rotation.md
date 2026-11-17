---
title: Identity rotation
description: How Kubernetes controller identities renew their mTLS certificates, how to observe and force it, and the ops runbook for expiring or expired certificates.
---

# Identity rotation

Each controller authenticates to the Hemlig delivery API with a 365-day mTLS leaf
stored in the identity Secret named by `HemligConsumer.spec.identity.secretName`.
Without renewal that certificate eventually expires and the cluster stops
syncing.

::: info Availability
Agent identity self-rotation is available from **the first release that includes
agent identity self-rotation**. Both halves must be deployed: the Hemlig service
(a stack that includes the identity-rotation Lambda and the
`POST /v1/agent/identities/rotate` route) **and** a controller release with
rotation support. Earlier releases never read `spec.identity.rotateBefore`; the
[manual procedure](#manual-recovery-and-renewal-on-older-releases) below is the only
option there.
:::

## How it works

1. **Due check.** After a successful sync with the *current* identity, the
   controller compares the certificate's expiry with `rotateBefore`.
2. **Stage.** If due and nothing is pending, it generates a new RSA-3072 key and
   CSR and stores them in the identity Secret as `hemlig.io.next-tls.key` and
   `hemlig.io.next-csr` (resourceVersion-guarded).
3. **Issue.** It calls `POST /v1/agent/identities/rotate` on the delivery API,
   authenticated with the **current** certificate. `Idempotency-Key` is the SHA-256
   of the staged CSR, so a retry after a crash replays the same leaf. The controller
   verifies the returned certificate matches the staged key.
4. **Verify.** It builds a client with the new certificate and key and calls
   `GET /v1/agent/config`; the response must name the same `consumerId` and
   `environment`.
5. **Swap.** Only then does it replace the Secret: `tls.crt`/`tls.key` become the
   new pair, the old pair is kept as `hemlig.io.previous-tls.crt` /
   `hemlig.io.previous-tls.key` (a rollback aid, overwritten at the next rotation),
   `next-*` keys are removed, and the annotations `hemlig.io/api-fingerprint` and
   `hemlig.io/rotated-at` are updated.
6. **Continue.** The same pass proceeds with the new identity (client and MQTT
   connection are re-established).

The old leaf is **not** revoked. It stays `ACTIVE` until its own expiry (an
overlap), or until an administrator revokes it.

### Server side

`POST /v1/agent/identities/rotate` is served by a dedicated Lambda so the ordinary
consumer Lambda never gains the ability to decrypt the issuer root.

| Aspect       | Behavior                                                                                                       |
| ------------ | -------------------------------------------------------------------------------------------------------------- |
| Auth         | mTLS with a currently `ACTIVE`, unexpired identity belonging to an `ACTIVE` agent grant, otherwise `403`        |
| Request      | `Idempotency-Key` header (required); body `{ "apiCertificateSigningRequestPem": "<PEM CSR>" }`                  |
| Response 201 | `{ consumerId, environment, rootFingerprint, apiFingerprint, apiCertificatePem, notBefore, notAfter, status: "ACTIVE" }` |
| Guards       | CSR public key must differ from the caller's key (`400`); at most 3 `ACTIVE` unexpired leaves per consumer after issuance (`409`; revoke old leaves via the admin API) |
| After issuing | The new leaf is registered with AWS IoT so it can connect to its MQTT topic                                   |
| Errors       | Certificate problems return `403` with code `identity_not_active`; grant denials return `forbidden`            |
| Audit        | Operation `agent.identity.rotate`, target consumer ID and new fingerprint                                       |

The same issuing root signs the new leaf, so the API Gateway truststore does not
change.

## `rotateBefore` semantics

`spec.identity.rotateBefore` is a duration matching `^[0-9]+[smhd]$` (for example
`2160h` or `90d`).

| Setting          | Effect                                                                                  |
| ---------------- | --------------------------------------------------------------------------------------- |
| unset            | `720h` (30 days) before expiry                                                          |
| `0s` / `0h`      | Automatic rotation disabled (manual annotation still works)                              |
| any other value  | Rotate when remaining validity is at most this long                                      |

The effective window is `min(rotateBefore, certificateLifetime / 2)`, so an overly
large value cannot cause a rotation loop.

```yaml
spec:
  identity:
    secretName: hemlig-payments-client
    rotateBefore: 2160h   # 90 days
```

## Observing rotation

```sh
kubectl -n payments get hemligconsumer payments -o yaml
```

Relevant status:

| Field                                  | Meaning                                                              |
| -------------------------------------- | -------------------------------------------------------------------- |
| `status.identity.apiFingerprint`       | Fingerprint of the certificate in use                                |
| `status.identity.notBefore` / `notAfter` | Validity of that certificate                                       |
| `status.identity.rotateAfter`          | When automatic rotation becomes due                                  |
| `status.identity.lastRotationTime`     | When the last rotation completed                                     |
| `status.identity.rotationRequest`      | Last honored `hemlig.io/rotate-identity` token                       |
| `status.identity.lastRotationError`    | Most recent failure, cleared on success                              |
| condition `IdentityRotation`           | `True` when healthy, `False` with a reason on failure                |

`IdentityRotation=False` never flips `Ready` while the old certificate still works.
The CRD also exposes the identity expiry as a printer column.

Inspect the certificate itself:

```sh
kubectl -n payments get secret hemlig-payments-client -o jsonpath='{.data.tls\.crt}' \
  | base64 -d | openssl x509 -noout -enddate -fingerprint -sha256
```

## Force a rotation

Annotate the consumer with any token that differs from
`status.identity.rotationRequest`:

```sh
kubectl -n payments annotate hemligconsumer payments \
  hemlig.io/rotate-identity="$(date +%s)" --overwrite
```

One rotation runs on the next pass. Use it to validate the setup in staging, or
after a suspected key compromise (then also revoke the old leaf; see below).
Re-using the same token does nothing.

## Failure modes

| Symptom (`IdentityRotation` reason / error)   | Cause and action                                                                                 |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `RotationUnsupported`                         | The server answered `404`/`405`: it does not have the rotation route yet. Controller keeps the old certificate. Deploy the server update first |
| `400` on the CSR                              | Staged CSR discarded; a fresh one is generated next pass                                         |
| `409` too many active identities              | Three active leaves already exist. Revoke old leaves (below)                                     |
| `403 identity_not_active`                     | The *current* certificate is expired or revoked. Rotation cannot self-heal; see [expired certificate](#if-the-certificate-already-expired) |
| Network / 5xx during issue or verify          | Old certificate stays in use, consumer stays `Ready`; retried with backoff                       |
| Crash between stage and swap                  | Safe: `next-*` keys persist and the same CSR is replayed idempotently                             |

## Ops runbook: renew cluster identities

This is generic; substitute your own clusters and namespaces.

1. **Deploy the server first.** Roll out a Hemlig stack that includes the
   identity-rotation Lambda and route. Controllers on an older server report
   `RotationUnsupported` and keep using their certificate.
2. **Inventory.** On each cluster, list consumers and certificate expiry:
   ```sh
   kubectl get hemligconsumer -A \
     -o custom-columns='NS:.metadata.namespace,NAME:.metadata.name,SECRET:.spec.identity.secretName'
   kubectl -n <ns> get secret <identity-secret> -o jsonpath='{.data.tls\.crt}' \
     | base64 -d | openssl x509 -noout -enddate -fingerprint -sha256
   ```
   Note which expire soonest. Prioritize anything inside 30 days.
3. **Upgrade the controller on staging clusters** ([Flux rollout](/operations/flux-rollout)).
4. **Set `rotateBefore` on staging** (for example `2160h` so rotation happens well
   ahead of expiry) and, to prove the path end to end, force one rotation with the
   annotation above.
5. **Verify.** `IdentityRotation=True`, a new `apiFingerprint`, `Ready=True`, imports
   still current, and the identity Secret has `hemlig.io.previous-tls.*`.
6. **Roll to production** clusters the same way.
7. **Revoke old leaves** once a cluster has run healthy on the new one (below).

### Revoke the old leaf

List a consumer's identities with `GET /v1/admin/consumers/{consumerId}/api-identities`,
then revoke the superseded fingerprint:

```sh
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  https://<adminFqdn>/v1/admin/consumers/<consumerId>/api-identities/<oldFingerprint>
```

Revocation is immediate on the next request. Revoke only after the new leaf is
confirmed working. If you do it too early the controller loses access and you are in
the expired-certificate case.

## If the certificate already expired

A controller whose leaf has expired (or been revoked) cannot rotate itself, and its
bootstrap capability cannot be reused.

What the code allows:

- A new bootstrap capability can only be issued for a grant that is still `PENDING`
  (otherwise `409`). Once the first redemption succeeded the grant is `ACTIVE`, so
  the original `consumerId` **cannot be re-bootstrapped**. Redeeming an already
  consumed capability only returns the same leaf for the *same* CSR.
- An administrator **can** sign a replacement leaf for an existing active consumer
  with `POST /v1/admin/consumers/{consumerId}/api-identities`. It needs only the
  administrator token, not the old certificate.

Manual recovery:

1. Generate a fresh key and CSR (RSA, 2048 bits or larger; the controller uses 3072):
   ```sh
   openssl req -new -newkey rsa:3072 -nodes \
     -keyout new.key -out new.csr -subj "/CN=Hemlig Kubernetes agent"
   ```
2. An administrator issues the leaf (`Idempotency-Key` 8 to 128 characters):
   ```sh
   jq -Rs '{apiCertificateSigningRequestPem: .}' new.csr | curl -sS -X POST \
     -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
     -H "Idempotency-Key: $(uuidgen)" --data-binary @- \
     https://<adminFqdn>/v1/admin/consumers/<consumerId>/api-identities \
     | jq -r .apiCertificatePem > new.crt
   ```
3. Write the pair into the identity Secret (keep the existing owner label and
   annotation; use `kubectl edit` or a patch rather than recreating it):
   ```sh
   kubectl -n <ns> patch secret <identity-secret> --type merge -p \
     "{\"data\":{\"tls.crt\":\"$(base64 < new.crt | tr -d '\n')\",\"tls.key\":\"$(base64 < new.key | tr -d '\n')\"}}"
   ```
4. The controller picks up the Secret on its next pass. Then revoke the expired leaf
   (optional; it is already unusable) and delete `new.key` from your workstation.

::: warning MQTT hints
The admin issuance route does not register the new certificate with AWS IoT. The
controller still works over mTLS and resyncs every ten minutes, but prompt MQTT
hints will not connect for the manually issued leaf until it is replaced by a
self-rotated one (the self-rotation route registers its leaves).
:::

If you cannot or do not want to issue a leaf by hand, the alternative is to start
over with a **new** AgentGrant and consumer ID (consumer IDs are one-to-one with a
grant): create the grant, issue a bootstrap capability, point the `HemligConsumer`
at it with a new `identity.secretName`, then retire the old consumer's identities.
Selected secrets must be re-granted to the new consumer.

## Manual recovery and renewal on older releases

Before self-rotation ships, renew like the manual recovery above, well before
expiry. Use the same steps; with a still-valid leaf you may also revoke the old one
afterwards.
