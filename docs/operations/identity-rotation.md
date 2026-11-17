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
| Guards       | CSR must be valid RSA ≥ 2048 bits with a key different from the caller's (`400 invalid_csr`); one active successor per identity (`409 identity_already_rotated`); at most 3 `ACTIVE` unexpired leaves per consumer (`409 identity_limit_reached`; revoke old leaves via the admin API) |
| After issuing | The new leaf is registered with AWS IoT so it can connect to its MQTT topic                                   |
| Errors       | Certificate problems return `403 identity_not_active`; no active agent grant returns `403 forbidden`; a replay of a since-revoked leaf returns `409 rotation_replay_inactive` |
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

Rotation failures are reported on the `IdentityRotation` condition and in
`status.identity.lastRotationError`. They never set `Ready=False` while the
current certificate still authenticates. Failed attempts retry with their own
capped exponential backoff (60 s doubling to 6 h, with jitter; reset when the
controller restarts); the 10-minute resync is a safety net. A new
`hemlig.io/rotate-identity` token bypasses the backoff.

| `IdentityRotation` reason | Server response | Staged key | Cause and action |
| --- | --- | --- | --- |
| `RotationUnsupported` | `400 bad_request`, `404`, `405` | kept | The server predates the rotation route (older servers answer it with `400 bad_request`). Deploy the server update; the controller keeps the old certificate |
| `RotationRejected` | `400 invalid_csr`, `409 rotation_replay_inactive`, `409 conflict`, or an issued certificate that does not match the staged key / consumer | discarded | A fresh key and CSR are generated on the next attempt |
| `IdentityLimitReached` | `409 identity_limit_reached` | kept | Three active leaves already exist for the consumer. [Revoke old leaves](#revoke-the-old-leaf) |
| `IdentityAlreadyRotated` | `409 identity_already_rotated` | kept | This certificate already has an active successor (for example someone rotated it out of band). Revoke the unwanted successor, or install the successor's key pair |
| `AuthenticationFailed` | `403 identity_not_active` (or a code-less mTLS `403`) | kept | The current certificate is expired or revoked; rotation cannot self-heal. See [expired certificate](#if-the-certificate-already-expired) |
| `RotationForbidden` | `403 forbidden` | kept | The consumer has no `ACTIVE` agent grant |
| `VerificationFailed` | The new leaf could not authenticate (`GET /v1/agent/config`) or names a different consumer | discarded on `403 identity_not_active` or a consumer mismatch; kept otherwise | The issued leaf is not usable yet or at all. On a discard, a fresh key and CSR are generated next attempt |
| `RotationFailed` | `429`, `5xx`, network, or a Kubernetes write conflict | kept | Transient. The old certificate stays in use and the same CSR is replayed idempotently |

Crashes are safe at every step: the staged key, CSR and (once issued) the new
certificate persist in the identity Secret, and the swap is a single
resourceVersion-guarded write.

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
3. **Upgrade the controller on staging clusters** ([Flux rollout](flux-rollout.md)).
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

### Roll back to the previous leaf

If a new leaf misbehaves after the swap, copy `hemlig.io.previous-tls.crt` /
`hemlig.io.previous-tls.key` back over `tls.crt` / `tls.key` in the identity Secret
(while the previous leaf is still valid and not revoked). Revoke the faulty successor
with the admin API: an identity may only have one active successor, and revoking it
lets the restored leaf rotate again later.

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
   Remove any stale `hemlig.io.next-tls.key`, `hemlig.io.next-csr` and
   `hemlig.io.next-tls.crt` keys left from an interrupted rotation
   (`kubectl edit secret`).
4. The controller picks up the Secret on its next pass. Delete `new.key` from your
   workstation.
5. Force a self-rotation so the controller moves onto a leaf that is registered with
   AWS IoT (see the warning below):
   ```sh
   kubectl -n <ns> annotate hemligconsumer <name> hemlig.io/rotate-identity="$(date +%s)" --overwrite
   ```
6. Optionally revoke the admin-issued leaf once `IdentityRotation=True` shows the new
   fingerprint.

::: warning MQTT hints
The admin issuance route does not register the new certificate with AWS IoT. The
controller still works over mTLS and resyncs every ten minutes, but prompt MQTT
hints will not connect for the manually issued leaf until it is replaced by a
self-rotated one (step 5; the self-rotation route registers its leaves).
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
