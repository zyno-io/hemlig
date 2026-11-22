---
title: "Roll over a CA"
description: "Replace an intermediate CA before it expires or after its key is compromised, without a gap in trust."
pageType: how-to
---

# Roll over a CA

Replace `prod-issuing-1` with `prod-issuing-2` while the old CA drains.

**Role:** administrator with the PKI CA role, and the root key holder. **Before you start:** an active `prod-issuing-1` and the [offline root recipe](pki-offline-root.md). Allow about an hour.

Steps 2 to 5 need trust bundles and issuance grants, which arrive in later releases. Today you can complete steps 1 and 6.

## Create the replacement

1. Create a CA with a new DN. A subject DN is claimed forever, so never reuse one. The CLI's `--rollover-from` copies the old CA's settings and increments the trailing number of the name and common name.

   ```sh
   hemlig pki ca create --rollover-from prod-issuing-1 --csr-out issuing2.csr
   ```

2. Have the root sign it, then activate it as in [Offline root recipe](pki-offline-root.md#sign-a-hemlig-csr).

## Move trust and grants

3. Add the new CA to every trust bundle and confirm its CRL is mounted. <Badge type="warning" text="later release" />
4. Issue a test leaf under the new CA and verify it against the bundle with full-chain CRL checking. <Badge type="warning" text="later release" />
5. Migrate each issuance grant to the new CA, then check that the old CA lists no grants. <Badge type="warning" text="later release" />

## Retire the old CA

6. Retire the old CA. Hemlig keeps publishing its CRL until it is drained.

   ```sh
   hemlig pki ca retire prod-issuing-1
   ```

Keep the old CA in bundles until it shows as drained, then remove it. Once its key is disabled, `hemlig pki ca destroy-key prod-issuing-1` removes the wrapped key.

## Verify

```sh
hemlig pki ca get prod-issuing-1
```

Expected output: `status` is `RETIRED`, and `drained` becomes `true` after the drain point (`drainAt`).

## Next steps

- [PKI](../guide/pki.md)
- [Admin: PKI](../reference/api/admin-pki.md)
