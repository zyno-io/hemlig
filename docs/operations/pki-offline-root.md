---
title: "Offline root (EZ and OpenSSL)"
description: "Create an offline root, sign a Hemlig CSR, keep the root CRL current and revoke an intermediate, with hemlig pki ez or with OpenSSL."
pageType: how-to
---

# Offline root (EZ and OpenSSL)

Create an offline root, sign Hemlig's intermediate CSR, and keep the root CRL current. Use `hemlig pki ez` for the short path, or the OpenSSL recipe below if you prefer your own tooling.

**Role:** the person who holds the root key. **Before you start:** the [CLI](../guide/cli.md) logged in on an online machine, and two backup media. EZ runs on the machine that holds the key; nothing else needs to be installed. The OpenSSL recipe needs OpenSSL 3. Allow about 20 minutes.

The root must sign the Hemlig CSR directly. Its subject must use printable ASCII, and a new root key needs a new root DN. For the design, see [PKI](../guide/pki.md).

## EZ: `hemlig pki ez`

EZ keeps the root key in an encrypted file, signs with `node:crypto`, and records every CRL number, serial and revocation in a state file, so a crash or a rerun never signs the same thing twice or loses a revocation. The full command reference is in the [CLI guide](../guide/cli.md#offline-root-pki-ez).

### Create the root

Run this on the machine that will hold the key, in an empty directory (the current directory is used unless you pass `--dir`).

```sh
hemlig pki ez generate-ca --subject 'CN=Example Offline Root CA 1,O=Example Corp'
```

On a terminal it shows the settings: key algorithm (`ECDSA_P384` by default), root validity (20 years), the default intermediate validity (730 days), the CRL validity (180 days) and the file names. Press Enter to accept, or type a number to change a row. It then asks for a passphrase of at least 12 characters, twice. Flags pre-fill the form, and `--yes` skips it.

The directory now holds `root.key.pem` (the encrypted key), `root.pem`, `root.crl.pem` and `hemlig-ez.json` (the state). Copy the whole directory to two backup media after every operation, and store the passphrase apart from the media. Two active copies of the directory fork the root's CRL numbers; keep one.

### Sign a CA

On the root machine, with the CA created in Hemlig and `hemlig login` done:

```sh
hemlig pki ez sign-cert prod-issuing-1 --environment prod
```

The command fetches the pending CA's CSR and checks it against the CA record. It prints the CA, the subject, the name constraints, the key and its SPKI SHA-256, the validity and the root that will sign, then asks you to type `confirm`. After the passphrase it signs the certificate, renews the root CRL if it is due, uploads the CRL if needed and activates the CA. If anything fails, run the same command again: it reuses the certificate it already signed.

For an air-gapped root, copy the CA's CSR from the console to the root machine and pin its key with the SPKI SHA-256 the console shows.

```sh
hemlig pki ez sign-cert ca-<uuid> --offline --csr issuing.csr.pem \
  --expect-spki-sha256 <hex> --out issuing.pem
```

The receipt lists the certificate, the root and the CRL to carry. On an online machine, activate with them:

```sh
hemlig pki ez activate ca-<uuid> --environment prod --certificate issuing.pem \
  --chain root.pem --crl root.crl.pem
```

### Keep the root CRL current

The root CRL must be uploaded before its `nextUpdate`. Run this on a schedule, at least every few months:

```sh
hemlig pki ez renew-crl --if-due
```

`--if-due` signs a new CRL only when fewer than 45 days remain, and always uploads the current one if the server has an older copy. Offline, use `renew-crl --offline --crl-out root.crl.pem` and upload the file with `hemlig pki external-ca upload-crl`. `sign-cert` also renews a due CRL.

### Revoke an intermediate with EZ

```sh
hemlig pki ez revoke-cert prod-issuing-1 --environment prod --reason caCompromise
```

The command shows the CA and the serial, asks you to type `confirm`, signs a new CRL that lists the serial, uploads it and checks that the CA is revoked. Revocation is permanent. Add `--offline --crl-out root.crl.pem` to carry the CRL to an online machine.

### Check the state

`hemlig pki ez status` shows the root, the current CRL and how many days remain, every issued certificate, the revocations and the deployments that are behind the current CRL.

### The key file and the OpenSSL recipe

`root.key.pem` is a standard `ENCRYPTED PRIVATE KEY` PEM (PBES2, PBKDF2-HMAC-SHA256 with 1,000,000 iterations, AES-256-CBC). `openssl pkey -in root.key.pem` reads it, so the [manual recipe](#manual-openssl) still works with an EZ root as a fallback. The recipe's own `openssl genpkey -aes256` uses only 2,048 iterations, which is weaker against a stolen file.

## Manual (OpenSSL)

The same operations with the `openssl` binary. Use it if you cannot run the CLI on the root machine.

### Create the root configuration

Save this as `root-ca.cnf` in an empty directory:

```ini
[ ca ]
default_ca = root_ca

[ root_ca ]
dir              = .
database         = $dir/index.txt
new_certs_dir    = $dir/certs
serial           = $dir/serial
crlnumber        = $dir/crlnumber
certificate      = $dir/root.pem
private_key      = $dir/private/root.key
default_md       = sha384
default_days     = 730
default_crl_days = 180
policy           = policy_hemlig
preserve         = yes
unique_subject   = no
copy_extensions  = copyall
x509_extensions  = intermediate_ext
crl_extensions   = crl_ext

[ policy_hemlig ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied

[ intermediate_ext ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always

[ crl_ext ]
authorityKeyIdentifier = keyid:always

[ req ]
prompt             = no
default_md         = sha384
string_mask        = utf8only
distinguished_name = root_dn
x509_extensions    = root_ext

[ root_dn ]
O  = Example Corp
CN = Example Offline Root CA 1

[ root_ext ]
basicConstraints     = critical, CA:true
keyUsage             = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
```

`default_days` is the intermediate validity; keep it short. `default_crl_days` is the root CRL validity, which you must refresh before it lapses. `copy_extensions = copyall` takes Hemlig's requested CA extensions, so review the CSR first.

### Create the root once

1. Create the key and the self-signed root.

   ```sh
   mkdir -p offline-root/certs offline-root/private && cd offline-root && chmod 700 private
   touch index.txt && echo 01 > crlnumber && openssl rand -hex 16 > serial
   openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 \
     -pkeyopt ec_param_enc:named_curve -aes256 -out private/root.key
   openssl req -config root-ca.cnf -new -x509 -key private/root.key -days 7300 -out root.pem
   openssl x509 -in root.pem -noout -fingerprint -sha256
   ```

2. Record the fingerprint. Copy the whole directory (encrypted key, `root.pem`, `index.txt`, `serial`, `crlnumber`, `root-ca.cnf`) to two offline media after every operation. Store the passphrase separately.

### Sign a Hemlig CSR

1. Review the CSR. Check the subject, `CA:TRUE, pathlen:0`, and the name constraints.

   ```sh
   openssl req -in issuing.csr -noout -text -verify
   ```

2. Sign it and issue the root's CRL.

   ```sh
   openssl ca -config root-ca.cnf -batch -in issuing.csr -out issuing.pem -notext
   openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
   ```

3. Activate the CA with `issuing.pem`, `root.pem` and `root.crl.pem`, as in [PKI](../guide/pki.md#create-sign-and-activate).

### Upload a fresh root CRL

Issue a new CRL and upload it before the old one's `nextUpdate`.

```sh
openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
hemlig pki external-ca upload-crl --for-ca prod-issuing-1 --crl root.crl.pem
```

Expected output: a receipt with `changed: true` and the list of revoked CA IDs, empty unless you revoked one.

### Revoke an intermediate

Use `keyCompromise` or another reason, then upload the new CRL.

```sh
openssl ca -config root-ca.cnf -revoke issuing.pem -crl_reason keyCompromise
openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
hemlig pki external-ca upload-crl --for-ca prod-issuing-1 --crl root.crl.pem
```

Hemlig revokes the CA when any reason lists it. Avoid `certificateHold`: Hemlig treats it as permanent, so a later release from hold does not restore the CA.

### Verify

Check the CA and its CRL with OpenSSL.

```sh
hemlig pki ca crl get prod-issuing-1 --out issuing.crl
openssl crl -inform DER -in issuing.crl -out issuing.crl.pem
cat issuing.pem root.pem > chain-and-root.pem
openssl verify -x509_strict -CAfile root.pem issuing.pem
openssl verify -crl_check -CAfile root.pem -CRLfile root.crl.pem issuing.pem
openssl crl -in issuing.crl.pem -CAfile chain-and-root.pem -noout -verify
```

Expected output: `OK` for the two `verify` commands and `verify OK` for the CRL.

## Next steps

- [Roll over a CA](pki-ca-rollover.md)
- [PKI](../guide/pki.md)
- [Gate PKI-2](acceptance.md#gate-pki-2-an-offline-root-activates-a-hemlig-intermediate)
