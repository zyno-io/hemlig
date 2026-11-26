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

On a terminal each command ends with a short result: what happened, the key facts, any warnings and a numbered list of next steps with your directory and IDs filled in. Add `--json` (or pipe the output) for the JSON receipt scripts use.

The directory now holds `root.key.pem` (the encrypted key), `root.pem`, `root.crl.pem` and `hemlig-ez.json` (the state). Copy the whole directory to two backup media after every operation, and store the passphrase apart from the media. Two active copies of the directory fork the root's CRL numbers; keep one.

### Keep the root key in a YubiKey

A YubiKey (firmware 5.3 or later, with `ykman` 5.5 or later installed) can hold the root key in PIV slot `9c`. Change the factory PIN first (`ykman piv access change-pin`); EZ refuses a default PIN.

```sh
hemlig pki ez generate-ca --subject 'CN=Example Offline Root CA 1,O=Example Corp' --yubikey
```

This is the **import** mode, and the one to prefer. EZ generates the key in software, writes the passphrase-encrypted backup `root.key.pem`, then imports the key into the slot with PIN policy `always` and touch policy `always`. You type the YubiKey's serial number, the passphrase (twice) and the PIN. Signing then needs the PIN and a touch.

To hold the same root on a second YubiKey, add `--second-yubikey-serial N` now, or run `hemlig pki ez import-key --yubikey-serial N` later; `import-key` also moves an existing software root onto a YubiKey.

**A second YubiKey that already holds the key.** If the same key was put on another YubiKey outside Hemlig (so there is no backup file for `import-key`), record it with `hemlig pki ez add-yubikey --yubikey-serial N`.

Hemlig checks that the root's slot on that device holds the root's key, shows a review, asks you to type `confirm` and the PIN, signs one test challenge, and records the device. It never writes to either device. After that either YubiKey can sign; connect one at a time or pass `--yubikey-serial`.

**Backup model.** The key file is the only copy that can restore the root. Store it, and the passphrase, apart from the YubiKey. A lost YubiKey is then a re-import, not a new root.

**On-device generation.** `--yubikey --on-device --accept-no-backup` generates the key inside the YubiKey so that it can never be exported. The tradeoff is that nothing can restore it: a lost, broken or locked YubiKey (PIN and PUK both blocked) means a new root, and every intermediate it signed has to be re-issued. EZ prints this warning and requires you to type `no backup`. Choose it only if you have a second, independent plan for losing the device.

**PIN and touch.** The PIN is entered at the terminal, never in an argument. EZ shows the attempts left, refuses a default PIN or a PIN with one attempt left (unless you pass `--allow-last-pin-attempt`), and never retries a wrong PIN. Prompts come after the typed `confirm`. When a signature waits for a touch, EZ prints `Touch the YubiKey`. `--touch-policy cached` keeps a touch valid for 15 seconds; `never` removes the second factor.

**Management key.** Importing or generating a key needs the YubiKey's management key. A factory default key is used with a warning, because anyone with the device could replace its keys. `--protect-management-key` swaps it for a random key stored behind the PIN; this changes the whole device and you must type `protect management key`. EZ never rotates a management key that is not the default. If yours is custom, EZ asks for it (hex) at the terminal.

**What EZ never does.** It uses only the slot you name, refuses an occupied slot unless you pass `--overwrite-slot <that slot>`, and never deletes, moves or resets anything. On firmware below 5.7 an overwritten key cannot be recovered or removed later, only replaced.

| Capability | Firmware 5.3 to 5.6 | Firmware 5.7 and later |
| ---------- | ------------------- | ---------------------- |
| ECDSA P-256, P-384 | Yes | Yes |
| RSA-3072, RSA-4096 | No | Yes |
| Delete or move a key | No (overwrite only) | Yes (EZ does not use it) |

### Adopt an existing root

If the root already exists, for example from the OpenSSL recipe below or as a key in a YubiKey slot, `adopt-ca` brings it into Hemlig instead of creating a new one. The root keeps its key and name, so the intermediates it signed stay valid. EZ must learn the root's last CRL number and every revocation it ever made: a next CRL that left one out would un-revoke it, so the command refuses without a source for each.

```sh
# the recipe directory from the manual steps below (root.pem, private/root.key, index.txt, crlnumber, root.crl.pem)
hemlig pki ez adopt-ca --dir ez-root --openssl-dir /path/to/recipe

# a root key in a YubiKey slot (the certificate comes from the slot, or from --cert)
hemlig pki ez adopt-ca --dir ez-root --yubikey --crl root.crl.pem
```

Hemlig validates the certificate against what it requires, checks the key against it, shows a review (the subject, fingerprint, key, CRL number, the number of revocations carried over and what it will sign) and asks you to type `confirm`. Then it signs one batch with the root key: a random test challenge, and a new CRL unless the CRL you gave is current, covers every revocation and has 45 days left.

- **Prior revocations.** Give `--crl FILE`, an `index.txt` (`--openssl-index`, or the recipe directory), or log in so EZ can read a registered root's stored CRL. If the root never revoked anything, say `--no-prior-revocations`. Without a CRL number from any of these, pass `--crl-number N`, at least the number of the last CRL the root ever issued. Every CRL must verify under the root.
- **A software key** is copied, never moved: EZ asks for its passphrase, then for a new one (twice), and writes the key to `--dir/root.key.pem` with 1,000,000 PBKDF2 iterations. OpenSSL's `-aes256` uses only 2,048, and an unencrypted key (accepted with a warning) is worse, so secure or delete the originals once the new copy is backed up. EZ never changes them.
- **A YubiKey** is read, not written: the slot is inspected read-only and Hemlig signs with the PIN and touch the slot requires. Hemlig holds no backup of such a key. `--store-certificate-in-slot` is the only device write.
- **A root whose certificate lacks CA extensions** (a certificate from `ykman piv certificates generate` has none) is refused with `--reissue-root-certificate` named. With the flag EZ issues a new self-signed certificate for the same key and name, keeps the old one as `root.original.pem`, and **the root fingerprint changes**: give the new `root.pem` to anything that pins the certificate. Chains still validate by name and key.

After adoption, `sign-cert`, `revoke-cert`, `renew-crl`, `upload-crl` and `status` work as for any EZ root.

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

`--if-due` signs a new CRL only when fewer than 45 days remain, and always uploads the current one if the server has an older copy. Offline, use `renew-crl --offline --crl-out root.crl.pem` and upload the file on an online machine with `hemlig pki ez upload-crl --crl root.crl.pem --root-cert root.pem`, which refuses a CRL that would drop a revocation the server already lists. `sign-cert` also renews a due CRL.

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
