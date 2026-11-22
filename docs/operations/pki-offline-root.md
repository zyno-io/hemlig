---
title: "Offline root recipe"
description: "Create an OpenSSL root, sign a Hemlig CSR, issue and upload the root CRL, and revoke an intermediate."
pageType: how-to
---

# Offline root recipe

Create an offline OpenSSL 3 root, sign Hemlig's intermediate CSR, and keep the root CRL current.

**Role:** the person who holds the root key. **Before you start:** an offline machine with OpenSSL 3, two offline backup media, and the [CLI](../guide/cli.md) logged in on an online machine. Allow about 30 minutes.

The root must sign the Hemlig CSR directly. Its subject must use printable ASCII, and a new root key needs a new root DN. For the design, see [PKI](../guide/pki.md).

## Create the root configuration

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

## Create the root once

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

## Sign a Hemlig CSR

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

## Upload a fresh root CRL

Issue a new CRL and upload it before the old one's `nextUpdate`.

```sh
openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
hemlig pki external-ca upload-crl --for-ca prod-issuing-1 --crl root.crl.pem
```

Expected output: a receipt with `changed: true` and the list of revoked CA IDs, empty unless you revoked one.

## Revoke an intermediate

Use `keyCompromise` or another reason, then upload the new CRL.

```sh
openssl ca -config root-ca.cnf -revoke issuing.pem -crl_reason keyCompromise
openssl ca -config root-ca.cnf -gencrl -out root.crl.pem
hemlig pki external-ca upload-crl --for-ca prod-issuing-1 --crl root.crl.pem
```

Hemlig revokes the CA when any reason lists it. Avoid `certificateHold`: Hemlig treats it as permanent, so a later release from hold does not restore the CA.

## Verify

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
