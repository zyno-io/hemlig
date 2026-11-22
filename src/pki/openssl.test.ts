import { spawnSync } from "node:child_process";
import {
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  newKey,
  leafKey,
  subjectDer,
  type TestKey,
} from "./__fixtures__/testkit";
import { caSignatureAlgorithmIdentifier } from "./asn1/algorithms";
import {
  assembleCertificate,
  buildLeafTbs,
  generateSerial,
  parseCertificate,
} from "./asn1/certificate";
import { assembleCrl, buildTbsCertList } from "./asn1/crl";
import { buildExternalIntermediateCsr } from "./asn1/csr";
import { EKU } from "./asn1/extensions";
import { fromPem, toPem } from "./asn1/pem";
import {
  computeLeafValidity,
  verifyActivationChain,
  earliestNotAfter,
} from "./chain";
import { parseCsr } from "./csr";
import { verifyRootCrl } from "./crl-verify";
import { buildCaSubject } from "./subject";
import type { NameConstraintSet } from "./types";

const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
if (!haveOpenssl) {
  // eslint-disable-next-line no-console
  console.warn(
    "openssl cross-checks SKIPPED: the `openssl` binary is not on PATH.",
  );
}
const suite = haveOpenssl ? describe : describe.skip;
if (!haveOpenssl && process.env.CI) {
  // CI must not silently lose the cross-checks.
  it("requires openssl on PATH when CI is set", () => {
    throw new Error(
      "openssl is not on PATH, but CI requires the cross-checks.",
    );
  });
}

/** The offline root recipe's configuration from the PKI plan, with an absolute `dir`. */
const rootConfig = (dir: string): string => `
[ ca ]
default_ca = root_ca

[ root_ca ]
dir              = ${dir}
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
`;

suite("openssl cross-checks", () => {
  let dir: string;
  let caKey: TestKey;
  const permitted: NameConstraintSet = {
    permitted: [
      { type: "dns", value: "example.com" },
      { type: "ip", value: "10.0.0.0/8" },
    ],
    excluded: [],
  };
  const subject = { O: "Example Corp", CN: "Example Prod Issuing CA 1" };

  const openssl = (
    args: string[],
    options: { allowFailure?: boolean } = {},
  ): { status: number; output: string } => {
    const result = spawnSync("openssl", args, { cwd: dir, encoding: "utf8" });
    const output = `${result.stdout}${result.stderr}`;
    if (result.status !== 0 && options.allowFailure !== true) {
      throw new Error(`openssl ${args.join(" ")} failed:\n${output}`);
    }
    return { status: result.status ?? -1, output };
  };
  const file = (name: string): string => join(dir, name);
  const read = (name: string): string => readFileSync(file(name), "utf8");
  const write = (name: string, data: string | Uint8Array): void =>
    writeFileSync(file(name), data);

  const issueLeaf = (dnsNames: string[], options: { serial?: Buffer } = {}) => {
    const issuer = parseCertificate(
      fromPem(read("issuing.pem"), "CERTIFICATE"),
    );
    const key = leafKey({ type: "ec", curve: "prime256v1" });
    const validity = computeLeafValidity({
      now: new Date(),
      requestedSeconds: 90 * 86_400,
      ceilingsSeconds: [397 * 86_400],
      caNotBefore: issuer.notBefore,
      chainNotAfters: [
        issuer.notAfter,
        parseCertificate(fromPem(read("root.pem"), "CERTIFICATE")).notAfter,
      ],
    });
    const { tbs, signatureAlgorithm } = buildLeafTbs({
      issuer,
      serial: options.serial ?? generateSerial(),
      notBefore: validity.notBefore,
      notAfter: validity.notAfter,
      subjectDer: subjectDer({ CN: dnsNames[0] ?? "leaf.example.com" }),
      spkiDer: key.spkiDer,
      keyUsage: ["digitalSignature"],
      extendedKeyUsage: [EKU.serverAuth],
      san: { dns: dnsNames },
      subjectEmpty: false,
    });
    const der = assembleCertificate(tbs, signatureAlgorithm, caKey.sign(tbs));
    return {
      der,
      pem: toPem(der, "CERTIFICATE"),
      parsed: parseCertificate(der),
    };
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "hemlig-pki-openssl-"));
    mkdirSync(join(dir, "certs"));
    mkdirSync(join(dir, "private"));
    write("root-ca.cnf", rootConfig(dir));
    write("index.txt", "");
    write("crlnumber", "01\n");
    write("serial", `${openssl(["rand", "-hex", "16"]).output.trim()}\n`);
    // The offline root recipe, step 1 (unencrypted key for the test).
    openssl([
      "genpkey",
      "-algorithm",
      "EC",
      "-pkeyopt",
      "ec_paramgen_curve:P-384",
      "-pkeyopt",
      "ec_param_enc:named_curve",
      "-out",
      "private/root.key",
    ]);
    openssl([
      "req",
      "-config",
      "root-ca.cnf",
      "-new",
      "-x509",
      "-key",
      "private/root.key",
      "-days",
      "7300",
      "-out",
      "root.pem",
    ]);

    // Hemlig creates the intermediate key and CSR; the root signs it (recipe step 2).
    caKey = await newKey("ECDSA_P256");
    const csr = await buildExternalIntermediateCsr({
      subjectDer: buildCaSubject(subject).der,
      spkiDer: caKey.spkiDer,
      keyAlgorithm: "ECDSA_P256",
      nameConstraints: permitted,
      extendedKeyUsage: [EKU.serverAuth, EKU.clientAuth],
      sign: async (info) => caKey.sign(info),
    });
    write("issuing.csr", toPem(csr, "CERTIFICATE REQUEST"));
  }, 120_000);

  afterAll(() => {
    if (dir !== undefined) {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("accepts the Hemlig CSR in OpenSSL and has it signed by the offline root", () => {
    expect(
      openssl(["req", "-in", "issuing.csr", "-noout", "-verify"]).output,
    ).toMatch(/verify OK/i);
    const text = openssl([
      "req",
      "-in",
      "issuing.csr",
      "-noout",
      "-text",
    ]).output;
    expect(text).toContain("CA:TRUE, pathlen:0");
    expect(text).toContain("Certificate Sign, CRL Sign");
    expect(text).toContain("Permitted:");
    openssl([
      "ca",
      "-config",
      "root-ca.cnf",
      "-in",
      "issuing.csr",
      "-out",
      "issuing.pem",
      "-notext",
      "-batch",
    ]);

    // The returned certificate passes Hemlig's activation checks.
    const caSpki = caKey.spkiDer;
    const result = verifyActivationChain({
      certificatePem: read("issuing.pem"),
      chainPem: read("root.pem"),
      now: new Date(),
      caSpkiDer: caSpki,
      requestedSubjectKey: buildCaSubject(subject).key,
      requested: {
        pathLen: 0,
        nameConstraints: permitted,
        extendedKeyUsages: [EKU.serverAuth, EKU.clientAuth],
      },
      deploymentName: "test",
    });
    expect(result.broaderThanRequested).toBe(false);
    expect(result.effective.nameConstraints).toEqual(permitted);
    expect(result.certificate.basicConstraints).toMatchObject({
      ca: true,
      pathLen: 0,
      critical: true,
    });
    expect(
      earliestNotAfter([result.certificate, result.root]).getTime(),
    ).toBeGreaterThan(Date.now());
  });

  it("verifies a Hemlig leaf under -x509_strict -purpose sslserver", () => {
    const leaf = issueLeaf(["api.example.com"]);
    write("leaf.pem", leaf.pem);
    const result = openssl([
      "verify",
      "-x509_strict",
      "-purpose",
      "sslserver",
      "-CAfile",
      "root.pem",
      "-untrusted",
      "issuing.pem",
      "leaf.pem",
    ]);
    expect(result.output).toContain("leaf.pem: OK");
    // The profile prints as intended.
    const text = openssl(["x509", "-in", "leaf.pem", "-noout", "-text"]).output;
    expect(text).toContain("CA:FALSE");
    expect(text).toContain("DNS:api.example.com");
    expect(text).toContain("TLS Web Server Authentication");
  });

  it("rejects a NameConstraints violation", () => {
    const leaf = issueLeaf(["api.evil.org"]);
    write("evil.pem", leaf.pem);
    const result = openssl(
      [
        "verify",
        "-x509_strict",
        "-purpose",
        "sslserver",
        "-CAfile",
        "root.pem",
        "-untrusted",
        "issuing.pem",
        "evil.pem",
      ],
      { allowFailure: true },
    );
    expect(result.status).not.toBe(0);
    expect(result.output).toMatch(/permitted subtree violation/i);
  });

  it("verifies a Hemlig-generated CRL with openssl crl -verify, and enforces it across the chain", () => {
    const revoked = issueLeaf(["revoked.example.com"]);
    const good = issueLeaf(["good.example.com"]);
    write("revoked.pem", revoked.pem);
    write("good.pem", good.pem);

    const issuer = parseCertificate(
      fromPem(read("issuing.pem"), "CERTIFICATE"),
    );
    const algorithm = caSignatureAlgorithmIdentifier("ECDSA_P256");
    const tbs = buildTbsCertList({
      signatureAlgorithm: algorithm,
      issuerDer: issuer.subjectDer,
      thisUpdate: new Date(),
      nextUpdate: new Date(Date.now() + 7 * 86_400_000),
      crlNumber: 5n,
      authorityKeyId: issuer.subjectKeyIdentifier ?? Buffer.alloc(0),
      entries: [
        {
          serialHex: revoked.parsed.serialHex,
          revokedAt: new Date(),
          reason: "keyCompromise",
          invalidityDate: new Date(Date.now() - 3_600_000),
        },
      ],
    });
    write(
      "hemlig.crl.pem",
      toPem(assembleCrl(tbs, algorithm, caKey.sign(tbs)), "X509 CRL"),
    );
    expect(
      openssl([
        "crl",
        "-in",
        "hemlig.crl.pem",
        "-CAfile",
        "issuing.pem",
        "-verify",
        "-noout",
      ]).output,
    ).toMatch(/verify OK/i);
    const text = openssl([
      "crl",
      "-in",
      "hemlig.crl.pem",
      "-noout",
      "-text",
    ]).output;
    expect(text).toContain("Key Compromise");
    expect(text).toContain("X509v3 CRL Number");
    expect(text).toContain(revoked.parsed.serialHex.toUpperCase());

    // Full-chain revocation checking needs the root CRL too (recipe step 3).
    openssl([
      "ca",
      "-config",
      "root-ca.cnf",
      "-gencrl",
      "-out",
      "root.crl.pem",
    ]);
    write("crls.pem", `${read("root.crl.pem")}${read("hemlig.crl.pem")}`);
    const args = (leaf: string): string[] => [
      "verify",
      "-crl_check_all",
      "-x509_strict",
      "-purpose",
      "sslserver",
      "-CAfile",
      "root.pem",
      "-untrusted",
      "issuing.pem",
      "-CRLfile",
      "crls.pem",
      leaf,
    ];
    expect(openssl(args("good.pem")).output).toContain("good.pem: OK");
    const refused = openssl(args("revoked.pem"), { allowFailure: true });
    expect(refused.status).not.toBe(0);
    expect(refused.output).toMatch(/certificate revoked/i);
  });

  it("accepts the recipe CRL from openssl ca -gencrl, before and after revoking the intermediate", () => {
    const root = parseCertificate(fromPem(read("root.pem"), "CERTIFICATE"));
    const issuing = parseCertificate(
      fromPem(read("issuing.pem"), "CERTIFICATE"),
    );

    const first = verifyRootCrl({
      crl: read("root.crl.pem"),
      issuer: root,
      now: new Date(),
    });
    expect(first.numberHex).toBe("0000000000000000000000000000000000000001");
    expect(first.entries).toEqual([]);

    // Recipe step 4: revoke the intermediate, then reissue the CRL.
    openssl([
      "ca",
      "-config",
      "root-ca.cnf",
      "-revoke",
      "issuing.pem",
      "-crl_reason",
      "keyCompromise",
    ]);
    openssl([
      "ca",
      "-config",
      "root-ca.cnf",
      "-gencrl",
      "-out",
      "root2.crl.pem",
    ]);
    const second = verifyRootCrl({
      crl: read("root2.crl.pem"),
      issuer: root,
      now: new Date(),
    });
    expect(second.numberHex).toBe("0000000000000000000000000000000000000002");
    expect(second.numberHex > first.numberHex).toBe(true);
    expect(second.entries).toHaveLength(1);
    expect(second.entries[0]?.serialHex).toBe(issuing.serialHex);
    expect(second.entries[0]?.reason).toBe(1);
    expect(
      second.parsed.authorityKeyIdentifier?.equals(
        root.subjectKeyIdentifier ?? Buffer.alloc(0),
      ),
    ).toBe(true);
  });

  it("parses CSRs produced by openssl req", () => {
    openssl([
      "req",
      "-new",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:P-256",
      "-nodes",
      "-keyout",
      "ec.key",
      "-subj",
      "/CN=api.example.com",
      "-addext",
      "subjectAltName=DNS:api.example.com,DNS:www.example.com,IP:10.0.0.1",
      "-out",
      "ec.csr",
    ]);
    const ec = parseCsr(read("ec.csr"));
    expect(ec.keyAlgorithm).toBe("ECDSA_P256");
    expect(ec.san.dns).toEqual(["api.example.com", "www.example.com"]);
    expect(ec.san.ip).toEqual(["10.0.0.1"]);
    expect(ec.subject).toEqual([{ oid: "2.5.4.3", value: "api.example.com" }]);

    openssl([
      "req",
      "-new",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      "rsa.key",
      "-subj",
      "/CN=rsa.example.com",
      "-out",
      "rsa.csr",
    ]);
    expect(parseCsr(read("rsa.csr")).keyAlgorithm).toBe("RSA_2048");

    openssl(["genpkey", "-algorithm", "ED25519", "-out", "ed.key"]);
    openssl([
      "req",
      "-new",
      "-key",
      "ed.key",
      "-subj",
      "/CN=ed.example.com",
      "-out",
      "ed.csr",
    ]);
    expect(parseCsr(read("ed.csr")).keyAlgorithm).toBe("ED25519");
  });
});
