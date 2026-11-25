import { spawnSync } from "node:child_process";
import { createHash, createPublicKey, randomBytes, generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// The EZ library is MIT and lives in the CLI package; this AGPL-side test imports it (MIT into AGPL is fine) and
// checks its output against the server's own validators. The reverse import is forbidden (see import-boundary.test.ts).
import { prepareCrl, prepareIntermediate, prepareRoot, signPrepared } from "../../packages/cli/src/ez-issue";
import { decryptKeyFile, encryptPkcs8, readPrivateKey } from "../../packages/cli/src/ez-keyfile";
import { SoftwareSigner, generateSoftwareKey } from "../../packages/cli/src/ez-signer";
import { validateCsr, validateRootCertificate, type EzKeyAlgorithm } from "../../packages/cli/src/ez-x509";
import { buildExternalIntermediateCsr } from "./asn1/csr";
import { parseCertificate } from "./asn1/certificate";
import { verifyActivationChain } from "./chain";
import { ExternalCaService } from "./external-ca-service";
import { verifyRootCrl } from "./crl-verify";
import { buildCaSubject } from "./subject";
import type { CaRecord, ExternalCaRecord, NameConstraintSet, PkiKeyAlgorithm } from "./types";

const haveOpenssl = spawnSync("openssl", ["version"]).status === 0;
if (!haveOpenssl) {
  // eslint-disable-next-line no-console
  console.warn("EZ openssl cross-checks SKIPPED: the `openssl` binary is not on PATH.");
}
if (!haveOpenssl && process.env.CI) {
  it("requires openssl on PATH when CI is set", () => {
    throw new Error("openssl is not on PATH, but CI requires the cross-checks.");
  });
}
const opensslSuite = haveOpenssl ? describe : describe.skip;

const pem = (der: Uint8Array, label: string): string =>
  `-----BEGIN ${label}-----\n${Buffer.from(der).toString("base64").match(/.{1,64}/g)!.join("\n")}\n-----END ${label}-----\n`;
const EKU = ["1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"];

interface HemligCa {
  readonly csrDer: Buffer;
  readonly spkiDer: Buffer;
  readonly subject: ReturnType<typeof buildCaSubject>;
  readonly requested: CaRecord["requested"];
}

/** A CSR built by the server's own builder, as `CaService.create` does for an external intermediate. */
const hemligCsr = async (
  algorithm: PkiKeyAlgorithm,
  options: { nameConstraints?: NameConstraintSet; eku?: string[]; cn?: string } = {},
): Promise<HemligCa> => {
  const pair =
    algorithm === "ECDSA_P256" ? generateKeyPairSync("ec", { namedCurve: "P-256" })
    : algorithm === "ECDSA_P384" ? generateKeyPairSync("ec", { namedCurve: "P-384" })
    : algorithm === "ED25519" ? generateKeyPairSync("ed25519")
    : generateKeyPairSync("rsa", { modulusLength: algorithm === "RSA_4096" ? 4096 : 3072 });
  const spkiDer = pair.publicKey.export({ type: "spki", format: "der" });
  const subject = buildCaSubject({ O: "Example Corp", CN: options.cn ?? "Example Prod Issuing CA 1" });
  const csrDer = await buildExternalIntermediateCsr({
    subjectDer: subject.der,
    spkiDer,
    keyAlgorithm: algorithm,
    nameConstraints: options.nameConstraints,
    extendedKeyUsage: options.eku,
    sign: async (info) =>
      algorithm === "ED25519" ? sign(null, info, pair.privateKey)
      : algorithm.startsWith("RSA") ? sign("sha256", info, pair.privateKey)
      : sign(algorithm === "ECDSA_P384" ? "sha384" : "sha256", info, { key: pair.privateKey, dsaEncoding: "der" }),
  });
  return {
    csrDer,
    spkiDer,
    subject,
    requested: { pathLen: 0, nameConstraints: options.nameConstraints, extendedKeyUsages: options.eku },
  };
};

const newRoot = async (algorithm: EzKeyAlgorithm) => {
  const key = generateSoftwareKey(algorithm);
  const signer = new SoftwareSigner(key.privateKey);
  const [root] = await signPrepared(signer, [prepareRoot(signer, { subject: { O: "Example Corp", CN: `Example EZ Root ${algorithm}` }, now: new Date() })] as const);
  return { key, signer, root };
};

const activate = (ca: HemligCa, rootDer: Buffer, certDer: Buffer) =>
  verifyActivationChain({
    certificatePem: pem(certDer, "CERTIFICATE"),
    chainPem: pem(rootDer, "CERTIFICATE"),
    now: new Date(),
    caSpkiDer: ca.spkiDer,
    requestedSubjectKey: ca.subject.key,
    requested: ca.requested,
    deploymentName: "test",
  });

const nc: NameConstraintSet = {
  permitted: [
    { type: "dns", value: "example.com" },
    { type: "ip", value: "10.0.0.0/8" },
  ],
  excluded: [{ type: "dns", value: "bad.example.com" }],
};

describe("EZ library against the server's validators", () => {
  const cases: [EzKeyAlgorithm, PkiKeyAlgorithm, NameConstraintSet | undefined, string[] | undefined][] = [
    ["ECDSA_P384", "ECDSA_P256", nc, EKU],
    ["ECDSA_P384", "ECDSA_P384", undefined, undefined],
    ["ECDSA_P256", "RSA_3072", nc, ["1.3.6.1.5.5.7.3.2"]],
    ["RSA_3072", "ECDSA_P256", undefined, EKU],
    ["ECDSA_P384", "ED25519", { permitted: [{ type: "dns", value: "example.org" }], excluded: [] }, undefined],
  ];

  it.each(cases)("root %s signs a Hemlig %s CSR that passes verifyActivationChain (constraints preserved)", async (rootAlgorithm, caAlgorithm, constraints, eku) => {
    const { signer, root } = await newRoot(rootAlgorithm);
    const ca = await hemligCsr(caAlgorithm, { nameConstraints: constraints, eku });
    const csr = validateCsr(ca.csrDer, {
      subject: { O: "Example Corp", CN: "Example Prod Issuing CA 1" },
      spkiSha256: createHash("sha256").update(ca.spkiDer).digest("hex"),
    });
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, csr, { now: new Date() })] as const);
    const result = activate(ca, root.der, issued.der);
    expect(result.broaderThanRequested).toBe(false);
    expect(result.effective.nameConstraints).toEqual(
      constraints === undefined ? undefined : expect.objectContaining({ permitted: expect.any(Array) }),
    );
    expect(result.certificate.serialHex).toBe(issued.certificate.serialHex);
    // The generated root also satisfies the independent server-side certificate parser.
    expect(result.root.subjectKeyIdentifier?.toString("hex")).toBe(root.certificate.subjectKeyIdentifier?.toString("hex"));
  });

  it("a second CA under the same root also activates", async () => {
    const { signer, root } = await newRoot("ECDSA_P384");
    for (const cn of ["Example Prod Issuing CA 1", "Example Prod Issuing CA 2"]) {
      const ca = await hemligCsr("ECDSA_P256", { cn, nameConstraints: nc, eku: EKU });
      const csr = validateCsr(ca.csrDer);
      const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, csr, { now: new Date() })] as const);
      expect(activate(ca, root.der, issued.der).broaderThanRequested).toBe(false);
    }
  });

  it("an intermediate longer than the root is clamped, and the server still accepts it", async () => {
    const key = generateSoftwareKey("ECDSA_P256");
    const signer = new SoftwareSigner(key.privateKey);
    const [root] = await signPrepared(signer, [prepareRoot(signer, { subject: { CN: "Short Root" }, now: new Date(), validityDays: 400 })] as const);
    const ca = await hemligCsr("ECDSA_P256");
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, validateCsr(ca.csrDer), { now: new Date(), validityDays: 730 })] as const);
    expect(issued.certificate.notAfter.getTime()).toBeLessThanOrEqual(root.certificate.notAfter.getTime());
    expect(activate(ca, root.der, issued.der).broaderThanRequested).toBe(false);
  });

  it("CRL #1, a renewal and a revoking CRL pass verifyRootCrl with ordered numbers", async () => {
    const { signer, root } = await newRoot("ECDSA_P384");
    const ca = await hemligCsr("ECDSA_P256", { nameConstraints: nc, eku: EKU });
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, validateCsr(ca.csrDer), { now: new Date() })] as const);
    const issuer = parseCertificate(root.der);
    const t0 = new Date(Math.floor(Date.now() / 1000) * 1000);
    const [c1] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 1, thisUpdate: t0, entries: [] })] as const);
    const [c2] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 2, thisUpdate: new Date(t0.getTime() + 1000), entries: [] })] as const);
    const [c3] = await signPrepared(signer, [prepareCrl(signer, root.certificate, {
      number: 3, thisUpdate: new Date(t0.getTime() + 2000),
      entries: [{ serial: issued.certificate.serialHex, revokedAt: t0, reason: "keyCompromise" }],
    })] as const);
    const v = [c1, c2, c3].map((c) => verifyRootCrl({ crl: c.pem, issuer, now: new Date(Date.now() + 5000) }));
    expect(v[0]!.numberHex < v[1]!.numberHex && v[1]!.numberHex < v[2]!.numberHex).toBe(true);
    expect(v[0]!.entries).toHaveLength(0);
    expect(v[2]!.entries).toHaveLength(1);
    expect(v[2]!.entries[0]!.serialHex).toBe(issued.certificate.serialHex);
    expect(v[2]!.entries[0]!.reason).toBe(1); // keyCompromise
    expect(v[2]!.nextUpdate.getTime() - v[2]!.thisUpdate.getTime()).toBe(180 * 86_400_000);
  });

  it("a reissued root keeps its identity for the server's external_ca_mismatch rule, and a root with a fresh SKI does not", async () => {
    const { signer, root } = await newRoot("ECDSA_P384");
    const [again] = await signPrepared(signer, [prepareRoot(signer, {
      subject: root.certificate.subjectDer, now: new Date(), subjectKeyIdentifier: root.certificate.subjectKeyIdentifier,
    })] as const);
    const [fresh] = await signPrepared(signer, [prepareRoot(signer, { subject: root.certificate.subjectDer, now: new Date(), subjectKeyIdentifier: randomBytes(20) })] as const);
    // An intermediate signed under the original root is what the server holds a record for.
    const ca = await hemligCsr("ECDSA_P256");
    const csr = validateCsr(ca.csrDer);
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, csr, { now: new Date() })] as const);
    const original = activate(ca, root.der, issued.der);
    // ca-service.ts: ext id from the root SPKI, then the record must match subjectKey and SKI hex.
    const extId = (r: { spkiSha256: string }) => `ext-${r.spkiSha256.slice(0, 40)}`;
    const matches = (r: ReturnType<typeof activate>["root"], rootSubjectKey: string) =>
      extId(r) === extId(original.root) &&
      rootSubjectKey === original.rootSubject.key &&
      r.subjectKeyIdentifier?.toString("hex") === original.root.subjectKeyIdentifier?.toString("hex");
    // The server activates a CA under the reissued root (new serial and fingerprint, same key, subject and SKI)...
    const [reissuedIssued] = await signPrepared(signer, [prepareIntermediate(signer, again.certificate, csr, { now: new Date() })] as const);
    const viaReissued = activate(ca, again.der, reissuedIssued.der);
    expect(again.certificate.fingerprint).not.toBe(root.certificate.fingerprint);
    expect(matches(viaReissued.root, viaReissued.rootSubject.key)).toBe(true);
    // ...whereas a root that does not keep the SKI would be rejected as external_ca_mismatch.
    const [freshIssued] = await signPrepared(signer, [prepareIntermediate(signer, fresh.certificate, csr, { now: new Date() })] as const);
    const viaFresh = activate(ca, fresh.der, freshIssued.der);
    expect(viaFresh.root.spkiSha256).toBe(original.root.spkiSha256);
    expect(matches(viaFresh.root, viaFresh.rootSubject.key)).toBe(false);
    // (Driving CaService.activate and ExternalCaService.uploadCrl needs the full DynamoDB/KMS mock harness of
    // ca-service.test.ts; the matching above is the exact predicate at ca-service.ts:1121-1128.)
  });
});

describe("ExternalCaService.uploadCrl with EZ-built root CRLs", () => {
  const actor = { type: "human" as const, id: "admin-1" };
  const idem = (n: number) => `idem-key-${String(n).padStart(4, "0")}`;

  /** The in-file mock harness of external-ca-service.test.ts: record and repository mocks around the real service. */
  const harness = (ext: ExternalCaRecord, cas: Record<string, CaRecord> = {}) => {
    const pki = {
      getExternalCa: jest.fn(async () => ext),
      getCa: jest.fn(async (id: string) => cas[id]),
      putHumanIdempotency: jest.fn(async () => "committed"),
      revokeCaExternally: jest.fn(async () => "revoked"),
      commitExternalCrl: jest.fn(async () => "committed"),
    };
    const service = new ExternalCaService({
      pki,
      repository: { getIdempotency: jest.fn(async () => undefined) },
      objects: { putImmutableOrGet: jest.fn(async () => ({})) },
      config: { pkiBucketName: "pki" },
      now: () => new Date(),
      cursors: { encode: jest.fn(), decode: jest.fn() },
    } as never);
    return { service, pki };
  };

  const build = async () => {
    const { signer, root } = await newRoot("ECDSA_P384");
    const ca = await hemligCsr("ECDSA_P256", { nameConstraints: nc, eku: EKU });
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, validateCsr(ca.csrDer), { now: new Date() })] as const);
    const t0 = new Date(Date.now() - 2 * 3_600_000);
    const crlAt = async (number: number, entries: { serial: string }[] = []) =>
      (await signPrepared(signer, [prepareCrl(signer, root.certificate, {
        number, thisUpdate: new Date(t0.getTime() + number * 1000),
        entries: entries.map((e) => ({ ...e, revokedAt: new Date(t0.getTime() + number * 1000), reason: "keyCompromise" as const })),
      })] as const))[0];
    const extId = `ext-${root.certificate.spkiSha256.slice(0, 40)}`;
    const record = (crl?: { pem: string; der: Buffer; crl: { number?: bigint; thisUpdate: Date; nextUpdate?: Date; sha256: string } }): ExternalCaRecord =>
      ({
        extId, certificatePem: root.pem, fingerprint: root.certificate.fingerprint, spkiSha256: root.certificate.spkiSha256,
        subjectDer: "", subjectAttributes: [], subjectKey: "k", subjectKeyIdentifier: root.certificate.subjectKeyIdentifier!.toString("hex"),
        notAfter: root.certificate.notAfter.toISOString(), createdAt: "2026-01-01T00:00:00.000Z", dependents: new Set(["ca-listed"]),
        environments: new Set(["prod"]), version: "pkv-1",
        ...(crl === undefined ? {} : { crl: {
          numberHex: crl.crl.number!.toString(16).padStart(40, "0"), thisUpdate: crl.crl.thisUpdate.toISOString(),
          nextUpdate: crl.crl.nextUpdate!.toISOString(), sha256: crl.crl.sha256, objectKey: "k", uploadedAt: "2026-01-01T00:00:00.000Z", uploadedBy: actor,
        } }),
      }) as ExternalCaRecord;
    const dependent = { caId: "ca-listed", status: "ACTIVE", serial: issued.certificate.serialHex, key: { state: "ACTIVE" }, parent: { type: "external", id: extId } } as unknown as CaRecord;
    return { extId, crlAt, record, dependent, issued };
  };

  it("accepts #1, then #2; repeats of #2 are unchanged; #1 after #2 is crl_not_newer", async () => {
    const { extId, crlAt, record } = await build();
    const [c1, c2] = [await crlAt(1), await crlAt(2)];
    const first = harness(record());
    const r1 = await first.service.uploadCrl(actor, idem(1), extId, { crl: c1.pem });
    expect(r1.body).toMatchObject({ changed: true, revokedCaIds: [] });
    expect(first.pki.commitExternalCrl).toHaveBeenCalledTimes(1);

    const second = harness(record(c1));
    expect((await second.service.uploadCrl(actor, idem(2), extId, { crl: c2.pem })).body).toMatchObject({ changed: true });

    const third = harness(record(c2));
    const repeat = await third.service.uploadCrl(actor, idem(3), extId, { crl: c2.pem });
    expect(repeat.body).toMatchObject({ changed: false, revokedCaIds: [] });
    expect(third.pki.commitExternalCrl).not.toHaveBeenCalled();
    await expect(third.service.uploadCrl(actor, idem(4), extId, { crl: c1.pem })).rejects.toMatchObject({ statusCode: 409, code: "crl_not_newer" });
  });

  it("a CRL #3 that lists the intermediate revokes its dependent CA", async () => {
    const { extId, crlAt, record, dependent, issued } = await build();
    const c2 = await crlAt(2);
    const c3 = await crlAt(3, [{ serial: issued.certificate.serialHex }]);
    const { service, pki } = harness(record(c2), { "ca-listed": dependent });
    const result = await service.uploadCrl(actor, idem(5), extId, { crl: c3.pem });
    expect(result.body).toMatchObject({ changed: true, revokedCaIds: ["ca-listed"] });
    expect(pki.revokeCaExternally).toHaveBeenCalledTimes(1);
    expect((pki.revokeCaExternally.mock.calls as unknown as unknown[][])[0]![1]).toMatchObject({ reason: "keyCompromise" });
  });
});

opensslSuite("EZ output against openssl", () => {
  let dir: string;
  const run = (args: string[], allowFailure = false) => {
    const r = spawnSync("openssl", args, { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    const output = `${r.stdout}${r.stderr}`;
    if (r.status !== 0 && !allowFailure) throw new Error(`openssl ${args.join(" ")} failed:\n${output}`);
    return { status: r.status ?? -1, output };
  };
  beforeAll(() => {
    dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), "ez-roundtrip-"));
  });
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it.each(["ECDSA_P384", "ECDSA_P256", "RSA_3072"] as const)("root %s: verify -x509_strict, -crl_check before and after a revoke, crl -verify", async (algorithm) => {
    const { signer, root } = await newRoot(algorithm);
    const ca = await hemligCsr("ECDSA_P256", { nameConstraints: nc, eku: EKU });
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, validateCsr(ca.csrDer), { now: new Date() })] as const);
    const t0 = new Date(Math.floor(Date.now() / 1000) * 1000);
    const [empty] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 1, thisUpdate: t0, entries: [] })] as const);
    const [revoked] = await signPrepared(signer, [prepareCrl(signer, root.certificate, {
      number: 2, thisUpdate: new Date(t0.getTime() + 1000), entries: [{ serial: issued.certificate.serialHex, revokedAt: t0, reason: "keyCompromise" }],
    })] as const);
    const tag = algorithm.toLowerCase();
    writeFileSync(join(dir, `${tag}.root.pem`), root.pem);
    writeFileSync(join(dir, `${tag}.ca.pem`), issued.pem);
    writeFileSync(join(dir, `${tag}.crl1.pem`), empty.pem);
    writeFileSync(join(dir, `${tag}.crl2.pem`), revoked.pem);
    expect(run(["verify", "-x509_strict", "-CAfile", `${tag}.root.pem`, `${tag}.ca.pem`]).output).toContain("OK");
    expect(run(["verify", "-x509_strict", "-crl_check", "-CAfile", `${tag}.root.pem`, "-CRLfile", `${tag}.crl1.pem`, `${tag}.ca.pem`]).output).toContain("OK");
    const bad = run(["verify", "-x509_strict", "-crl_check", "-CAfile", `${tag}.root.pem`, "-CRLfile", `${tag}.crl2.pem`, `${tag}.ca.pem`], true);
    expect(bad.status).not.toBe(0);
    expect(bad.output).toContain("error 23");
    expect(run(["crl", "-in", `${tag}.crl2.pem`, "-CAfile", `${tag}.root.pem`, "-verify", "-noout"]).output).toContain("verify OK");
    const text = run(["x509", "-in", `${tag}.root.pem`, "-noout", "-text"]).output;
    expect(text).toContain("CA:TRUE");
    expect(text).toContain("Certificate Sign, CRL Sign");
  });

  it("openssl pkey reads the EZ key file and decrypts to the same public key", () => {
    const key = generateSoftwareKey("ECDSA_P384");
    const passphrase = "correct horse battery staple";
    writeFileSync(join(dir, "ez.key.pem"), encryptPkcs8(key.exportPkcs8(), passphrase));
    writeFileSync(join(dir, "ez.pass"), passphrase);
    const out = spawnSync("openssl", ["pkey", "-in", join(dir, "ez.key.pem"), "-passin", `file:${join(dir, "ez.pass")}`, "-pubout", "-outform", "DER"], { stdio: ["ignore", "pipe", "pipe"] });
    expect(out.status).toBe(0);
    expect(Buffer.from(out.stdout).equals(key.spkiDer)).toBe(true);
    expect(createPublicKey(decryptKeyFile(encryptPkcs8(key.exportPkcs8(), passphrase), passphrase)).export({ type: "spki", format: "der" }).equals(key.spkiDer)).toBe(true);
  });

  it("adopts a recipe root created by the openssl CLI (SHA-1 SKI): validates, signs, and the server activates", async () => {
    const conf = `[req]\nprompt=no\ndefault_md=sha384\nstring_mask=utf8only\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nO=Example Corp\nCN=Example Offline Root CA 1\n[ext]\nbasicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n`;
    writeFileSync(join(dir, "recipe.cnf"), conf);
    run(["ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", "recipe.key"]);
    run(["req", "-new", "-x509", "-key", "recipe.key", "-days", "3650", "-config", "recipe.cnf", "-out", "recipe.pem", "-sha384"]);
    const rootPem = readFileSync(join(dir, "recipe.pem"), "utf8") as string;
    const rootDer = Buffer.from(rootPem.replace(/-----[A-Z ]+-----|\s/g, ""), "base64");
    const validation = validateRootCertificate(rootDer, { minimumRemainingDays: 90 });
    expect(validation.reasons).toEqual([]);
    expect(validation.certificate.subjectKeyIdentifier).toHaveLength(20);
    const signer = new SoftwareSigner(readPrivateKey(readFileSync(join(dir, "recipe.key"), "utf8")).key);
    const ca = await hemligCsr("ECDSA_P256", { nameConstraints: nc, eku: EKU });
    const [issued] = await signPrepared(signer, [prepareIntermediate(signer, validation.certificate, validateCsr(ca.csrDer), { now: new Date() })] as const);
    expect(activate(ca, rootDer, issued.der).broaderThanRequested).toBe(false);
    const t0 = new Date(Math.floor(Date.now() / 1000) * 1000);
    const [crl] = await signPrepared(signer, [prepareCrl(signer, validation.certificate, { number: 1, thisUpdate: t0, entries: [] })] as const);
    verifyRootCrl({ crl: crl.pem, issuer: parseCertificate(rootDer), now: new Date(Date.now() + 5000) });
    writeFileSync(join(dir, "recipe.ca.pem"), issued.pem);
    expect(run(["verify", "-x509_strict", "-CAfile", "recipe.pem", "recipe.ca.pem"]).output).toContain("OK");
  });
});
