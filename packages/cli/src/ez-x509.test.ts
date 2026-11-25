import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import test from "node:test";
import { bitString, bool, children, extension, explicit, octetString, oid, parseDer, seq, set, smallInt, time, tlv, uint } from "./ez-der";
import { EzError } from "./ez-error";
import { prepareCrl, prepareIntermediate, prepareRoot, signPrepared } from "./ez-issue";
import { assertRestrictedName, encodeSubject, formatIp, parseCidr, parseIp, parseSubject } from "./ez-name";
import { SoftwareSigner, generateSoftwareKey, normalizeEcdsa, signBatch } from "./ez-signer";
import { makeTestCsr } from "./ez-testkit";
import {
  EXTENSION_PROFILE_REASONS, OID, assembleCertificate, buildCrlTbs, computeIntermediateValidity, fromPem, keyIdentifier,
  displaySafe, summarizeCsr, parseCrl, parseKeyUsageBits, parseBasicConstraints, randomSerial, selfCheckCrl, toPem, validateCsr,
  validateRootCertificate, verifyCrlSignature, signatureAlgorithmForSpki, type EzKeyAlgorithm,
} from "./ez-x509";

const now = new Date("2026-11-25T12:00:00Z");
const day = 86_400_000;
const subject = { O: "Example Corp", CN: "Example EZ Root CA 1" };

const rejectsWith = (fn: () => unknown, code: string) =>
  assert.throws(fn, (e) => e instanceof EzError && e.code === code, `expected ${code}`);

const newRoot = async (algorithm: EzKeyAlgorithm = "ECDSA_P384", extra: { pathLen?: number } = {}) => {
  const key = generateSoftwareKey(algorithm);
  const signer = new SoftwareSigner(key.privateKey);
  const [root] = await signPrepared(signer, [prepareRoot(signer, { subject, now, ...extra })] as const);
  return { key, signer, root };
};

for (const algorithm of ["ECDSA_P384", "ECDSA_P256", "RSA_3072"] as const) {
  test(`root profile (${algorithm})`, async () => {
    const { signer, root } = await newRoot(algorithm);
    const cert = root.certificate;
    assert.equal(cert.version, 3);
    assert.ok(cert.issuerDer.equals(cert.subjectDer), "issuer bytes == subject bytes");
    assert.ok(cert.innerAlgorithm.equals(cert.outerAlgorithm), "one AlgorithmIdentifier");
    assert.equal(cert.innerAlgorithm.equals(signer.signatureAlgorithm.algorithmIdentifier), true);
    assert.equal(cert.serialMagnitude.length, 20);
    assert.equal(cert.serialMagnitude[0]! & 0x80, 0);
    assert.equal(cert.notBefore.toISOString(), "2026-11-25T11:00:00.000Z");
    assert.equal(cert.notAfter.toISOString(), new Date(now.getTime() + 7300 * day).toISOString());
    assert.deepEqual(cert.extensions.map((e) => [e.oid, e.critical]), [
      [OID.basicConstraints, true], [OID.keyUsage, true], [OID.ski, false],
    ]);
    const bc = parseBasicConstraints(cert.extensions[0]!.value);
    assert.deepEqual(bc, { ca: true, pathLen: undefined });
    assert.deepEqual([...parseKeyUsageBits(cert.extensions[1]!.value)].sort(), [5, 6]);
    assert.ok(cert.subjectKeyIdentifier!.equals(keyIdentifier(signer.spkiDer)));
    assert.equal(cert.authorityKeyIdentifier, undefined);
    assert.deepEqual(validateRootCertificate(root.der, { now, minimumRemainingDays: 90 }).reasons, []);
    // ECDSA AlgId has no parameters; RSA has NULL.
    assert.equal(cert.innerAlgorithm.length, algorithm.startsWith("ECDSA") ? 12 : 15);
  });
}

test("root: pathLen is optional and must be at least 1", async () => {
  const { root } = await newRoot("ECDSA_P256", { pathLen: 2 });
  assert.equal(parseBasicConstraints(root.certificate.extensions[0]!.value).pathLen, 2);
  const key = generateSoftwareKey("ECDSA_P256");
  const signer = new SoftwareSigner(key.privateKey);
  rejectsWith(() => prepareRoot(signer, { subject, now, pathLen: 0 }), "invalid_input");
});

test("root: the signer-side batch rejects a corrupted signature before anything is assembled", async () => {
  const key = generateSoftwareKey("ECDSA_P256");
  const good = new SoftwareSigner(key.privateKey);
  const bad = Object.assign(Object.create(good), {
    sign: async (items: readonly { data: Buffer }[]) => (await good.sign(items as never)).map((s) => Buffer.concat([s.subarray(0, -1), Buffer.from([s.at(-1)! ^ 1])])),
  });
  await assert.rejects(() => signPrepared(bad, [prepareRoot(good, { subject, now })] as const), (e) => e instanceof EzError && e.exitCode === 7 && e.code === "signature_self_check_failed");
});

test("signBatch calls the confirmation first; an abort signs nothing", async () => {
  const key = generateSoftwareKey("ECDSA_P256");
  const signer = new SoftwareSigner(key.privateKey);
  let signed = 0;
  const spy = Object.assign(Object.create(signer), { sign: async (...a: unknown[]) => { signed++; return signer.sign(...(a as [never])); } });
  const item = { id: "x", description: "x", data: Buffer.from("data") };
  await assert.rejects(() => signBatch(spy, [item], { confirm: () => { throw new Error("declined"); } }), /declined/);
  assert.equal(signed, 0);
  const out = await signBatch(spy, [item], { confirm: (items) => assert.equal(items.length, 1) });
  assert.equal(out.length, 1);
  assert.equal(signed, 1);
});

test("normalizeEcdsa converts raw r||s to DER and passes DER through", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const der = sign("sha256", Buffer.from("m"), { key: privateKey, dsaEncoding: "der" });
  const raw = sign("sha256", Buffer.from("m"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  assert.equal(raw.length, 64);
  assert.ok(normalizeEcdsa(der, 32).equals(der));
  const converted = normalizeEcdsa(raw, 32);
  assert.equal(converted[0], 0x30);
  assert.ok(verify("sha256", Buffer.from("m"), { key: publicKey, dsaEncoding: "der" }, converted), "the converted signature verifies");
  assert.ok(verify("sha256", Buffer.from("m"), { key: publicKey, dsaEncoding: "der" }, normalizeEcdsa(der, 32)));
  rejectsWith(() => normalizeEcdsa(Buffer.alloc(10, 1), 32), "signature_self_check_failed");
});

// -- custom self-signed certificates for validateRootCertificate ---------------------------------------------------

const handmade = (options: {
  extensions?: Buffer[]; cn?: string; version?: 3 | 1; notBefore?: Date; notAfter?: Date; issuerCn?: string; innerAlg?: Buffer; wrongKey?: boolean;
}) => {
  const pair = generateKeyPairSync("ec", { namedCurve: "P-384" });
  const spki = pair.publicKey.export({ type: "spki", format: "der" });
  const alg = seq(oid(OID.ecdsaSha384));
  const name = (cn: string) => encodeSubject({ CN: cn });
  const tbs = seq(
    ...(options.version === 1 ? [] : [explicit(0, smallInt(2))]),
    uint(randomSerial()), options.innerAlg ?? alg, name(options.issuerCn ?? options.cn ?? "Old Root"),
    seq(time(options.notBefore ?? new Date(now.getTime() - day)), time(options.notAfter ?? new Date(now.getTime() + 3650 * day))),
    name(options.cn ?? "Old Root"), spki,
    ...(options.extensions === undefined ? [] : [explicit(3, seq(...options.extensions))]),
  );
  const signer = options.wrongKey ? generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey : pair.privateKey;
  return assembleCertificate(tbs, alg, sign("sha384", tbs, { key: signer, dsaEncoding: "der" }));
};

const profileExtensions = (ski = Buffer.alloc(20, 7)) => [
  extension(OID.basicConstraints, true, seq(bool(true))),
  extension(OID.keyUsage, true, bitString(Buffer.from([0x06]), 1)),
  extension(OID.ski, false, octetString(ski)),
];

test("validateRootCertificate: an extension-less (ykman-style) certificate lists every profile reason", () => {
  const { reasons } = validateRootCertificate(handmade({ version: 1 }), { now });
  assert.deepEqual(new Set(reasons), new Set(["root_not_v3", "root_not_ca", "root_key_usage", "root_missing_ski"]));
  assert.ok(reasons.filter((r) => r !== "root_not_v3").every((r) => EXTENSION_PROFILE_REASONS.has(r)));
  const v3 = validateRootCertificate(handmade({ extensions: [] }), { now }).reasons;
  assert.deepEqual(new Set(v3), new Set(["root_not_ca", "root_key_usage", "root_missing_ski"]));
});

test("validateRootCertificate: individual rules", () => {
  const bad = (opts: Parameters<typeof handmade>[0], vopts = {}) => validateRootCertificate(handmade(opts), { now, ...vopts }).reasons;
  assert.deepEqual(bad({ extensions: profileExtensions() }), []);
  assert.deepEqual(bad({ extensions: [extension(OID.basicConstraints, false, seq(bool(true))), ...profileExtensions().slice(1)] }), ["root_basic_constraints_not_critical"]);
  assert.deepEqual(bad({ extensions: [extension(OID.basicConstraints, true, seq(bool(true), smallInt(0))), ...profileExtensions().slice(1)] }), ["root_path_len"]);
  assert.deepEqual(bad({ extensions: [...profileExtensions(), extension(OID.nameConstraints, true, seq())] }), ["root_name_constraints_unsupported"]);
  assert.deepEqual(bad({ extensions: [...profileExtensions(), extension(OID.policyConstraints, true, seq())] }), ["policy_extension_present"]);
  assert.deepEqual(bad({ extensions: [...profileExtensions(), extension("1.2.3.4.5", true, seq())] }), ["unrecognized_critical_extension"]);
  assert.deepEqual(bad({ extensions: profileExtensions(), cn: "Hemlig prod Issuing Root" }), ["identity_root_reserved"]);
  assert.deepEqual(bad({ extensions: profileExtensions(), issuerCn: "Someone Else" }), ["root_not_self_signed"]);
  assert.deepEqual(bad({ extensions: profileExtensions(), wrongKey: true }), ["root_signature_invalid"]);
  assert.deepEqual(bad({ extensions: profileExtensions(), notAfter: new Date(now.getTime() - day), notBefore: new Date(now.getTime() - 2 * day) }), ["root_not_valid"]);
  assert.deepEqual(bad({ extensions: profileExtensions(), notAfter: new Date(now.getTime() + 30 * day) }, { minimumRemainingDays: 90 }), ["root_expires_soon"]);
  // A SHA-1 SKI (OpenSSL recipe root) is fine.
  assert.deepEqual(bad({ extensions: profileExtensions(Buffer.alloc(20, 1)) }), []);
  assert.deepEqual(bad({ extensions: profileExtensions() }, { spkiDer: Buffer.from("x") }), ["key_mismatch"]);
});

// -- intermediates ------------------------------------------------------------------------------------------------

test("intermediate: CSR extensions copied byte for byte, AKI added, issuer is the root's subject bytes", async () => {
  const { signer, root } = await newRoot();
  const t = makeTestCsr({ permitted: { dns: ["example.com"], ip: ["10.0.0.0/8"] }, excluded: { dns: ["bad.example.com"] }, eku: [OID.serverAuth, OID.clientAuth] });
  const csr = validateCsr(t.der, { spkiSha256: undefined, subject: t.subject });
  const [issued] = await signPrepared(signer, [prepareIntermediate(signer, root.certificate, csr, { now, validityDays: 730 })] as const);
  const cert = issued.certificate;
  assert.ok(cert.issuerDer.equals(root.certificate.subjectDer));
  assert.ok(cert.subjectDer.equals(encodeSubject(t.subject)));
  assert.equal(cert.spkiSha256, csr.spkiSha256);
  assert.ok(cert.authorityKeyIdentifier!.equals(root.certificate.subjectKeyIdentifier!));
  const requested = csr.extensions.map((e) => e.toString("hex"));
  assert.deepEqual(cert.extensions.slice(0, -1).map((e) => e.raw.toString("hex")), requested);
  assert.equal(cert.extensions.at(-1)!.oid, OID.aki);
  assert.equal(cert.notAfter.getTime() - now.getTime(), 730 * day);
  assert.equal(cert.notBefore.getTime(), now.getTime() - 3_600_000);
  assert.ok(cert.innerAlgorithm.equals(cert.outerAlgorithm));
});

test("intermediate validity: clamped to the root, refused when too short or the root is not valid", async () => {
  const root = { notBefore: new Date(now.getTime() - day), notAfter: new Date(now.getTime() + 400 * day) };
  const v = computeIntermediateValidity({ now, days: 730, root });
  assert.equal(v.notAfter.getTime(), root.notAfter.getTime());
  assert.equal(v.notBefore.getTime(), now.getTime() - 3_600_000);
  assert.equal(computeIntermediateValidity({ now, days: 730, root: { ...root, notBefore: new Date(now.getTime() - 1800_000) } }).notBefore.getTime(), now.getTime() - 1800_000);
  rejectsWith(() => computeIntermediateValidity({ now, days: 730, root: { ...root, notAfter: new Date(now.getTime() + 60 * day) } }), "validity_too_short");
  rejectsWith(() => computeIntermediateValidity({ now, days: 730, root: { ...root, notBefore: new Date(now.getTime() + 1000) } }), "root_not_valid");
  rejectsWith(() => computeIntermediateValidity({ now, days: 730, root: { ...root, notAfter: new Date(now.getTime() - 1000) } }), "root_not_valid");
});

test("prepareIntermediate refuses a signer that does not hold the root key", async () => {
  const { root } = await newRoot();
  const other = new SoftwareSigner(generateSoftwareKey("ECDSA_P384").privateKey);
  const csr = validateCsr(makeTestCsr().der);
  rejectsWith(() => prepareIntermediate(other, root.certificate, csr, { now }), "key_mismatch");
});

// -- CSR validation matrix ----------------------------------------------------------------------------------------

test("validateCsr: accepts a Hemlig-shaped CSR and binds it to the record", () => {
  const t = makeTestCsr({ permitted: { dns: ["Example.com"] }, eku: [OID.serverAuth] });
  const spki = createHash("sha256").update(t.spkiDer).digest("hex");
  const csr = validateCsr(t.pem, {
    spkiSha256: spki, subject: t.subject, extendedKeyUsages: ["serverAuth"], nameConstraints: { permitted: { dns: ["example.com"] } },
  });
  assert.deepEqual(csr.warnings, []);
  assert.equal(csr.keyInfo.algorithm, "ECDSA_P256");
  assert.deepEqual(validateCsr(t.der).warnings, ["csr_unbound"]);
});

test("validateCsr: rejections", () => {
  const t = makeTestCsr();
  rejectsWith(() => validateCsr(makeTestCsr({ badSignature: true }).der), "csr_invalid");
  rejectsWith(() => validateCsr(t.der, { spkiSha256: "0".repeat(64) }), "csr_key_mismatch");
  rejectsWith(() => validateCsr(t.der, { subject: { CN: "Other" } }), "csr_subject_mismatch");
  rejectsWith(() => validateCsr(t.der, { rootSubjectDer: encodeSubject(t.subject) }), "csr_subject_is_root");
  rejectsWith(() => validateCsr(makeTestCsr({ pathLen: 1 }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ pathLen: null }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ omitSki: true }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ omitKeyUsage: true }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ keyUsageNonCritical: true }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ extra: [extension(OID.subjectAltName, false, seq())] }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ extraAttribute: true }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ eku: ["1.3.6.1.5.5.7.3.3"] }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(Buffer.from("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n")), "csr_invalid");
  rejectsWith(() => validateCsr(Buffer.from("garbage")), "csr_invalid");
  // Record comparison: NC / EKU.
  const nc = makeTestCsr({ permitted: { dns: ["example.com"] }, eku: [OID.serverAuth] });
  rejectsWith(() => validateCsr(nc.der, { nameConstraints: { permitted: { dns: ["other.com"] } } }), "csr_constraints_mismatch");
  rejectsWith(() => validateCsr(nc.der, { nameConstraints: null }), "csr_constraints_mismatch");
  rejectsWith(() => validateCsr(t.der, { nameConstraints: { permitted: { dns: ["example.com"] } } }), "csr_constraints_mismatch");
  rejectsWith(() => validateCsr(nc.der, { extendedKeyUsages: ["clientAuth"] }), "csr_constraints_mismatch");
  rejectsWith(() => validateCsr(nc.der, { extendedKeyUsages: [] }), "csr_constraints_mismatch");
});

test("validateCsr: IPv6 name constraints compare by address and mask bytes, not text; host bits are refused", () => {
  const t = makeTestCsr({ permitted: { ip: ["2001:db8::/32", "10.1.2.3/8"] } });
  // The testkit clears host bits (10.1.2.3/8 is sent as 10.0.0.0/8), so text forms differ but the bytes agree.
  validateCsr(t.der, { nameConstraints: { permitted: { ip: ["2001:0DB8:0:0:0:0:0:0/32", "10.0.0.0/8"] } } });
  // The record side may carry host bits; they are cleared before comparing.
  validateCsr(t.der, { nameConstraints: { permitted: { ip: ["2001:db8::1/32", "10.9.9.9/8"] } } });
  rejectsWith(() => validateCsr(t.der, { nameConstraints: { permitted: { ip: ["2001:db8::/33", "10.0.0.0/8"] } } }), "csr_constraints_mismatch");
  validateCsr(t.der, { nameConstraints: { permitted: [{ type: "ip", value: "2001:db8::/32" }, { type: "ip", value: "10.0.0.0/8" }] } });
  // A CSR whose iPAddress constraint has host bits set (10.1.2.3/8 on the wire) is refused, not silently masked.
  const hostBits = seq(explicit(0, seq(seq(tlv(0x87, Buffer.from("0a010203ff000000", "hex"))))));
  rejectsWith(() => validateCsr(makeTestCsr({ ncRaw: hostBits }).der), "csr_unexpected_extension");
});

const ncOf = (...parts: Buffer[]) => seq(...parts);
const dnsSubtree = (bytes: Buffer) => seq(tlv(0x82, bytes));

test("name constraints: strict host forms, decoded as latin1 so display equals the signed bytes", () => {
  const bad = (value: Buffer) => rejectsWith(() => validateCsr(makeTestCsr({ ncRaw: ncOf(explicit(0, dnsSubtree(value))) }).der), "csr_unexpected_extension");
  bad(Buffer.from([0x62, 0xe1, 0x64, 0x2e, 0x63, 0x6f, 0x6d])); // high bit: 'b\xE1d.com' used to display as "bad.com"
  bad(Buffer.from("\x1b[1A\x1b[2K\rexample.com", "latin1"));
  bad(Buffer.alloc(0));
  bad(Buffer.from("a..b"));
  bad(Buffer.from("a b.com"));
  bad(Buffer.from("a.com."));
  bad(Buffer.from("..a.com"));
  bad(Buffer.from("a_b.com"));
  // The same through the testkit's own encoder (the original probe).
  rejectsWith(() => validateCsr(makeTestCsr({ permitted: { dns: ["example.com"] }, excluded: { dns: ["b\u00e1d.example.com"] } }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ permitted: { dns: [""] } }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ permitted: { uri: ["a b"] } }).der), "csr_unexpected_extension");
  const ok = validateCsr(makeTestCsr({ permitted: { dns: [".Example.com", "a-b.example.org"], uri: ["host.example.com"] } }).der);
  assert.deepEqual(ok.nameConstraints!.permitted.map((e) => e.value), [".example.com", "a-b.example.org", "host.example.com"]);
  // Record-side values obey the same rule.
  rejectsWith(() => validateCsr(makeTestCsr().der, { nameConstraints: { permitted: { dns: ["a b"] } } }), "invalid_input");
});

test("name constraints: structure is strict (one [0], then one [1], non-empty, no duplicates)", () => {
  const sub = (v: string) => dnsSubtree(Buffer.from(v));
  const bad = (raw: Buffer) => rejectsWith(() => validateCsr(makeTestCsr({ ncRaw: raw }).der), "csr_unexpected_extension");
  bad(ncOf(explicit(0, sub("evil.com")), explicit(0, sub("example.com")))); // the probe: two [0]
  bad(ncOf(explicit(1, sub("a.com")), explicit(1, sub("b.com"))));
  bad(ncOf(explicit(1, sub("a.com")), explicit(0, sub("b.com")))); // wrong order
  bad(ncOf(explicit(0)));
  bad(ncOf());
  bad(ncOf(explicit(0, sub("a.com"), sub("A.com"))));
  bad(ncOf(explicit(0, seq(tlv(0x81, Buffer.from("x@example.com"))))));
  const good = validateCsr(makeTestCsr({ ncRaw: ncOf(explicit(0, sub("a.com")), explicit(1, sub("b.a.com"))) }).der);
  assert.equal(good.nameConstraints!.excluded.length, 1);
});

test("hostile strings are never shown raw: subjects are restricted and summaries escape", () => {
  const withCn = (cn: string) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from(cn, "latin1")))));
  rejectsWith(() => assertRestrictedName(withCn("\x1b[2J\rpwned"), "hemlig"), "subject_invalid");
  rejectsWith(() => assertRestrictedName(withCn("caf\xe9"), "hemlig"), "subject_invalid");
  assert.equal(displaySafe("a\x1b[0m\r\n\x7f\u00e9b"), "a\\x1b[0m\\x0d\\x0a\\x7f\\xe9b");
  const csr = validateCsr(makeTestCsr({ permitted: { dns: ["example.com"] } }).der);
  assert.deepEqual(summarizeCsr(csr).nameConstraints!.permitted, ["dns:example.com"]);
});

test("EKU is parsed strictly: trailing data after the SEQUENCE is refused", () => {
  const eku = Buffer.concat([seq(oid(OID.serverAuth)), seq(oid("1.3.6.1.5.5.7.3.3"))]);
  rejectsWith(() => validateCsr(makeTestCsr({ extra: [extension(OID.extendedKeyUsage, false, eku)] }).der), "csr_unexpected_extension");
  rejectsWith(() => validateCsr(makeTestCsr({ extra: [extension(OID.extendedKeyUsage, false, seq())] }).der), "csr_unexpected_extension");
});

test("prepareIntermediate refuses a CSR whose subject is the root's, whatever the caller checked", async () => {
  const { signer, root } = await newRoot();
  const csr = validateCsr(makeTestCsr({ subject }).der);
  rejectsWith(() => prepareIntermediate(signer, root.certificate, csr, { now }), "csr_subject_is_root");
  const folded = validateCsr(makeTestCsr({ subject: { O: "example   corp".replace("   ", " "), CN: "EXAMPLE EZ ROOT CA 1" } }).der);
  rejectsWith(() => prepareIntermediate(signer, root.certificate, folded, { now }), "csr_subject_is_root");
});

test("validateCsr: RSA and Ed25519 request keys", () => {
  assert.equal(validateCsr(makeTestCsr({ rsaBits: 2048 }).der).keyInfo.algorithm, "RSA_2048");
  assert.equal(validateCsr(makeTestCsr({ ed25519: true }).der).keyInfo.algorithm, "ED25519");
  assert.equal(validateCsr(makeTestCsr({ curve: "P-384" }).der).signatureAlgorithm.name, "ecdsa-with-SHA384");
});

// -- CRL --------------------------------------------------------------------------------------------------------

test("CRL builder: sorted entries, reason omitted for unspecified, number, AKI, self-check", async () => {
  const { signer, root } = await newRoot();
  const t0 = new Date("2026-11-25T12:00:00Z");
  const entries = [
    { serial: "0200", revokedAt: t0, reason: "keyCompromise" as const },
    { serial: "01", revokedAt: t0, reason: "unspecified" as const },
    { serial: "ff", revokedAt: t0, reason: "superseded" as const, invalidityDate: new Date("2026-11-20T00:00:00Z") },
  ];
  const [crl] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 7, thisUpdate: t0, entries })] as const);
  const parsed = crl.crl;
  assert.equal(parsed.version, 1);
  assert.equal(parsed.number, 7n);
  assert.deepEqual(parsed.entries.map((e) => e.serial), ["01", "ff", "0200"]);
  assert.deepEqual(parsed.entries.map((e) => e.reason), [undefined, "superseded", "keyCompromise"]);
  assert.equal(parsed.entries[1]!.invalidityDate!.toISOString(), "2026-11-20T00:00:00.000Z");
  assert.equal(parsed.nextUpdate!.getTime() - parsed.thisUpdate.getTime(), 180 * day);
  assert.deepEqual(parsed.extensions.map((e) => e.oid), [OID.aki, OID.crlNumber]);
  assert.ok(parsed.extensions.every((e) => !e.critical));
  assert.ok(parsed.authorityKeyIdentifier!.equals(root.certificate.subjectKeyIdentifier!));
  assert.ok(verifyCrlSignature(parsed, signer.spkiDer));
  assert.ok(fromPem(crl.pem, "X509 CRL").equals(crl.der));
});

test("CRL builder: an empty CRL omits revokedCertificates; limits are enforced", async () => {
  const { signer, root } = await newRoot("ECDSA_P256");
  const [empty] = await signPrepared(signer, [prepareCrl(signer, root.certificate, { number: 1, thisUpdate: now, entries: [] })] as const);
  assert.deepEqual(empty.crl.entries, []);
  const issuer = { subjectDer: root.certificate.subjectDer, subjectKeyIdentifier: root.certificate.subjectKeyIdentifier! };
  const base = { issuer, signatureAlgorithm: signer.signatureAlgorithm, number: 1n, thisUpdate: now, nextUpdate: new Date(now.getTime() + day), entries: [] };
  rejectsWith(() => buildCrlTbs({ ...base, nextUpdate: new Date(now.getTime() + 401 * day) }), "invalid_input");
  rejectsWith(() => buildCrlTbs({ ...base, nextUpdate: now }), "invalid_input");
  rejectsWith(() => buildCrlTbs({ ...base, number: 0n }), "invalid_input");
  rejectsWith(() => buildCrlTbs({ ...base, number: 1n << 160n }), "invalid_input");
  rejectsWith(() => buildCrlTbs({ ...base, thisUpdate: new Date(now.getTime() + 5) }), "invalid_input");
  rejectsWith(() => buildCrlTbs({ ...base, entries: [{ serial: "01", revokedAt: now }, { serial: "1", revokedAt: now }] }), "invalid_input");
  // selfCheckCrl catches a tampered CRL.
  const tampered = Buffer.from(empty.der);
  tampered[tampered.length - 3] = tampered[tampered.length - 3]! ^ 0xff;
  assert.throws(() => selfCheckCrl(tampered, { spkiDer: signer.spkiDer, subjectDer: root.certificate.subjectDer, subjectKeyIdentifier: root.certificate.subjectKeyIdentifier! }), EzError);
  assert.equal(parseCrl(empty.der).sha256.length, 64);
});

// -- names and helpers --------------------------------------------------------------------------------------------

test("subjects: parse, encode order and the restricted form", () => {
  const s = parseSubject("CN=My CA\\, Inc,O=Example,C=US");
  assert.deepEqual(s, { CN: "My CA, Inc", O: "Example", C: "US" });
  const der = encodeSubject(s);
  const rdns = children(parseDer(der));
  assert.equal(rdns.length, 3);
  assert.equal(rdns[0]!.raw.toString("hex").includes("1302" + "5553"), true, "C is a PrintableString first");
  rejectsWith(() => parseSubject("CN=a,CN=b"), "subject_invalid");
  rejectsWith(() => parseSubject("XX=a"), "subject_invalid");
  rejectsWith(() => parseSubject("CN=  "), "subject_invalid");
  rejectsWith(() => parseSubject("CN=double  space"), "subject_invalid");
  rejectsWith(() => parseSubject("CN=Zoë"), "subject_invalid");
  rejectsWith(() => parseSubject("C=USA,CN=x"), "subject_invalid");
  rejectsWith(() => parseSubject("O=NoCommonName"), "subject_invalid");
});

test("IP and CIDR parsing", () => {
  assert.equal(formatIp(parseIp("2001:db8:0:0:0:0:0:1")!), "2001:db8::1");
  assert.equal(parseIp("::ffff:1.2.3.4")!.toString("hex"), "00000000000000000000ffff01020304");
  assert.equal(parseIp("1.2.3"), undefined);
  assert.equal(parseIp("01.2.3.4"), undefined);
  assert.equal(parseIp("1::2::3"), undefined);
  assert.equal(parseCidr("10.1.2.3/8")!.address.toString("hex"), "0a000000");
  assert.equal(parseCidr("10.0.0.0/33"), undefined);
  assert.equal(parseCidr("10.0.0.0"), undefined);
});

test("serials, PEM and signature algorithm selection", () => {
  for (let i = 0; i < 50; i++) {
    const s = randomSerial();
    assert.equal(s.length, 20);
    assert.ok(s[0]! > 0 && s[0]! < 0x80);
  }
  assert.throws(() => fromPem("-----BEGIN A-----\nAA==\n-----END A-----\n-----BEGIN A-----\nAA==\n-----END A-----\n", "A"), EzError);
  assert.throws(() => fromPem("nothing", "A"), EzError);
  assert.equal(toPem(Buffer.alloc(100), "X").split("\n")[1]!.length, 64);
  const ed = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "der" });
  assert.equal(signatureAlgorithmForSpki(ed).name, "Ed25519");
  assert.equal(signatureAlgorithmForSpki(generateKeyPairSync("ec", { namedCurve: "secp521r1" }).publicKey.export({ type: "spki", format: "der" })).name, "ecdsa-with-SHA512");
});
