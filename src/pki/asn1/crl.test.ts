import {
  expectGolden,
  goldenFixtures,
  makeIntermediate,
  makeRoot,
  newKey,
} from "../__fixtures__/testkit";
import { caSignatureAlgorithmIdentifier } from "./algorithms";
import {
  assembleCrl,
  buildTbsCertList,
  parseCrl,
  verifyCrlSignature,
} from "./crl";
import {
  children,
  encodeTime,
  explicit,
  parseDer,
  seq,
  tlv,
  unsignedInteger,
} from "./der";
import { EXT, extension } from "./extensions";

describe("CRL encoding", () => {
  it("builds a full v2 CRL with AKI and CRLNumber, entries ordered by serial", async () => {
    const root = await makeRoot();
    const ca = await makeIntermediate(root);
    const algorithm = caSignatureAlgorithmIdentifier("ECDSA_P256");
    const tbs = buildTbsCertList({
      signatureAlgorithm: algorithm,
      issuerDer: ca.cert.subjectDer,
      thisUpdate: new Date("2026-11-22T10:00:00Z"),
      nextUpdate: new Date("2026-11-29T10:00:00Z"),
      crlNumber: 258n,
      authorityKeyId: ca.cert.subjectKeyIdentifier ?? Buffer.alloc(0),
      entries: [
        {
          serialHex: "ff01",
          revokedAt: new Date("2026-11-22T09:00:00Z"),
          reason: "keyCompromise",
          invalidityDate: new Date("2026-11-21T00:00:00Z"),
        },
        {
          serialHex: "01",
          revokedAt: new Date("2026-11-22T08:00:00Z"),
          reason: "unspecified",
        },
        {
          serialHex: "0203",
          revokedAt: new Date("2026-11-22T08:30:00Z"),
          reason: "superseded",
        },
      ],
    });
    const der = assembleCrl(tbs, algorithm, ca.key.sign(tbs));
    const crl = parseCrl(der);

    expect(crl.version).toBe(1);
    expect(crl.issuerDer.equals(ca.cert.subjectDer)).toBe(true);
    expect(crl.crlNumber?.toString("hex")).toBe("0102");
    expect(
      crl.authorityKeyIdentifier?.equals(
        ca.cert.subjectKeyIdentifier ?? Buffer.alloc(0),
      ),
    ).toBe(true);
    expect(
      crl.extensions.map((extension) => [extension.oid, extension.critical]),
    ).toEqual([
      [EXT.authorityKeyIdentifier, false],
      [EXT.crlNumber, false],
    ]);
    expect(crl.entries.map((entry) => entry.serialHex)).toEqual([
      "01",
      "0203",
      "ff01",
    ]);
    // `unspecified` is encoded by omitting the reason.
    expect(crl.entries.map((entry) => entry.reason)).toEqual([undefined, 4, 1]);
    expect(
      crl.entries[2]?.extensions.map((extension) => extension.oid),
    ).toEqual([EXT.reasonCode, EXT.invalidityDate]);
    expect(
      crl.entries[2]?.extensions.every((extension) => !extension.critical),
    ).toBe(true);
    expect(verifyCrlSignature(crl, ca.cert.spkiDer)).toBe(true);
    expect(verifyCrlSignature(crl, root.cert.spkiDer)).toBe(false);
    expect(verifyCrlSignature(crl, (await newKey()).spkiDer)).toBe(false);
  });

  it("omits revokedCertificates when empty", async () => {
    const root = await makeRoot();
    const algorithm = caSignatureAlgorithmIdentifier("ECDSA_P384");
    const tbs = buildTbsCertList({
      signatureAlgorithm: algorithm,
      issuerDer: root.cert.subjectDer,
      thisUpdate: new Date("2026-11-22T10:00:00Z"),
      nextUpdate: new Date("2026-11-29T10:00:00Z"),
      crlNumber: 1n,
      authorityKeyId: root.cert.subjectKeyIdentifier ?? Buffer.alloc(0),
      entries: [],
    });
    // version, signature, issuer, thisUpdate, nextUpdate, [0] extensions
    expect(children(parseDer(tbs)).map((element) => element.tag)).toEqual([
      0x02, 0x30, 0x30, 0x17, 0x17, 0xa0,
    ]);
    expect(
      parseCrl(assembleCrl(tbs, algorithm, root.key.sign(tbs))).entries,
    ).toEqual([]);
  });

  it("matches the golden TBSCertList, with GeneralizedTime from 2050", async () => {
    const { issuer } = await goldenFixtures();
    const algorithm = caSignatureAlgorithmIdentifier("ECDSA_P256");
    const tbs = buildTbsCertList({
      signatureAlgorithm: algorithm,
      issuerDer: issuer.subjectDer,
      thisUpdate: new Date("2049-12-30T00:00:00Z"),
      nextUpdate: new Date("2050-01-06T00:00:00Z"),
      crlNumber: 7n,
      authorityKeyId: issuer.subjectKeyIdentifier ?? Buffer.alloc(0),
      entries: [
        {
          serialHex: "0a0b0c",
          revokedAt: new Date("2049-12-30T00:00:00Z"),
          reason: "cessationOfOperation",
        },
        { serialHex: "0d", revokedAt: new Date("2050-01-02T00:00:00Z") },
      ],
    });
    expectGolden("crl.tbs.der", tbs);
    const crl = parseCrl(assembleCrl(tbs, algorithm, Buffer.alloc(8, 1)));
    expect(crl.thisUpdate.toISOString()).toBe("2049-12-30T00:00:00.000Z");
    expect(crl.nextUpdate?.toISOString()).toBe("2050-01-06T00:00:00.000Z");
    expect(tbs.includes(Buffer.from("3439313233303030303030305a", "hex"))).toBe(
      true,
    ); // UTCTime 491230000000Z
    expect(
      tbs.includes(Buffer.from("32303530303130363030303030305a", "hex")),
    ).toBe(true); // GeneralizedTime
  });

  describe("strict parsing", () => {
    const base = async () => {
      const root = await makeRoot();
      const algorithm = caSignatureAlgorithmIdentifier("ECDSA_P384");
      const tbs = buildTbsCertList({
        signatureAlgorithm: algorithm,
        issuerDer: root.cert.subjectDer,
        thisUpdate: new Date("2026-11-22T10:00:00Z"),
        nextUpdate: new Date("2026-11-29T10:00:00Z"),
        crlNumber: 1n,
        authorityKeyId: root.cert.subjectKeyIdentifier ?? Buffer.alloc(0),
        entries: [],
      });
      return { algorithm, kids: children(parseDer(tbs)).map((kid) => kid.raw) };
    };

    it.each([
      [
        "a duplicate [0] extensions block",
        [explicit(0, seq(extension("1.2.3.4", false, seq())))],
      ],
      ["a field after the extensions", [tlv(0xa1, Buffer.alloc(0))]],
    ])("rejects %s", async (_, extra) => {
      const { algorithm, kids } = await base();
      expect(() =>
        parseCrl(
          assembleCrl(seq(...kids, ...extra), algorithm, Buffer.alloc(8, 1)),
        ),
      ).toThrow();
    });

    it("rejects a reasonCode that is not one minimal ENUMERATED byte", async () => {
      const { algorithm, kids } = await base();
      const entryWith = (value: Buffer) =>
        seq(
          ...kids.slice(0, 5),
          seq(
            seq(
              unsignedInteger(Buffer.from("01", "hex")),
              encodeTime(new Date("2026-11-22T09:00:00Z")),
              seq(extension(EXT.reasonCode, false, value)),
            ),
          ),
          ...kids.slice(5),
        );
      const parse = (value: Buffer) =>
        parseCrl(assembleCrl(entryWith(value), algorithm, Buffer.alloc(8, 1)));
      expect(parse(tlv(0x0a, Buffer.from([1]))).entries[0]?.reason).toBe(1);
      expect(() => parse(tlv(0x0a, Buffer.from([0, 1])))).toThrow();
      expect(() => parse(tlv(0x0a, Buffer.alloc(0)))).toThrow();
      expect(() => parse(tlv(0x0a, Buffer.from([0x81])))).toThrow();
    });

    it("rejects malformed serial hex when building", async () => {
      const root = await makeRoot();
      for (const serialHex of ["abc", "", "0G", "AB"]) {
        expect(() =>
          buildTbsCertList({
            signatureAlgorithm: caSignatureAlgorithmIdentifier("ECDSA_P384"),
            issuerDer: root.cert.subjectDer,
            thisUpdate: new Date(),
            nextUpdate: new Date(),
            crlNumber: 1n,
            authorityKeyId: Buffer.alloc(20),
            entries: [{ serialHex, revokedAt: new Date() }],
          }),
        ).toThrow();
      }
    });

    it("writes serials in canonical form", async () => {
      const root = await makeRoot();
      const algorithm = caSignatureAlgorithmIdentifier("ECDSA_P384");
      const tbs = buildTbsCertList({
        signatureAlgorithm: algorithm,
        issuerDer: root.cert.subjectDer,
        thisUpdate: new Date("2026-11-22T10:00:00Z"),
        nextUpdate: new Date("2026-11-29T10:00:00Z"),
        crlNumber: 1n,
        authorityKeyId: Buffer.alloc(20),
        entries: [
          { serialHex: "000102", revokedAt: new Date("2026-11-22T09:00:00Z") },
        ],
      });
      expect(
        parseCrl(assembleCrl(tbs, algorithm, Buffer.alloc(8, 1))).entries[0]
          ?.serialHex,
      ).toBe("0102");
    });
  });
});
