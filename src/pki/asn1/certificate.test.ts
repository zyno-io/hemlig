import { createHash } from "node:crypto";
import {
  expectGolden,
  goldenFixtures as fixtures,
  makeIntermediate,
  makeRoot,
  newKey,
  subjectDer,
} from "../__fixtures__/testkit";
import { caSignatureAlgorithmIdentifier } from "./algorithms";
import {
  assembleCertificate,
  buildCaTbs,
  buildLeafTbs,
  generateSerial,
  parseCertificate,
  verifyCertificateSignature,
  type LeafTbsInput,
  type ParsedCertificate,
} from "./certificate";
import { EKU, EXT } from "./extensions";

const serial = Buffer.from("0102030405060708090a0b0c0d0e0f1011121314", "hex");

/** Parses a TBS wrapped in a certificate with a placeholder signature. */
const unsigned = (tbs: Buffer): ParsedCertificate =>
  parseCertificate(
    assembleCertificate(
      tbs,
      caSignatureAlgorithmIdentifier("ECDSA_P256"),
      Buffer.alloc(8, 1),
    ),
  );

const leafInput = (
  issuer: ParsedCertificate,
  leafSpki: Buffer,
  overrides: Partial<LeafTbsInput> = {},
): LeafTbsInput => ({
  issuer,
  serial,
  notBefore: new Date("2026-11-22T00:00:00Z"),
  notAfter: new Date("2027-02-20T00:00:00Z"),
  subjectDer: subjectDer("api.example.com"),
  spkiDer: leafSpki,
  keyUsage: ["digitalSignature"],
  extendedKeyUsage: [EKU.serverAuth, EKU.clientAuth],
  san: {
    dns: ["api.example.com"],
    ip: ["10.0.0.5"],
    uri: ["spiffe://prod.example.com/ns/a"],
  },
  subjectEmpty: false,
  policies: ["1.3.6.1.4.1.99999.1"],
  ...overrides,
});

describe("buildLeafTbs", () => {
  it("matches the golden TBS and the criticality profile", async () => {
    const { issuer, leafSpki } = await fixtures();
    const { tbs } = buildLeafTbs(leafInput(issuer, leafSpki));
    expectGolden("leaf.tbs.der", tbs);

    const leaf = unsigned(tbs);
    expect(leaf.version).toBe(2);
    expect(leaf.serialHex).toBe(serial.toString("hex"));
    expect(
      leaf.extensions.map((extension) => [extension.oid, extension.critical]),
    ).toEqual([
      [EXT.basicConstraints, true],
      [EXT.keyUsage, true],
      [EXT.extendedKeyUsage, false],
      [EXT.subjectAltName, false],
      [EXT.subjectKeyIdentifier, false],
      [EXT.authorityKeyIdentifier, false],
      [EXT.certificatePolicies, false],
    ]);
    expect(leaf.basicConstraints).toEqual({
      ca: false,
      pathLen: undefined,
      critical: true,
    });
    expect(leaf.keyUsage).toEqual(["digitalSignature"]);
    expect(leaf.extendedKeyUsage).toEqual([EKU.serverAuth, EKU.clientAuth]);
  });

  it("sets SKI by RFC 7093 method 1 and AKI to the issuer SKI bytes", async () => {
    const { issuer, leafSpki } = await fixtures();
    const leaf = unsigned(buildLeafTbs(leafInput(issuer, leafSpki)).tbs);
    // P-256 SPKI ends with the 65-byte uncompressed point, the BIT STRING contents.
    const expected = createHash("sha256")
      .update(leafSpki.subarray(leafSpki.length - 65))
      .digest()
      .subarray(0, 20);
    expect(leaf.subjectKeyIdentifier?.toString("hex")).toBe(
      expected.toString("hex"),
    );
    expect(leaf.authorityKeyIdentifier?.toString("hex")).toBe(
      issuer.subjectKeyIdentifier?.toString("hex"),
    );
    const aki = leaf.extensions.find(
      (extension) => extension.oid === EXT.authorityKeyIdentifier,
    );
    expect(aki?.value.toString("hex")).toBe(
      `3016 8014 ${issuer.subjectKeyIdentifier?.toString("hex")}`.replace(
        / /g,
        "",
      ),
    );
  });

  it("copies the issuer DN byte for byte", async () => {
    const { issuer, leafSpki } = await fixtures();
    const { tbs } = buildLeafTbs(leafInput(issuer, leafSpki));
    expect(unsigned(tbs).issuerDer.equals(issuer.subjectDer)).toBe(true);
    expect(tbs.includes(issuer.subjectDer)).toBe(true);
  });

  it("makes SubjectAltName critical for an empty subject", async () => {
    const { issuer, leafSpki } = await fixtures();
    const empty = Buffer.from("3000", "hex");
    const { tbs } = buildLeafTbs(
      leafInput(issuer, leafSpki, {
        subjectDer: empty,
        subjectEmpty: true,
        policies: undefined,
      }),
    );
    expectGolden("leaf-empty-subject.tbs.der", tbs);
    const leaf = unsigned(tbs);
    expect(
      leaf.extensions.find((extension) => extension.oid === EXT.subjectAltName)
        ?.critical,
    ).toBe(true);
    expect(() =>
      buildLeafTbs(
        leafInput(issuer, leafSpki, {
          subjectDer: empty,
          subjectEmpty: true,
          san: {},
        }),
      ),
    ).toThrow(/SubjectAltName/);
  });

  it("encodes validity as UTCTime before 2050 and GeneralizedTime from 2050", async () => {
    const { issuer, leafSpki } = await fixtures();
    const { tbs } = buildLeafTbs(
      leafInput(issuer, leafSpki, {
        notBefore: new Date("2049-12-31T23:59:59Z"),
        notAfter: new Date("2050-03-01T00:00:00Z"),
      }),
    );
    expectGolden("leaf-2050.tbs.der", tbs);
    expect(
      tbs.includes(Buffer.from("170d3439313233313233353935395a", "hex")),
    ).toBe(true);
    expect(
      tbs.includes(Buffer.from("180f32303530303330313030303030305a", "hex")),
    ).toBe(true);
    const leaf = unsigned(tbs);
    expect(leaf.notBefore.toISOString()).toBe("2049-12-31T23:59:59.000Z");
    expect(leaf.notAfter.toISOString()).toBe("2050-03-01T00:00:00.000Z");
  });
});

describe("buildCaTbs", () => {
  it("builds the intermediate profile with critical constraints", async () => {
    const root = await makeRoot();
    const key = await newKey();
    const { tbs } = buildCaTbs({
      issuer: root.cert,
      serial,
      notBefore: new Date("2026-11-22T00:00:00Z"),
      notAfter: new Date("2028-11-22T00:00:00Z"),
      subjectDer: subjectDer("Issuing"),
      spkiDer: key.spkiDer,
      pathLen: 0,
      nameConstraints: {
        permitted: [{ type: "dns", value: "example.com" }],
        excluded: [],
      },
      extendedKeyUsage: [EKU.serverAuth],
    });
    const ca = unsigned(tbs);
    expect(
      ca.extensions.map((extension) => [extension.oid, extension.critical]),
    ).toEqual([
      [EXT.basicConstraints, true],
      [EXT.keyUsage, true],
      [EXT.nameConstraints, true],
      [EXT.extendedKeyUsage, false],
      [EXT.subjectKeyIdentifier, false],
      [EXT.authorityKeyIdentifier, false],
    ]);
    expect(ca.extensions[0]?.value.toString("hex")).toBe("30060101ff020100");
    expect(ca.extensions[1]?.value.toString("hex")).toBe("03020106");
    expect(ca.basicConstraints).toMatchObject({ ca: true, pathLen: 0 });
    expect(ca.nameConstraints?.permitted).toEqual([
      { type: "dns", value: "example.com" },
    ]);
  });
});

describe("certificate parsing and signatures", () => {
  it("verifies a chain and rejects the wrong key", async () => {
    const root = await makeRoot();
    const intermediate = await makeIntermediate(root);
    const other = await newKey("ECDSA_P384");
    expect(
      verifyCertificateSignature(intermediate.cert, root.cert.spkiDer),
    ).toBe(true);
    expect(verifyCertificateSignature(intermediate.cert, other.spkiDer)).toBe(
      false,
    );
    expect(verifyCertificateSignature(root.cert, root.cert.spkiDer)).toBe(true);
  });

  it("generates 20-byte positive serials with the top bit clear", () => {
    for (let i = 0; i < 50; i += 1) {
      const value = generateSerial();
      expect(value).toHaveLength(20);
      expect((value[0] as number) & 0x80).toBe(0);
      expect(value.some((byte) => byte !== 0)).toBe(true);
    }
  });

  it("rejects garbage", () => {
    expect(() => parseCertificate(Buffer.from("3000", "hex"))).toThrow();
    expect(() => parseCertificate(Buffer.from("deadbeef", "hex"))).toThrow();
  });
});
