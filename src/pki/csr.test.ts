import { createHash, ECDH, generateKeyPairSync } from "node:crypto";
import { ApiError } from "./../domain/errors";
import {
  csrPem,
  extensionRequest,
  leafKey,
  makeCsrDer,
  subjectDer,
  type LeafKeySpec,
} from "./__fixtures__/testkit";
import { OID } from "./asn1/algorithms";
import {
  bitString,
  children,
  parseDer,
  type Tlv,
  oid,
  seq,
  set,
  smallInteger,
  tlv,
  TAG,
  unsignedInteger,
  derNull,
} from "./asn1/der";
import {
  EKU,
  EXT,
  basicConstraintsValue,
  extendedKeyUsageValue,
  extension,
  keyUsageValue,
} from "./asn1/extensions";
import { encodeNameConstraints, encodeSubjectAltName } from "./asn1/names";
import { toPem } from "./asn1/pem";
import { parseCsr, maximumCsrBytes } from "./csr";

const p256 = leafKey({ type: "ec", curve: "prime256v1" });

const sanExtension = (
  names: Parameters<typeof encodeSubjectAltName>[0],
): Buffer => extension(EXT.subjectAltName, false, encodeSubjectAltName(names));

const failure = (
  action: () => unknown,
): { code: string; status: number; reason?: string } => {
  try {
    action();
  } catch (error) {
    if (error instanceof ApiError) {
      return {
        code: error.code,
        status: error.statusCode,
        reason: error.safeReason,
      };
    }
    throw error;
  }
  throw new Error("expected the CSR to be rejected");
};

describe("parseCsr", () => {
  it("normalizes a well-formed request", () => {
    const der = makeCsrDer({
      key: p256,
      subject: subjectDer({ O: "Example Corp", CN: "api.example.com" }),
      extensions: [
        sanExtension({
          dns: ["api.example.com", "www.example.com"],
          ip: ["10.0.0.5"],
          uri: ["spiffe://prod/ns/a"],
        }),
        extension(
          EXT.keyUsage,
          true,
          keyUsageValue(["digitalSignature", "keyEncipherment"]),
        ),
        extension(
          EXT.extendedKeyUsage,
          false,
          extendedKeyUsageValue([EKU.serverAuth]),
        ),
        extension(EXT.basicConstraints, true, basicConstraintsValue(false)),
        // Ignored, never copied.
        extension(
          EXT.nameConstraints,
          true,
          encodeNameConstraints({
            permitted: [{ type: "dns", value: "x.com" }],
            excluded: [],
          }),
        ),
      ],
    });
    const parsed = parseCsr(csrPem(der));
    expect(parsed.keyAlgorithm).toBe("ECDSA_P256");
    expect(
      parsed.subject.map((attribute) => [attribute.oid, attribute.value]),
    ).toEqual([
      ["2.5.4.10", "Example Corp"],
      ["2.5.4.3", "api.example.com"],
    ]);
    expect(parsed.san).toEqual({
      dns: ["api.example.com", "www.example.com"],
      ip: ["10.0.0.5"],
      uri: ["spiffe://prod/ns/a"],
      email: [],
      unsupported: [],
    });
    expect(parsed.keyUsage).toEqual(["digitalSignature", "keyEncipherment"]);
    expect(parsed.extendedKeyUsage).toEqual([EKU.serverAuth]);
    expect(parsed.basicConstraints).toEqual({ ca: false, pathLen: undefined });
    expect(parsed.spkiSha256).toBe(
      createHash("sha256").update(p256.spkiDer).digest("hex"),
    );
    expect(parsed.derSha256).toBe(
      createHash("sha256").update(der).digest("hex"),
    );
    expect(Object.keys(parsed)).not.toContain("nameConstraints");
  });

  it("accepts a request with no attributes and with unsupported SAN types reported", () => {
    expect(parseCsr(csrPem(makeCsrDer({ key: p256 }))).san.dns).toEqual([]);
    const parsed = parseCsr(
      csrPem(
        makeCsrDer({
          key: p256,
          extensions: [
            extension(
              EXT.subjectAltName,
              false,
              seq(
                tlv(0x81, Buffer.from("a@example.com")),
                tlv(0xa4, seq()),
                tlv(0x82, Buffer.from("a.example.com")),
              ),
            ),
          ],
        }),
      ),
    );
    expect(parsed.san.email).toEqual(["a@example.com"]);
    expect(parsed.san.unsupported).toEqual(["directoryName"]);
    expect(parsed.san.dns).toEqual(["a.example.com"]);
  });

  it.each<[LeafKeySpec, string]>([
    [{ type: "ec", curve: "prime256v1" }, "ECDSA_P256"],
    [{ type: "ec", curve: "secp384r1" }, "ECDSA_P384"],
    [{ type: "ec", curve: "secp521r1" }, "ECDSA_P521"],
    [{ type: "ed25519" }, "ED25519"],
    [{ type: "rsa", bits: 2048 }, "RSA_2048"],
  ])("classifies %j as %s", (spec, expected) => {
    expect(
      parseCsr(csrPem(makeCsrDer({ key: leafKey(spec) }))).keyAlgorithm,
    ).toBe(expected);
  });

  it("verifies RSA-PSS signatures", () => {
    const key = leafKey({ type: "rsa", bits: 2048 });
    expect(parseCsr(csrPem(makeCsrDer({ key, pss: true }))).keyAlgorithm).toBe(
      "RSA_2048",
    );
    expect(
      failure(() =>
        parseCsr(
          csrPem(makeCsrDer({ key, pss: true, corruptSignature: true })),
        ),
      ),
    ).toMatchObject({
      reason: "bad_signature",
    });
  });

  describe("rejects", () => {
    it("multiple PEM blocks", () => {
      const one = csrPem(makeCsrDer({ key: p256 }));
      expect(failure(() => parseCsr(one + one))).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "multiple_blocks",
      });
      expect(
        failure(() =>
          parseCsr(one + toPem(Buffer.from("3000", "hex"), "CERTIFICATE")),
        ),
      ).toMatchObject({
        reason: "multiple_blocks",
      });
    });

    it("text that is not exactly one CSR block", () => {
      const one = csrPem(makeCsrDer({ key: p256 }));
      expect(failure(() => parseCsr(""))).toMatchObject({
        code: "invalid_csr",
        reason: "no_block",
      });
      expect(failure(() => parseCsr("not a pem"))).toMatchObject({
        reason: "no_block",
      });
      expect(failure(() => parseCsr(`junk\n${one}`))).toMatchObject({
        reason: "malformed",
      });
      expect(failure(() => parseCsr(`${one}trailing`))).toMatchObject({
        reason: "malformed",
      });
      expect(
        failure(() =>
          parseCsr(
            one.replace("CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST"),
          ),
        ),
      ).toMatchObject({
        reason: "malformed",
      });
      expect(
        failure(() =>
          parseCsr(toPem(Buffer.from("3000", "hex"), "CERTIFICATE REQUEST")),
        ),
      ).toMatchObject({
        reason: "malformed",
      });
    });

    it("an oversize request", () => {
      const big = makeCsrDer({
        key: p256,
        subject: subjectDer({ CN: "a".repeat(30_000) }),
      });
      const pem = csrPem(big);
      expect(Buffer.byteLength(pem)).toBeGreaterThan(maximumCsrBytes);
      expect(failure(() => parseCsr(pem))).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "too_large",
      });
    });

    it("a bad signature", () => {
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, corruptSignature: true }))),
        ),
      ).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "bad_signature",
      });
      // Signed by another key.
      const other = leafKey({ type: "ec", curve: "prime256v1" });
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, signedBy: other }))),
        ),
      ).toMatchObject({
        reason: "bad_signature",
      });
      // A signature algorithm that does not fit the key (or is weak) never verifies.
      expect(
        failure(() =>
          parseCsr(
            csrPem(
              makeCsrDer({
                key: p256,
                signatureAlgorithm: seq(oid("1.2.840.113549.1.1.5"), derNull()),
              }),
            ),
          ),
        ),
      ).toMatchObject({ reason: "bad_signature" });
    });

    it("an SPKI that is not the canonical encoding of its key", () => {
      const rsa = leafKey({ type: "rsa", bits: 2048 });
      const [algorithm, bits] = children(parseDer(rsa.spkiDer));
      const padded = seq(
        (algorithm as Tlv).raw,
        bitString(
          Buffer.concat([(bits as Tlv).value.subarray(1), Buffer.from([0])]),
        ),
      );
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: rsa, spkiDer: padded }))),
        ),
      ).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "malformed_public_key",
      });
      // The canonical form is accepted, and the hash covers exactly that encoding.
      const parsed = parseCsr(csrPem(makeCsrDer({ key: rsa })));
      expect(parsed.spkiSha256).toBe(
        createHash("sha256").update(rsa.spkiDer).digest("hex"),
      );
      expect(parsed.spkiDer.equals(rsa.spkiDer)).toBe(true);
    });

    it("weak or irregular RSA keys", () => {
      expect(
        failure(() =>
          parseCsr(
            csrPem(makeCsrDer({ key: leafKey({ type: "rsa", bits: 1024 }) })),
          ),
        ),
      ).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "weak_rsa_key",
      });
      expect(
        failure(() =>
          parseCsr(
            csrPem(
              makeCsrDer({
                key: leafKey({ type: "rsa", bits: 2048, exponent: 3 }),
              }),
            ),
          ),
        ),
      ).toMatchObject({ reason: "invalid_rsa_exponent" });
      // Between 2048 and 8192 bits, but not an allowed size.
      expect(
        failure(() =>
          parseCsr(
            csrPem(makeCsrDer({ key: leafKey({ type: "rsa", bits: 2560 }) })),
          ),
        ),
      ).toEqual({
        code: "issuance_denied",
        status: 403,
        reason: "key_algorithm_not_permitted",
      });
    });

    it("RSA moduli that are even or have a small prime factor", () => {
      const rsaSpki = (modulus: bigint): Buffer =>
        seq(
          seq(oid(OID.rsaEncryption), derNull()),
          bitString(
            seq(
              unsignedInteger(
                Buffer.from(modulus.toString(16).padStart(512, "0"), "hex"),
              ),
              smallIntegerE(),
            ),
          ),
        );
      const base = (1n << 2047n) | 0x1234567890abcdefn;
      const evenCsr = makeCsrDer({ key: p256, spkiDer: rsaSpki(base & ~1n) });
      const smallPrime = (((3n << 2046n) / 3n) | 1n) * 3n;
      expect(smallPrime.toString(2).length).toBe(2048);
      const smallPrimeCsr = makeCsrDer({
        key: p256,
        spkiDer: rsaSpki(smallPrime),
      });
      expect(failure(() => parseCsr(csrPem(evenCsr)))).toMatchObject({
        reason: "invalid_rsa_modulus",
      });
      expect(failure(() => parseCsr(csrPem(smallPrimeCsr)))).toMatchObject({
        reason: "invalid_rsa_modulus",
      });
    });

    it("explicit EC parameters", () => {
      const explicitSpki = seq(
        seq(
          oid(OID.ecPublicKey),
          seq(
            smallInteger(1),
            seq(
              oid("1.2.840.10045.1.1"),
              unsignedInteger(Buffer.from("ff", "hex")),
            ),
          ),
        ),
        bitString(Buffer.concat([Buffer.from([4]), Buffer.alloc(64, 1)])),
      );
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, spkiDer: explicitSpki }))),
        ),
      ).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "explicit_ec_parameters",
      });
    });

    it("unnamed curves, DSA and unknown algorithms", () => {
      const k1 = leafKey({ type: "ec", curve: "secp256k1" });
      expect(failure(() => parseCsr(csrPem(makeCsrDer({ key: k1 }))))).toEqual({
        code: "issuance_denied",
        status: 403,
        reason: "key_algorithm_not_permitted",
      });
      const dsa = seq(
        seq(oid("1.2.840.10040.4.1")),
        bitString(Buffer.from([2, 1, 1])),
      );
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, spkiDer: dsa }))),
        ),
      ).toMatchObject({
        code: "invalid_csr",
        reason: "unsupported_key_algorithm",
      });
      const nullKey = seq(
        seq(oid(OID.ecPublicKey), derNull()),
        bitString(Buffer.alloc(65, 1)),
      );
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, spkiDer: nullKey }))),
        ),
      ).toMatchObject({
        reason: "malformed_public_key",
      });
    });

    it("compressed EC points", () => {
      // SPKI = SEQ{ algId, BIT STRING{ 00 04 x y } }; take the 65-byte point.
      const uncompressed = p256.spkiDer.subarray(p256.spkiDer.length - 65);
      const compressed = ECDH.convertKey(
        uncompressed,
        "prime256v1",
        undefined,
        undefined,
        "compressed",
      ) as Buffer;
      const compressedSpki = seq(
        seq(oid(OID.ecPublicKey), oid(OID.prime256v1)),
        bitString(compressed),
      );
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, spkiDer: compressedSpki }))),
        ),
      ).toMatchObject({
        code: "invalid_csr",
        reason: "malformed_public_key",
      });
    });

    it("attributes other than one extensionRequest", () => {
      const challenge = seq(
        oid("1.2.840.113549.1.9.7"),
        set(tlv(TAG.utf8String, Buffer.from("secret"))),
      );
      expect(
        failure(() =>
          parseCsr(
            csrPem(
              makeCsrDer({
                key: p256,
                extensions: [],
                attributes: [challenge],
              }),
            ),
          ),
        ),
      ).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "unsupported_attribute",
      });
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, attributes: [challenge] }))),
        ),
      ).toMatchObject({
        reason: "unsupported_attribute",
      });
      const twice = makeCsrDer({
        key: p256,
        extensions: [sanExtension({ dns: ["a.example.com"] })],
        attributes: [
          extensionRequest([sanExtension({ dns: ["b.example.com"] })]),
        ],
      });
      expect(failure(() => parseCsr(csrPem(twice)))).toMatchObject({
        reason: "unsupported_attribute",
      });
    });

    it("malformed extensions and duplicated extensions", () => {
      const dup = makeCsrDer({
        key: p256,
        extensions: [
          sanExtension({ dns: ["a.example.com"] }),
          sanExtension({ dns: ["b.example.com"] }),
        ],
      });
      expect(failure(() => parseCsr(csrPem(dup)))).toMatchObject({
        reason: "malformed_extension",
      });
      const bad = makeCsrDer({
        key: p256,
        extensions: [extension(EXT.keyUsage, true, Buffer.from("0400", "hex"))],
      });
      expect(failure(() => parseCsr(csrPem(bad)))).toMatchObject({
        reason: "malformed_extension",
      });
    });

    it("a version other than 0 and a multi-valued subject", () => {
      expect(
        failure(() => parseCsr(csrPem(makeCsrDer({ key: p256, version: 1 })))),
      ).toMatchObject({
        reason: "unsupported_version",
      });
      const multi = seq(
        set(
          seq(oid("2.5.4.10"), tlv(TAG.utf8String, Buffer.from("Corp"))),
          seq(oid("2.5.4.3"), tlv(TAG.utf8String, Buffer.from("cn"))),
        ),
      );
      expect(
        failure(() =>
          parseCsr(csrPem(makeCsrDer({ key: p256, subject: multi }))),
        ),
      ).toMatchObject({
        reason: "unsupported_subject",
      });
    });

    it("a reserved key through the hook", () => {
      const spkiSha256 = createHash("sha256")
        .update(p256.spkiDer)
        .digest("hex");
      const pem = csrPem(makeCsrDer({ key: p256 }));
      expect(
        failure(() =>
          parseCsr(pem, { isReservedKey: (hash) => hash === spkiSha256 }),
        ),
      ).toEqual({
        code: "invalid_csr",
        status: 400,
        reason: "reserved_key",
      });
      expect(parseCsr(pem, { isReservedKey: () => false }).spkiSha256).toBe(
        spkiSha256,
      );
    });
  });
});

const smallIntegerE = (): Buffer => unsignedInteger(Buffer.from([1, 0, 1]));

// Keep the unused import list honest for generateKeyPairSync-based helpers.
void generateKeyPairSync;
