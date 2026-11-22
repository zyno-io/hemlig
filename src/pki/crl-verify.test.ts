import { createHash } from "node:crypto";
import { ApiError } from "../domain/errors";
import {
  crlPem,
  days,
  hours,
  makeCrl,
  makeRoot,
  newKey,
  rawReasonExtension,
  skiExtension,
  type CrlSpec,
  type TestCert,
} from "./__fixtures__/testkit";
import { seq, smallInteger, tlv } from "./asn1/der";
import {
  basicConstraintsValue,
  EXT,
  extension,
  keyUsageValue,
} from "./asn1/extensions";
import { encodeName } from "./asn1/names";
import { verifyRootCrl, maximumUploadedCrlBytes } from "./crl-verify";

const now = new Date();

let root: TestCert;
beforeAll(async () => {
  root = await makeRoot({
    subject: { O: "Test Corp", CN: "Test Offline Root" },
  });
});

const verify = (
  spec: Partial<CrlSpec> & { text?: string; issuer?: TestCert },
) =>
  verifyRootCrl({
    crl: spec.text ?? crlPem(makeCrl({ ca: root, ...spec })),
    issuer: (spec.issuer ?? root).cert,
    now,
  });

const reasonOf = (action: () => unknown): string | undefined => {
  try {
    action();
  } catch (error) {
    if (error instanceof ApiError) {
      expect(error.code).toBe("crl_invalid");
      expect(error.statusCode).toBe(400);
      return error.safeReason;
    }
    throw error;
  }
  return undefined;
};

describe("verifyRootCrl", () => {
  it("accepts a current, direct, full CRL as PEM or base64 DER", () => {
    const der = makeCrl({
      ca: root,
      number: 258n,
      entries: [
        {
          serialHex: "0a0b",
          date: new Date(now.getTime() - hours(2)),
          extensions: [],
        },
      ],
    });
    const fromPem = verifyRootCrl({ crl: crlPem(der), issuer: root.cert, now });
    const fromBase64 = verifyRootCrl({
      crl: der.toString("base64"),
      issuer: root.cert,
      now,
    });
    expect(fromBase64.sha256).toBe(fromPem.sha256);
    expect(fromPem.sha256).toBe(createHash("sha256").update(der).digest("hex"));
    expect(fromPem.numberHex).toBe("0000000000000000000000000000000000000102");
    expect(fromPem.numberHex).toHaveLength(40);
    expect(fromPem.entries.map((entry) => entry.serialHex)).toEqual(["0a0b"]);
    expect(fromPem.nextUpdate.getTime()).toBeGreaterThan(now.getTime());
  });

  it("parses a 20-octet CRL number into its canonical 40-digit form", () => {
    const high = Buffer.alloc(20, 0xff);
    expect(verify({ number: high }).numberHex).toBe("ff".repeat(20));
    expect(verify({ number: Buffer.from([0x7f]) }).numberHex).toBe(
      "7f".padStart(40, "0"),
    );
    // Numbers compare as strings once zero-padded.
    expect(
      verify({ number: 9n }).numberHex < verify({ number: 10n }).numberHex,
    ).toBe(true);
    expect(reasonOf(() => verify({ number: Buffer.alloc(21, 1) }))).toBe(
      "crl_number_too_large",
    );
  });

  it("matches the issuer canonically, whatever the string types and case", () => {
    const respelled = encodeName([
      { oid: "2.5.4.10", value: "test corp", kind: "printable" },
      { oid: "2.5.4.3", value: "TEST OFFLINE ROOT", kind: "printable" },
    ]);
    expect(reasonOf(() => verify({ issuerDer: respelled }))).toBeUndefined();
  });

  describe("rejects", () => {
    it("a CRL from another issuer", async () => {
      const other = await makeRoot({
        subject: { O: "Test Corp", CN: "Someone Else" },
      });
      expect(
        reasonOf(() => verify({ text: crlPem(makeCrl({ ca: other })) })),
      ).toBe("issuer_mismatch");
      const unrestricted = encodeName([
        { oid: "2.5.4.3", value: "Rót", kind: "utf8" },
      ]);
      expect(reasonOf(() => verify({ issuerDer: unrestricted }))).toBe(
        "issuer_mismatch",
      );
    });

    it("a bad signature", async () => {
      const stranger = await newKey("ECDSA_P384");
      expect(reasonOf(() => verify({ corruptSignature: true }))).toBe(
        "bad_signature",
      );
      expect(reasonOf(() => verify({ signedBy: stranger }))).toBe(
        "bad_signature",
      );
    });

    it("a missing or mismatched AKI", () => {
      expect(reasonOf(() => verify({ omitAki: true }))).toBe("missing_aki");
      expect(reasonOf(() => verify({ akiBytes: Buffer.alloc(20, 3) }))).toBe(
        "aki_mismatch",
      );
    });

    it("an expired CRL", () => {
      expect(
        reasonOf(() =>
          verify({
            thisUpdate: new Date(now.getTime() - days(10)),
            nextUpdate: new Date(now.getTime() - hours(1)),
          }),
        ),
      ).toBe("expired");
    });

    it("a future thisUpdate, with five minutes of tolerance", () => {
      expect(
        reasonOf(() =>
          verify({ thisUpdate: new Date(now.getTime() + hours(1)) }),
        ),
      ).toBe("this_update_in_future");
      expect(
        reasonOf(() =>
          verify({ thisUpdate: new Date(now.getTime() + 4 * 60_000) }),
        ),
      ).toBeUndefined();
    });

    it("a missing nextUpdate, or one more than 400 days out", () => {
      expect(reasonOf(() => verify({ nextUpdate: null }))).toBe(
        "missing_next_update",
      );
      const thisUpdate = new Date(now.getTime() - hours(1));
      expect(
        reasonOf(() =>
          verify({
            thisUpdate,
            nextUpdate: new Date(thisUpdate.getTime() + days(401)),
          }),
        ),
      ).toBe("validity_too_long");
      expect(
        reasonOf(() =>
          verify({
            thisUpdate,
            nextUpdate: new Date(thisUpdate.getTime() + days(399)),
          }),
        ),
      ).toBeUndefined();
    });

    it("an IssuingDistributionPoint", () => {
      expect(
        reasonOf(() =>
          verify({
            extraExtensions: [
              extension(EXT.issuingDistributionPoint, true, seq()),
            ],
          }),
        ),
      ).toBe("issuing_distribution_point");
      expect(
        reasonOf(() =>
          verify({
            extraExtensions: [
              extension(EXT.issuingDistributionPoint, false, seq()),
            ],
          }),
        ),
      ).toBe("issuing_distribution_point");
    });

    it("a delta CRL indicator or FreshestCRL", () => {
      expect(
        reasonOf(() =>
          verify({
            extraExtensions: [
              extension(EXT.deltaCrlIndicator, true, smallInteger(1)),
            ],
          }),
        ),
      ).toBe("delta_crl");
      expect(
        reasonOf(() =>
          verify({
            extraExtensions: [extension(EXT.freshestCrl, false, seq())],
          }),
        ),
      ).toBe("delta_crl");
    });

    it("removeFromCRL entries", () => {
      expect(
        reasonOf(() =>
          verify({
            entries: [{ serialHex: "01", extensions: [rawReasonExtension(8)] }],
          }),
        ),
      ).toBe("remove_from_crl");
      // certificateHold is accepted and listed.
      const held = verify({
        entries: [{ serialHex: "01", extensions: [rawReasonExtension(6)] }],
      });
      expect(held.entries[0]?.reason).toBe(6);
    });

    it("entries with a certificateIssuer", () => {
      const issuer = extension(
        EXT.certificateIssuer,
        true,
        seq(tlv(0xa4, seq())),
      );
      expect(
        reasonOf(() =>
          verify({ entries: [{ serialHex: "01", extensions: [issuer] }] }),
        ),
      ).toBe("indirect_crl");
    });

    it("an unknown critical extension, in the CRL or in an entry", () => {
      expect(
        reasonOf(() =>
          verify({ extraExtensions: [extension("1.2.3.4.5", true, seq())] }),
        ),
      ).toBe("unrecognized_critical_extension");
      expect(
        reasonOf(() =>
          verify({
            entries: [
              {
                serialHex: "01",
                extensions: [extension("1.2.3.4.5", true, seq())],
              },
            ],
          }),
        ),
      ).toBe("unrecognized_critical_extension");
      expect(
        reasonOf(() =>
          verify({ extraExtensions: [extension("1.2.3.4.5", false, seq())] }),
        ),
      ).toBeUndefined();
    });

    it("an oversize CRL", () => {
      const padding = extension(
        "1.2.3.4.5",
        false,
        tlv(0x04, Buffer.alloc(maximumUploadedCrlBytes, 1)),
      );
      const der = makeCrl({ ca: root, extraExtensions: [padding] });
      expect(der.length).toBeGreaterThan(maximumUploadedCrlBytes);
      expect(reasonOf(() => verify({ text: crlPem(der) }))).toBe("too_large");
      expect(reasonOf(() => verify({ text: der.toString("base64") }))).toBe(
        "too_large",
      );
      expect(
        reasonOf(() =>
          verify({ text: "A".repeat(maximumUploadedCrlBytes * 2) }),
        ),
      ).toBe("too_large");
    });

    it("a v1 CRL or one without a CRL number", () => {
      expect(reasonOf(() => verify({ version: null }))).toBe("not_v2");
      expect(reasonOf(() => verify({ number: null }))).toBe(
        "missing_crl_number",
      );
    });

    it("multiple CRLs, garbage and an issuer that cannot sign CRLs", async () => {
      const one = crlPem(makeCrl({ ca: root }));
      expect(reasonOf(() => verify({ text: one + one }))).toBe("multiple_crls");
      expect(reasonOf(() => verify({ text: "not a crl" }))).toBe("malformed");
      expect(
        reasonOf(() =>
          verify({
            text: "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n",
          }),
        ),
      ).toBe("malformed");
      const noCrlSign = await makeRoot({
        subject: { O: "Test Corp", CN: "No CRL Sign" },
        extensions: (k) => [
          extension(EXT.basicConstraints, true, basicConstraintsValue(true)),
          extension(EXT.keyUsage, true, keyUsageValue(["keyCertSign"])),
          skiExtension(k),
        ],
      });
      expect(
        reasonOf(() =>
          verifyRootCrl({
            crl: crlPem(makeCrl({ ca: noCrlSign })),
            issuer: noCrlSign.cert,
            now,
          }),
        ),
      ).toBe("issuer_cannot_sign_crl");
    });
  });
});
