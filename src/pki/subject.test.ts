import { encodeName } from "./asn1/names";
import { seq, set, tlv, oid, TAG } from "./asn1/der";
import {
  buildCaSubject,
  canonicalSubjectKey,
  identityRootSubjectKey,
  matchesIdentityRoot,
  parseRestrictedName,
  SubjectError,
  SUBJECT_OID,
} from "./subject";

const name = (
  ...attributes: { oid: string; value: string; tag: number }[]
): Buffer =>
  seq(
    ...attributes.map((a) =>
      set(seq(oid(a.oid), tlv(a.tag, Buffer.from(a.value, "utf8")))),
    ),
  );

const reason = (
  der: Buffer,
  kind: "hemlig" | "external" = "external",
): string | undefined => {
  try {
    parseRestrictedName(der, kind);
    return undefined;
  } catch (error) {
    return error instanceof SubjectError ? error.reason : "other";
  }
};

describe("restricted subject form", () => {
  it("encodes Hemlig subjects in the order C, ST, L, O, OU, CN with C as PrintableString", () => {
    const built = buildCaSubject({
      CN: "Issuing CA",
      OU: "Platform",
      O: "Example Corp",
      L: "Oslo",
      ST: "Oslo",
      C: "NO",
    });
    expect(
      built.der.equals(
        encodeName([
          { oid: SUBJECT_OID.C, value: "NO", kind: "printable" },
          { oid: SUBJECT_OID.ST, value: "Oslo", kind: "utf8" },
          { oid: SUBJECT_OID.L, value: "Oslo", kind: "utf8" },
          { oid: SUBJECT_OID.O, value: "Example Corp", kind: "utf8" },
          { oid: SUBJECT_OID.OU, value: "Platform", kind: "utf8" },
          { oid: SUBJECT_OID.CN, value: "Issuing CA", kind: "utf8" },
        ]),
      ),
    ).toBe(true);
    expect(
      built.der.includes(Buffer.from([TAG.printableString, 2, 0x4e, 0x4f])),
    ).toBe(true);
    expect(parseRestrictedName(built.der, "hemlig").key).toBe(built.key);
  });

  it("gives PrintableString and UTF8String one key, ignoring case and whitespace runs", () => {
    const printable = name(
      { oid: SUBJECT_OID.O, value: "Example Corp", tag: TAG.printableString },
      { oid: SUBJECT_OID.CN, value: "Root CA 1", tag: TAG.printableString },
    );
    const utf8 = name(
      { oid: SUBJECT_OID.O, value: "EXAMPLE CORP", tag: TAG.utf8String },
      { oid: SUBJECT_OID.CN, value: "root ca 1", tag: TAG.utf8String },
    );
    const ia5 = name(
      { oid: SUBJECT_OID.O, value: "example corp", tag: TAG.ia5String },
      { oid: SUBJECT_OID.CN, value: "Root CA 1", tag: TAG.ia5String },
    );
    const keys = [printable, utf8, ia5].map(
      (der) => parseRestrictedName(der).key,
    );
    expect(new Set(keys).size).toBe(1);
    expect(keys[0]).toBe(
      canonicalSubjectKey([
        { oid: SUBJECT_OID.O, value: "Example Corp" },
        { oid: SUBJECT_OID.CN, value: "Root CA 1" },
      ]),
    );
    expect(buildCaSubject({ O: "Example Corp", CN: "Root CA 1" }).key).toBe(
      keys[0],
    );
    // Order matters and the attribute type is part of the key.
    expect(canonicalSubjectKey([{ oid: SUBJECT_OID.CN, value: "a" }])).not.toBe(
      canonicalSubjectKey([{ oid: SUBJECT_OID.O, value: "a" }]),
    );
  });

  it("refuses non-ASCII values", () => {
    expect(
      reason(
        name({ oid: SUBJECT_OID.CN, value: "Café CA", tag: TAG.utf8String }),
      ),
    ).toBe("non_ascii");
    expect(
      reason(
        name({ oid: SUBJECT_OID.CN, value: "tab\there", tag: TAG.utf8String }),
      ),
    ).toBe("non_ascii");
  });

  it("refuses multi-valued RDNs", () => {
    const multi = seq(
      set(
        seq(oid(SUBJECT_OID.O), tlv(TAG.utf8String, Buffer.from("Corp"))),
        seq(oid(SUBJECT_OID.CN), tlv(TAG.utf8String, Buffer.from("CA"))),
      ),
    );
    expect(reason(multi)).toBe("multi_valued_rdn");
  });

  it("refuses leading, trailing and doubled spaces", () => {
    for (const value of [" lead", "trail ", "dou  ble"]) {
      expect(
        reason(name({ oid: SUBJECT_OID.CN, value, tag: TAG.utf8String })),
      ).toBe("space_not_allowed");
      expect(() => buildCaSubject({ CN: value })).toThrow(/restricted form/);
    }
    expect(() => buildCaSubject({ CN: "Café" })).toThrow(/restricted form/);
  });

  it("refuses unsupported string types, empty names and malformed names", () => {
    expect(
      reason(
        name({ oid: SUBJECT_OID.CN, value: "x", tag: TAG.generalizedTime }),
      ),
    ).toBe("unsupported_string_type");
    expect(reason(name({ oid: SUBJECT_OID.CN, value: "x", tag: 0x14 }))).toBe(
      "unsupported_string_type",
    ); // TeletexString
    expect(reason(name({ oid: SUBJECT_OID.CN, value: "x", tag: 0x1e }))).toBe(
      "unsupported_string_type",
    ); // BMPString
    expect(reason(seq())).toBe("empty_name");
    expect(reason(Buffer.from("3003020100", "hex"))).toBe("malformed_name");
  });

  it("limits Hemlig subjects to C, ST, L, O, OU and CN but lets external names carry DC", () => {
    const dc = name(
      {
        oid: "0.9.2342.19200300.100.1.25",
        value: "example",
        tag: TAG.ia5String,
      },
      { oid: SUBJECT_OID.CN, value: "Root", tag: TAG.utf8String },
    );
    expect(reason(dc, "hemlig")).toBe("attribute_not_allowed");
    expect(reason(dc, "external")).toBeUndefined();
    expect(() => buildCaSubject({ CN: "" })).toThrow();
    expect(() => buildCaSubject({} as never)).toThrow();
  });
});

describe("identity root comparison (layer 6)", () => {
  it("matches the fixed subject, stored subject, SPKI and fingerprint", () => {
    const fixed = buildCaSubject({ CN: "Hemlig prod Issuing Root" });
    expect(fixed.key).toBe(identityRootSubjectKey("prod"));
    // Case and whitespace folding mean a look-alike subject is reserved too.
    expect(
      matchesIdentityRoot(
        { subjectKey: buildCaSubject({ CN: "HEMLIG PROD ISSUING ROOT" }).key },
        "prod",
      ),
    ).toBe(true);
    expect(
      matchesIdentityRoot(
        {
          subjectKey: buildCaSubject({ CN: "Hemlig staging Issuing Root" }).key,
        },
        "prod",
      ),
    ).toBe(false);
    const identity = { subjectKey: "a", spkiSha256: "b", fingerprint: "c" };
    expect(matchesIdentityRoot({ subjectKey: "a" }, "prod", identity)).toBe(
      true,
    );
    expect(
      matchesIdentityRoot(
        { subjectKey: "z", spkiSha256: "b" },
        "prod",
        identity,
      ),
    ).toBe(true);
    expect(
      matchesIdentityRoot(
        { subjectKey: "z", fingerprint: "c" },
        "prod",
        identity,
      ),
    ).toBe(true);
    expect(
      matchesIdentityRoot(
        { subjectKey: "z", spkiSha256: "q", fingerprint: "q" },
        "prod",
        identity,
      ),
    ).toBe(false);
    expect(matchesIdentityRoot({ subjectKey: "z" }, "prod")).toBe(false);
  });
});
