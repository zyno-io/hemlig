import {
  children,
  decodeOid,
  decodeTime,
  DerError,
  encodeTime,
  oid,
  parseDer,
  readTlv,
  seq,
  smallInteger,
  TAG,
  unsignedInteger,
} from "./der";

describe("der", () => {
  it("round-trips object identifiers, including large arcs", () => {
    for (const value of [
      "1.2.840.113549.1.1.11",
      "2.5.29.19",
      "1.3.101.112",
      "2.25.123456789012345",
    ]) {
      expect(decodeOid(parseDer(oid(value)))).toBe(value);
    }
    expect(oid("2.5.29.19").toString("hex")).toBe("0603551d13");
  });

  it("encodes integers minimally with sign padding", () => {
    expect(unsignedInteger(Buffer.from([0x00, 0x7f])).toString("hex")).toBe(
      "02017f",
    );
    expect(unsignedInteger(Buffer.from([0x80])).toString("hex")).toBe(
      "02020080",
    );
    expect(smallInteger(0).toString("hex")).toBe("020100");
    expect(smallInteger(2).toString("hex")).toBe("020102");
  });

  it("uses UTCTime before 2050 and GeneralizedTime from 2050", () => {
    const before = encodeTime(new Date("2049-12-31T23:59:59Z"));
    expect(before[0]).toBe(TAG.utcTime);
    expect(before.subarray(2).toString("ascii")).toBe("491231235959Z");
    const from = encodeTime(new Date("2050-01-01T00:00:00Z"));
    expect(from[0]).toBe(TAG.generalizedTime);
    expect(from.subarray(2).toString("ascii")).toBe("20500101000000Z");
    expect(decodeTime(parseDer(before)).toISOString()).toBe(
      "2049-12-31T23:59:59.000Z",
    );
    expect(decodeTime(parseDer(from)).toISOString()).toBe(
      "2050-01-01T00:00:00.000Z",
    );
    // RFC 5280: UTCTime years 50-99 are 19xx.
    expect(
      decodeTime(
        parseDer(Buffer.from("170d3530303130313030303030305a", "hex")),
      ).getUTCFullYear(),
    ).toBe(1950);
  });

  it("rejects indefinite, non-minimal and truncated lengths and trailing bytes", () => {
    expect(() => readTlv(Buffer.from("308000000000", "hex"))).toThrow(DerError);
    expect(() => readTlv(Buffer.from("30810100", "hex"))).toThrow(DerError);
    expect(() => readTlv(Buffer.from("3005020101", "hex"))).toThrow(DerError);
    expect(() => parseDer(Buffer.from("02010100", "hex"))).toThrow(DerError);
    expect(
      children(parseDer(seq(smallInteger(1), smallInteger(2)))),
    ).toHaveLength(2);
  });
});
