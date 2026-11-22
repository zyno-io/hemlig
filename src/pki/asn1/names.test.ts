import { seq, tlv } from "./der";
import {
  decodeName,
  decodeNameConstraints,
  decodeSubjectAltName,
  encodeName,
  encodeNameConstraints,
  encodeSubjectAltName,
  formatCidr,
  ipFromBytes,
  ipToBytes,
  parseCidr,
} from "./names";

describe("asn1 names", () => {
  it("encodes and decodes a Name with per-attribute string types", () => {
    const der = encodeName([
      { oid: "2.5.4.6", value: "US", kind: "printable" },
      { oid: "2.5.4.3", value: "Example CA", kind: "utf8" },
    ]);
    expect(der.toString("hex")).toBe(
      "3022310b3009060355040613025553311330110603550403" +
        "0c0a4578616d706c65204341",
    );
    expect(decodeName(der)).toEqual([
      [{ oid: "2.5.4.6", value: "US", kind: "printable" }],
      [{ oid: "2.5.4.3", value: "Example CA", kind: "utf8" }],
    ]);
  });

  it("converts IP addresses both ways", () => {
    expect(ipToBytes("10.1.2.3").toString("hex")).toBe("0a010203");
    expect(ipFromBytes(ipToBytes("fd00::1"))).toBe("fd00::1");
    expect(ipFromBytes(ipToBytes("2001:db8:0:0:1:0:0:1"))).toBe(
      "2001:db8::1:0:0:1",
    );
    expect(ipFromBytes(ipToBytes("::ffff:1.2.3.4"))).toBe("::ffff:102:304");
    expect(ipFromBytes(ipToBytes("::"))).toBe("::");
    expect(() => ipToBytes("300.1.1.1")).toThrow();
    expect(() => ipToBytes("fe80::1%eth0")).toThrow();
    expect(formatCidr(parseCidr("10.1.2.3/8"))).toBe("10.0.0.0/8");
    expect(() => parseCidr("10.0.0.0/33")).toThrow();
  });

  it("round-trips SubjectAltName entries and reports unsupported types", () => {
    const der = encodeSubjectAltName({
      dns: ["a.example.com"],
      ip: ["10.0.0.1", "fd00::2"],
      uri: ["spiffe://x/y"],
    });
    expect(decodeSubjectAltName(der)).toEqual({
      dns: ["a.example.com"],
      ip: ["10.0.0.1", "fd00::2"],
      uri: ["spiffe://x/y"],
      email: [],
      unsupported: [],
    });
    const other = seq(
      tlv(0x81, Buffer.from("a@b.c")),
      tlv(0xa0, Buffer.from([6, 1, 0])),
    );
    expect(decodeSubjectAltName(other)).toMatchObject({
      email: ["a@b.c"],
      unsupported: ["otherName"],
    });
    expect(() =>
      decodeSubjectAltName(seq(tlv(0x87, Buffer.alloc(3)))),
    ).toThrow();
  });

  it("round-trips NameConstraints", () => {
    const constraints = {
      permitted: [
        { type: "dns" as const, value: "example.com" },
        { type: "ip" as const, value: "10.0.0.0/8" },
        { type: "ip" as const, value: "fd00::/8" },
        { type: "uri" as const, value: ".example.com" },
      ],
      excluded: [{ type: "dns" as const, value: "bad.example.com" }],
    };
    const der = encodeNameConstraints(constraints);
    expect(decodeNameConstraints(der)).toEqual(constraints);
    expect(der[0]).toBe(0x30);
  });
});
