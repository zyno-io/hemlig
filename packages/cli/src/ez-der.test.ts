import assert from "node:assert/strict";
import test from "node:test";
import {
  bitString, children, decodeBitString, decodeOid, decodeTime, DerError, ia5, oid, parseDer, printable, readTlv, seq,
  smallInt, time, tlv, uint, utf8, decodeUint, bigUint,
} from "./ez-der";

test("lengths: short, long forms and round trip through the strict reader", () => {
  assert.deepEqual([...tlv(0x04, Buffer.alloc(127))].slice(0, 2), [0x04, 127]);
  assert.deepEqual([...tlv(0x04, Buffer.alloc(128))].slice(0, 3), [0x04, 0x81, 128]);
  assert.deepEqual([...tlv(0x04, Buffer.alloc(256))].slice(0, 4), [0x04, 0x82, 1, 0]);
  assert.deepEqual([...tlv(0x04, Buffer.alloc(70000))].slice(0, 5), [0x04, 0x83, 1, 0x11, 0x70]);
  for (const n of [0, 1, 127, 128, 255, 256, 65535, 65536]) {
    assert.equal(parseDer(tlv(0x04, Buffer.alloc(n))).value.length, n);
  }
});

test("INTEGER is minimal and sign padded", () => {
  assert.equal(uint(Buffer.from([0x00, 0x00, 0x7f])).toString("hex"), "02017f");
  assert.equal(uint(Buffer.from([0x80])).toString("hex"), "02020080");
  assert.equal(uint(Buffer.alloc(3)).toString("hex"), "020100");
  assert.equal(smallInt(0).toString("hex"), "020100");
  assert.equal(smallInt(256).toString("hex"), "02020100");
  assert.equal(bigUint(255n).toString("hex"), "020200ff");
  assert.equal(decodeUint(parseDer(uint(Buffer.from([0x80, 0x01])))).toString("hex"), "8001");
});

test("OIDs: arcs and multi-byte components", () => {
  assert.equal(oid("1.2.840.113549.1.1.11").toString("hex"), "06092a864886f70d01010b");
  assert.equal(oid("2.5.4.3").toString("hex"), "0603550403");
  assert.equal(oid("1.3.6.1.4.1.311.21.7").toString("hex"), "06092b0601040182371507");
  for (const dotted of ["2.5.29.37.0", "1.2.840.10045.4.3.3", "2.16.840.1.101.3.4.1.42", "2.999.3"]) {
    assert.equal(decodeOid(parseDer(oid(dotted))), dotted);
  }
});

test("time: UTCTime before 2050, GeneralizedTime from 2050", () => {
  assert.equal(time(new Date("2049-12-31T23:59:59Z")).toString("latin1"), "\x17\x0d491231235959Z");
  assert.equal(time(new Date("2050-01-01T00:00:00Z")).toString("latin1"), "\x18\x0f20500101000000Z");
  assert.equal(time(new Date("1999-01-02T03:04:05Z")).toString("latin1"), "\x17\x0d990102030405Z");
  for (const iso of ["2049-12-31T23:59:59.000Z", "2050-01-01T00:00:00.000Z", "2026-11-25T01:02:03.000Z"]) {
    assert.equal(decodeTime(parseDer(time(new Date(iso)))).toISOString(), iso);
  }
  assert.throws(() => decodeTime(parseDer(tlv(0x17, Buffer.from("261301000000Z")))), DerError);
});

test("strings and bit strings", () => {
  assert.equal(utf8("é").toString("hex"), "0c02c3a9");
  assert.equal(printable("US").toString("hex"), "13025553");
  assert.throws(() => printable("a@b"));
  assert.throws(() => ia5("é"));
  assert.equal(decodeBitString(parseDer(bitString(Buffer.from([0x06]), 1))).unusedBits, 1);
});

test("the strict reader refuses indefinite, non-minimal, truncated and trailing input", () => {
  assert.throws(() => readTlv(Buffer.from("3080000000", "hex")), /Indefinite/);
  assert.throws(() => readTlv(Buffer.from("048105aa", "hex")), /Non-minimal/);
  assert.throws(() => readTlv(Buffer.from("04820005aa", "hex")), /Non-minimal/);
  assert.throws(() => readTlv(Buffer.from("0405aa", "hex")), /Truncated/);
  assert.throws(() => readTlv(Buffer.from("1f0100", "hex")), /Multi-byte/);
  assert.throws(() => parseDer(Buffer.from("040100ff", "hex")), /Trailing/);
  assert.throws(() => readTlv(Buffer.from("0485ffffffffff", "hex")), /too large/);
});

test("children slices share bytes with the parent (raw TLVs are what was signed)", () => {
  const inner = seq(smallInt(1), utf8("x"));
  const outer = seq(inner, smallInt(2));
  const [first] = children(parseDer(outer));
  assert.ok(first!.raw.equals(inner));
});
