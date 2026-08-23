import { describe, expect, it } from "vitest";
import {
  MAX_PAYLOAD_BYTES,
  inspectPayload,
  isCanonicalBase64,
  parseDotEnv,
  payloadBytes,
  rowError,
  type PayloadRow,
} from "./payload";

const row = (over: Partial<PayloadRow> = {}): PayloadRow => ({
  id: over.id ?? "1",
  key: over.key ?? "username",
  value: over.value ?? "service-account",
  encoding: over.encoding ?? "utf8",
});

describe("payload validation mirrors the service", () => {
  it("accepts the documented key charset and rejects anything else", () => {
    expect(rowError(row({ key: "a.b_c-1" }))).toBeUndefined();
    expect(rowError(row({ key: "has space" }))).toBeDefined();
    expect(rowError(row({ key: "" }))).toBeDefined();
  });

  it("requires canonical RFC 4648 base64 with padding", () => {
    expect(isCanonicalBase64("c2VjcmV0")).toBe(true);
    expect(isCanonicalBase64("Y29ycmVjdC1ob3JzZQ==")).toBe(true);
    // Missing padding is not canonical even though it decodes.
    expect(isCanonicalBase64("c2VjcmV")).toBe(false);
    expect(isCanonicalBase64("not base64!")).toBe(false);
  });

  it("measures the serialized request body, as the service does", () => {
    const rows = [row({ key: "k", value: "v" })];
    expect(payloadBytes(rows)).toBe(
      new TextEncoder().encode(JSON.stringify({ k: { encoding: "utf8", value: "v" } }))
        .length,
    );
  });

  it("flags an oversize payload against the 768,000 byte cap", () => {
    const rows = [row({ value: "x".repeat(MAX_PAYLOAD_BYTES) })];
    const problems = inspectPayload(rows);
    expect(problems.oversize).toBe(true);
    expect(problems.valid).toBe(false);
  });

  it("flags duplicate keys, which would silently collapse", () => {
    const problems = inspectPayload([
      row({ id: "1", key: "same" }),
      row({ id: "2", key: "same" }),
    ]);
    expect(problems.duplicates).toEqual(["same"]);
    expect(problems.valid).toBe(false);
  });

  it("refuses an empty payload rather than submitting an empty replacement", () => {
    expect(inspectPayload([]).valid).toBe(false);
  });
});

describe("parseDotEnv", () => {
  it("reads assignments, skips comments, and strips quotes", () => {
    let n = 0;
    const rows = parseDotEnv(
      ['# comment', 'export A=1', 'B="two"', "C='three'", "", "malformed"].join("\n"),
      () => String(++n),
    );
    expect(rows.map((r) => [r.key, r.value])).toEqual([
      ["A", "1"],
      ["B", "two"],
      ["C", "three"],
    ]);
  });

  it("never guesses base64, which would corrupt a delivered secret", () => {
    const rows = parseDotEnv("TOKEN=c2VjcmV0", () => "1");
    expect(rows[0]?.encoding).toBe("utf8");
  });
});
