import { describe, expect, it } from "vitest";
import {
  MAX_PAYLOAD_BYTES,
  duplicateKeys,
  environmentName,
  inspectPayload,
  isCanonicalBase64,
  parseDotEnv,
  parseJsonPayload,
  payloadBytes,
  rowError,
  toDotEnv,
  toJsonText,
  toPayload,
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

describe("toJsonText / parseJsonPayload", () => {
  it("round-trips rows through the wire format losslessly, including base64 entries", () => {
    const rows = [
      row({ id: "1", key: "username", value: "service-account", encoding: "utf8" }),
      row({ id: "2", key: "password", value: "c2VjcmV0", encoding: "base64" }),
    ];

    const text = toJsonText(rows);
    expect(JSON.parse(text)).toEqual(toPayload(rows));

    let n = 0;
    const result = parseJsonPayload(text, () => String(++n));
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.rows.map(({ key, value, encoding }) => ({ key, value, encoding }))).toEqual([
        { key: "username", value: "service-account", encoding: "utf8" },
        { key: "password", value: "c2VjcmV0", encoding: "base64" },
      ]);
    }
  });

  it("reports invalid JSON as an error rather than throwing, and produces no rows", () => {
    const result = parseJsonPayload("{ not json", () => "1");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("Invalid JSON");
    }
  });

  it("rejects a document that is not an object", () => {
    const result = parseJsonPayload("[1, 2, 3]", () => "1");
    expect(result.ok).toBe(false);
  });

  it("rejects a key outside the documented charset with a useful message", () => {
    const result = parseJsonPayload(
      JSON.stringify({ "bad key!": { encoding: "utf8", value: "x" } }),
      () => "1",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("bad key!");
    }
  });

  it("rejects an entry with the wrong shape", () => {
    const result = parseJsonPayload(JSON.stringify({ a: "just-a-string" }), () => "1");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("encoding=utf8|base64");
    }
  });

  it("rejects non-canonical base64 the same way the service does", () => {
    const result = parseJsonPayload(
      JSON.stringify({ a: { encoding: "base64", value: "abc" } }),
      () => "1",
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toContain("canonical base64");
    }
  });
});

describe("toDotEnv", () => {
  it("round-trips utf8 entries through .env losslessly", () => {
    const rows = [
      row({ id: "1", key: "HOST", value: "db.internal", encoding: "utf8" }),
      row({ id: "2", key: "EMPTY", value: "", encoding: "utf8" }),
      row({ id: "3", key: "PADDED", value: "  spaced  ", encoding: "utf8" }),
    ];

    const { text, lossyKeys } = toDotEnv(rows);
    expect(lossyKeys).toEqual([]);

    let n = 0;
    const roundTripped = parseDotEnv(text, () => String(++n));
    expect(roundTripped.map(({ key, value, encoding }) => ({ key, value, encoding }))).toEqual([
      { key: "HOST", value: "db.internal", encoding: "utf8" },
      { key: "EMPTY", value: "", encoding: "utf8" },
      { key: "PADDED", value: "  spaced  ", encoding: "utf8" },
    ]);
  });

  it("names base64 entries as lossy, and a .env round trip turns them into utf8", () => {
    const rows = [row({ id: "1", key: "TOKEN", value: "c2VjcmV0", encoding: "base64" })];

    const { text, lossyKeys } = toDotEnv(rows);
    expect(lossyKeys).toEqual(["TOKEN"]);

    const roundTripped = parseDotEnv(text, () => "1");
    expect(roundTripped).toEqual([{ id: "1", key: "TOKEN", value: "c2VjcmV0", encoding: "utf8" }]);
  });
});

describe("duplicate keys pasted via .env", () => {
  it("is detected the same way duplicate rows are", () => {
    const rows = parseDotEnv("A=1\nA=2", () => crypto.randomUUID());
    expect(duplicateKeys(rows)).toEqual(["A"]);
  });
});

describe("environmentName mirrors assertEnvironmentName", () => {
  it("accepts 1 to 64 lowercase letters, digits, and hyphens starting with a letter", () => {
    expect(environmentName.test("dev")).toBe(true);
    expect(environmentName.test("a")).toBe(true);
    expect(environmentName.test("staging-2")).toBe(true);
    expect(environmentName.test("a".repeat(64))).toBe(true);
  });

  it("rejects what the service rejects, no stricter and no looser", () => {
    expect(environmentName.test("")).toBe(false);
    expect(environmentName.test("Dev")).toBe(false);
    expect(environmentName.test("1dev")).toBe(false);
    expect(environmentName.test("-dev")).toBe(false);
    expect(environmentName.test("dev_prod")).toBe(false);
    expect(environmentName.test("a".repeat(65))).toBe(false);
  });
});
