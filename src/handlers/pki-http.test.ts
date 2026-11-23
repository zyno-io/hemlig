import {
  assertPkiRole,
  binaryResponse,
  notModified,
  parseIfNoneMatch,
  parseObjectBody,
  requireIdempotencyKey,
  requireIfMatch,
} from "./pki-http";

describe("pki-http", () => {
  it("decodes base64 bodies and caps them at 1 MiB", () => {
    expect(parseObjectBody({ body: JSON.stringify({ a: 1 }) })).toEqual({
      a: 1,
    });
    expect(
      parseObjectBody({
        body: Buffer.from('{"a":2}').toString("base64"),
        isBase64Encoded: true,
      }),
    ).toEqual({ a: 2 });
    expect(parseObjectBody({})).toEqual({});
    expect(() => parseObjectBody({ body: "[]" })).toThrow();
    expect(() => parseObjectBody({ body: "{" })).toThrow();
    const big = JSON.stringify({ x: "a".repeat(1024 * 1024) });
    expect(() => parseObjectBody({ body: big })).toThrow(
      expect.objectContaining({ details: { reason: "body_too_large" } }),
    );
  });

  it("validates the headers", () => {
    expect(() => requireIdempotencyKey(undefined)).toThrow();
    expect(() => requireIdempotencyKey("short")).toThrow();
    expect(requireIdempotencyKey("long-enough-key")).toBe("long-enough-key");
    expect(() => requireIfMatch(undefined)).toThrow();
    expect(requireIfMatch('W/"pkv-1"')).toBe("pkv-1");
    expect(parseIfNoneMatch('"a", W/"b", *')).toEqual(["a", "b", "*"]);
    expect(parseIfNoneMatch(undefined)).toEqual([]);
  });

  it("builds a base64 CRL response with the hash as ETag", () => {
    const response = binaryResponse(
      Buffer.from([0xff, 0x00]),
      "ca-x-1.crl",
      "abc",
    );
    expect(response).toMatchObject({
      statusCode: 200,
      isBase64Encoded: true,
      body: "/wA=",
      headers: {
        "content-type": "application/pkix-crl",
        "cache-control": "no-store",
        etag: "abc",
        "content-disposition": 'attachment; filename="ca-x-1.crl"',
      },
    });
  });

  it("adds the CRL metadata headers only when given", () => {
    const crl = {
      number: "7",
      thisUpdate: "2026-11-01T00:00:00.000Z",
      nextUpdate: "2026-11-08T00:00:00.000Z",
    };
    const expected = {
      "hemlig-crl-number": "7",
      "hemlig-crl-this-update": crl.thisUpdate,
      "hemlig-crl-next-update": crl.nextUpdate,
    };
    expect(binaryResponse(Buffer.alloc(1), "f.crl", "abc", crl).headers).toMatchObject(expected);
    expect(notModified("abc", crl)).toMatchObject({
      statusCode: 304,
      headers: { etag: "abc", ...expected },
    });
    expect(binaryResponse(Buffer.alloc(1), "f.crl", "abc").headers).not.toHaveProperty("hemlig-crl-number");
    expect(notModified("abc").headers).not.toHaveProperty("hemlig-crl-number");
  });

  it("falls back to the administrator when no role is configured", () => {
    expect(() => assertPkiRole({}, {}, "ca-admin")).not.toThrow();
    expect(() =>
      assertPkiRole({ roles: ["x"] }, { adminPkiCaRole: "y" }, "ca-admin"),
    ).toThrow(expect.objectContaining({ statusCode: 403 }));
    expect(() =>
      assertPkiRole({ roles: ["y"] }, { adminPkiCaRole: "y" }, "ca-admin"),
    ).not.toThrow();
    expect(() =>
      assertPkiRole({}, { adminPkiCaRole: "y" }, "read"),
    ).not.toThrow();
  });
});
