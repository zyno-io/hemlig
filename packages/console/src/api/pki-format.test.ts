import { describe, expect, it } from "vitest";
import {
  daysUntil,
  ED25519_WARNING,
  EXTERNAL_ROOT_RECOMMENDATION,
  fileToPemOrBase64,
  formatDuration,
  inspectPem,
  isoToLocalInput,
  localInputToIso,
  parseDuration,
  pemBodiesEqual,
} from "./pki-format";

const block = (label: string, body = "AAAA"): string =>
  `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----\n`;

describe("durations", () => {
  it("parses each suffix", () => {
    expect(parseDuration("90d")).toBe(7_776_000);
    expect(parseDuration("2h")).toBe(7200);
    expect(parseDuration("5m")).toBe(300);
    expect(parseDuration("45s")).toBe(45);
  });

  it("rejects malformed durations", () => {
    for (const bad of ["", "90", "d", "1w", "-1d", "1.5h", "1d2h"]) {
      expect(parseDuration(bad)).toBeUndefined();
    }
  });

  it("round-trips", () => {
    for (const seconds of [45, 300, 3600, 7200, 86_400, 7_776_000, 90]) {
      expect(parseDuration(formatDuration(seconds))).toBe(seconds);
    }
    expect(formatDuration(7_776_000)).toBe("90d");
    expect(formatDuration(90)).toBe("90s");
  });
});

describe("dates", () => {
  it("round-trips a datetime-local value through ISO", () => {
    const iso = localInputToIso("2026-11-23T10:30");
    expect(iso).toBeDefined();
    expect(isoToLocalInput(iso)).toBe("2026-11-23T10:30");
  });

  it("treats empty and invalid input as absent", () => {
    expect(localInputToIso("")).toBeUndefined();
    expect(localInputToIso("nope")).toBeUndefined();
    expect(isoToLocalInput(undefined)).toBe("");
  });

  it("counts whole days", () => {
    const now = new Date("2026-11-01T00:00:00Z");
    expect(daysUntil("2026-11-30T00:00:00Z", now)).toBe(29);
    expect(daysUntil("2026-10-31T00:00:00Z", now)).toBe(-1);
  });
});

describe("constants", () => {
  it("carry the documented texts", () => {
    expect(ED25519_WARNING).toContain("Prefer P-256 or P-384");
    expect(EXTERNAL_ROOT_RECOMMENDATION).toMatch(/^An external offline root is strongly recommended/);
  });
});

describe("inspectPem", () => {
  const privateKeys = [
    "PRIVATE KEY",
    "RSA PRIVATE KEY",
    "EC PRIVATE KEY",
    "ENCRYPTED PRIVATE KEY",
    "OPENSSH PRIVATE KEY",
  ];

  it.each(privateKeys)("rejects a %s anywhere in the text", (label) => {
    for (const kind of ["certificate", "chain", "csr", "crl"] as const) {
      const text = `${block("CERTIFICATE")}\n${block(label)}`;
      const result = inspectPem(text, kind);
      expect(result.privateKey).toBe(true);
      expect(result.problems.join(" ")).toContain("private key");
    }
  });

  it("requires exactly one block for a certificate", () => {
    expect(inspectPem(block("CERTIFICATE"), "certificate").problems).toEqual([]);
    expect(
      inspectPem(block("CERTIFICATE") + block("CERTIFICATE"), "certificate").problems,
    ).not.toEqual([]);
    expect(inspectPem("", "certificate").problems).not.toEqual([]);
  });

  it("accepts one or more blocks for a chain", () => {
    expect(inspectPem(block("CERTIFICATE"), "chain").problems).toEqual([]);
    expect(
      inspectPem(block("CERTIFICATE") + block("CERTIFICATE"), "chain").problems,
    ).toEqual([]);
    expect(inspectPem(block("X509 CRL"), "chain").problems).not.toEqual([]);
  });

  it("accepts a CSR of any key type under either label", () => {
    // An EC CSR must pass: the RSA-only inspectCsr is deliberately not reused.
    expect(inspectPem(block("CERTIFICATE REQUEST", "ECEC"), "csr").problems).toEqual([]);
    expect(inspectPem(block("NEW CERTIFICATE REQUEST"), "csr").problems).toEqual([]);
    expect(inspectPem(block("CERTIFICATE"), "csr").problems).not.toEqual([]);
  });

  it("accepts a CRL as PEM or base64 DER", () => {
    expect(inspectPem(block("X509 CRL"), "crl").problems).toEqual([]);
    expect(inspectPem("MIIBAAoBAA==\n", "crl").problems).toEqual([]);
    expect(inspectPem("not base64!!", "crl").problems).not.toEqual([]);
    expect(inspectPem(block("CERTIFICATE"), "crl").problems).not.toEqual([]);
  });

  it("rejects oversized input", () => {
    const big = block("CERTIFICATE", "A".repeat(33_000));
    expect(inspectPem(big, "certificate").problems.join(" ")).toContain("32 KiB");
    expect(inspectPem("A".repeat(720_001), "crl").problems.join(" ")).toContain("too large");
  });
});

describe("pemBodiesEqual", () => {
  it("ignores wrapping and whitespace", () => {
    expect(
      pemBodiesEqual(
        "-----BEGIN CERTIFICATE-----\nAAAA\nBBBB\n-----END CERTIFICATE-----\n",
        "\n-----BEGIN CERTIFICATE-----\r\nAAAABBBB\r\n-----END CERTIFICATE-----",
      ),
    ).toBe(true);
  });

  it("detects a different body", () => {
    expect(pemBodiesEqual(block("CERTIFICATE", "AAAA"), block("CERTIFICATE", "AAAB"))).toBe(false);
  });
});

describe("fileToPemOrBase64", () => {
  const file = (bytes: BlobPart, name = "f"): File => new File([bytes], name);

  it("passes PEM text through", async () => {
    const result = await fileToPemOrBase64(file(block("CERTIFICATE")), "certificate");
    expect(result.text).toBe(block("CERTIFICATE"));
  });

  it("wraps a DER certificate as PEM", async () => {
    const result = await fileToPemOrBase64(
      file(new Uint8Array([0x30, 0x82, 0x01, 0xff])),
      "certificate",
    );
    expect(result.text).toBe(
      "-----BEGIN CERTIFICATE-----\nMIIB/w==\n-----END CERTIFICATE-----\n",
    );
  });

  it("turns a DER CRL into base64", async () => {
    const result = await fileToPemOrBase64(
      file(new Uint8Array([0x30, 0xff, 0x00])),
      "crl",
    );
    expect(result.text).toBe("MP8A");
  });

  it("refuses a private key in PEM or in raw bytes", async () => {
    const pem = await fileToPemOrBase64(file(block("EC PRIVATE KEY")), "certificate");
    expect(pem.problem).toContain("private key");
    expect(pem.text).toBeUndefined();

    const raw = new Uint8Array([
      0x30,
      0x82,
      ...new TextEncoder().encode("xx PRIVATE KEY-----"),
    ]);
    const der = await fileToPemOrBase64(file(raw), "crl");
    expect(der.problem).toContain("private key");
  });

  it("refuses an oversized file", async () => {
    const result = await fileToPemOrBase64(file("A".repeat(40_000)), "certificate");
    expect(result.problem).toContain("too large");
  });
});
