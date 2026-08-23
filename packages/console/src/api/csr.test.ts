import { describe, expect, it } from "vitest";
import { inspectCsr } from "./csr";

describe("CSR pre-validation", () => {
  it("requires a PEM block", async () => {
    expect(await inspectCsr("")).toMatchObject({ message: expect.stringContaining("Paste") });
    expect(await inspectCsr("not a csr")).toMatchObject({
      message: expect.stringContaining("BEGIN"),
    });
  });

  it("refuses more than one request", async () => {
    const block =
      "-----BEGIN CERTIFICATE REQUEST-----\nAAAA\n-----END CERTIFICATE REQUEST-----";
    expect(await inspectCsr(`${block}\n${block}`)).toMatchObject({
      message: expect.stringContaining("exactly one"),
    });
  });

  it("refuses a request larger than the 32 KiB service limit", async () => {
    const oversize = `-----BEGIN CERTIFICATE REQUEST-----\n${"A".repeat(33 * 1024)}\n-----END CERTIFICATE REQUEST-----`;
    expect(await inspectCsr(oversize)).toMatchObject({
      message: expect.stringContaining("32 KiB"),
    });
  });

  it("rejects a PEM body that is not base64", async () => {
    const bad = "-----BEGIN CERTIFICATE REQUEST-----\n!!!!\n-----END CERTIFICATE REQUEST-----";
    expect(await inspectCsr(bad)).toBeDefined();
  });
});
