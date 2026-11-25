import { describe, expect, it } from "vitest";
import { ezActivationCommands, ezRenewCrlCommands, fileStem, shellArg } from "./ez-commands";

const SPKI = "AB".repeat(32);
const ca = { caId: "ca-0a1b", environment: "prod", name: "issuing-1", spkiSha256: SPKI };

describe("shellArg", () => {
  it("leaves plain values bare and quotes the rest", () => {
    expect(shellArg("ca-1")).toBe("ca-1");
    expect(shellArg("a b")).toBe("'a b'");
    expect(shellArg("it's $(x)")).toBe("'it'\\''s $(x)'");
  });
});

describe("fileStem", () => {
  it("strips path and shell characters", () => {
    expect(fileStem("../a b;c")).toBe("a-b-c");
    expect(fileStem("///")).toBe("ca");
  });
});

describe("ezActivationCommands", () => {
  it("emits commands matching the CLI flags", () => {
    const c = ezActivationCommands(ca, "https://hemlig.example.com");
    expect(c?.login).toBe("hemlig login --console-url https://hemlig.example.com");
    expect(c?.sign).toBe("hemlig pki ez sign-cert ca-0a1b --environment prod");
    expect(c?.offlineSign).toBe(
      `hemlig pki ez sign-cert ca-0a1b --offline --csr issuing-1.csr.pem --expect-spki-sha256 ${SPKI.toLowerCase()} --out issuing-1.pem --chain-out root.pem --crl-out root.crl.pem`,
    );
    expect(c?.activate).toBe(
      "hemlig pki ez activate ca-0a1b --environment prod --certificate issuing-1.pem --chain root.pem --crl root.crl.pem",
    );
  });

  it("refuses unsafe identifiers or a bad hash", () => {
    expect(ezActivationCommands({ ...ca, caId: "a; rm -rf /" }, "https://x")).toBeUndefined();
    expect(ezActivationCommands({ ...ca, environment: "$(x)" }, "https://x")).toBeUndefined();
    expect(ezActivationCommands({ ...ca, spkiSha256: "zz" }, "https://x")).toBeUndefined();
  });

  it("never lets a hostile name reach the shell", () => {
    const c = ezActivationCommands({ ...ca, name: "x'; rm -rf $HOME" }, "https://x");
    expect(c?.offlineSign).toMatch(/--csr x-rm--rf-HOME\.csr\.pem /);
    expect(c?.offlineSign).not.toMatch(/[;'$]/);
  });
});

describe("ezRenewCrlCommands", () => {
  const ext = `ext-${"a".repeat(40)}`;
  it("emits the renew and upload commands", () => {
    const c = ezRenewCrlCommands(ext);
    expect(c?.renew).toBe(`hemlig pki ez renew-crl --if-due --expect-ext-id ${ext}`);
    expect(c?.upload).toBe(`hemlig pki ez upload-crl --expect-ext-id ${ext}`);
    expect(c?.offlineUpload).toBe(`hemlig pki external-ca upload-crl ${ext} --crl root.crl.pem`);
  });
  it("rejects a malformed ID", () => {
    expect(ezRenewCrlCommands("ext-1")).toBeUndefined();
    expect(ezRenewCrlCommands("ext-1; id")).toBeUndefined();
  });
});
