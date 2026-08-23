// @vitest-environment node
//
// crypto.subtle is not reliably present under jsdom; this module only needs
// WebCrypto, so it runs under the plain node environment instead of
// weakening any assertion to work around jsdom.
import forge from "node-forge";
import { describe, expect, it } from "vitest";
import { inspectCsr } from "./csr";
import { generateCsr, type CsrKeySize } from "./csr-generate";

// Mirrors exactly how src/services/issuer.ts parses a submitted CSR
// (parseAndVerifyCsr), so a pass here means the real server-side parser
// would accept this generator's output too.
const parseAsTheServiceWould = (pem: string) => forge.pki.certificationRequestFromPem(pem, true, true);

describe("generateCsr", () => {
  it("produces a CSR that the server's own CSR library parses and verifies", async () => {
    const { csrPem } = await generateCsr({ commonName: "prod-east", keySize: 2048 });
    const csr = parseAsTheServiceWould(csrPem);
    expect(csr.verify()).toBe(true);
  });

  it.each<CsrKeySize>([2048, 3072])("generates a %i-bit RSA key", async (keySize) => {
    const { csrPem } = await generateCsr({ commonName: "prod-east", keySize });
    const csr = parseAsTheServiceWould(csrPem);
    const publicKey = csr.publicKey as forge.pki.rsa.PublicKey;
    expect(publicKey.n.bitLength()).toBe(keySize);
  });

  it("passes the console's own CSR pre-validator", async () => {
    const { csrPem } = await generateCsr({ commonName: "prod-east", keySize: 2048 });
    await expect(inspectCsr(csrPem)).resolves.toBeUndefined();
  });

  it("exports the private key as PKCS#8 and forge can parse it", async () => {
    const { privateKeyPem } = await generateCsr({ commonName: "prod-east", keySize: 2048 });
    expect(privateKeyPem).toContain("-----BEGIN PRIVATE KEY-----");
    expect(() => forge.pki.privateKeyFromPem(privateKeyPem)).not.toThrow();
  });

  it("generates a different key pair on every call", async () => {
    const first = await generateCsr({ commonName: "prod-east", keySize: 2048 });
    const second = await generateCsr({ commonName: "prod-east", keySize: 2048 });
    expect(first.privateKeyPem).not.toBe(second.privateKeyPem);
    expect(first.publicKeyFingerprint).not.toBe(second.publicKeyFingerprint);
  });
});
