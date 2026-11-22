import { createPublicKey, Decipheriv, verify } from "node:crypto";
import { generateCaKeyPair, wrapCaKey } from "./wrapped-keys";
import { WrappedCaSigner, type CaSigner } from "./signer";
import { mockKms } from "./__fixtures__/testkit";
import type { PkiKeyAlgorithm } from "./types";

const binding = { caId: "ca-0a1b2c3d", environment: "prod" };
const tbs = Buffer.from("to-be-signed bytes");

const signerFor = async (algorithm: PkiKeyAlgorithm) => {
  const mock = mockKms();
  const key = await generateCaKeyPair(algorithm);
  const wrapped = await wrapCaKey(
    mock.kms,
    "key-arn",
    key.privateKeyDer,
    binding,
  );
  const signer: CaSigner = new WrappedCaSigner({
    kms: mock.kms,
    kmsKeyId: "key-arn",
    algorithm,
    wrapped,
    ...binding,
  });
  return {
    ...mock,
    key,
    signer,
    wrapped,
    publicKey: createPublicKey({
      key: key.spkiDer,
      format: "der",
      type: "spki",
    }),
  };
};

describe("WrappedCaSigner", () => {
  it("decrypts under the pki-ca context and returns a DER ECDSA signature", async () => {
    const { signer, send, publicKey } = await signerFor("ECDSA_P256");
    const signature = await signer.sign(tbs);
    expect(signer.algorithm).toBe("ECDSA_P256");
    // DER SEQUENCE { INTEGER r, INTEGER s }, not the 64-byte raw form.
    expect(signature[0]).toBe(0x30);
    expect(signature.length).toBeGreaterThanOrEqual(68);
    expect(signature.length).toBeLessThanOrEqual(72);
    expect(
      verify("sha256", tbs, { key: publicKey, dsaEncoding: "der" }, signature),
    ).toBe(true);
    expect(
      verify(
        "sha256",
        Buffer.from("other"),
        { key: publicKey, dsaEncoding: "der" },
        signature,
      ),
    ).toBe(false);

    const decrypt = send.mock.calls[send.mock.calls.length - 1]?.[0] as {
      input: { EncryptionContext: unknown; KeyId: string };
    };
    expect(decrypt.input.EncryptionContext).toEqual({
      service: "hemlig",
      purpose: "pki-ca",
      ...binding,
    });
    expect(decrypt.input.KeyId).toBe("key-arn");
  });

  it("signs P-384 with SHA-384 and Ed25519 as the raw 64 bytes", async () => {
    const p384 = await signerFor("ECDSA_P384");
    const p384Signature = await p384.signer.sign(tbs);
    expect(p384Signature[0]).toBe(0x30);
    expect(
      verify(
        "sha384",
        tbs,
        { key: p384.publicKey, dsaEncoding: "der" },
        p384Signature,
      ),
    ).toBe(true);

    const ed = await signerFor("ED25519");
    const edSignature = await ed.signer.sign(tbs);
    expect(edSignature).toHaveLength(64);
    expect(verify(null, tbs, ed.publicKey, edSignature)).toBe(true);
  });

  it("signs RSA with PKCS#1 v1.5 and SHA-256", async () => {
    const rsa = await signerFor("RSA_3072");
    const signature = await rsa.signer.sign(tbs);
    expect(signature).toHaveLength(384);
    expect(verify("sha256", tbs, rsa.publicKey, signature)).toBe(true);
  }, 60_000);

  it("zeroes every plaintext PKCS#8 copy and the data key, and caches nothing", async () => {
    const { signer, send, handedOut, key } = await signerFor("ECDSA_P256");
    const outputs: Buffer[] = [];
    const concats: Buffer[] = [];
    const update = jest.spyOn(Decipheriv.prototype, "update");
    const final = jest.spyOn(Decipheriv.prototype, "final");
    const concat = jest.spyOn(Buffer, "concat");
    try {
      const callsBefore = send.mock.calls.length;
      const handedBefore = handedOut.length;
      const signature = await signer.sign(tbs);
      await signer.sign(tbs);
      // One Decrypt per signature: plaintext is never reused across calls.
      expect(send.mock.calls.length - callsBefore).toBe(2);
      for (const plaintext of handedOut.slice(handedBefore)) {
        expect(plaintext.every((byte) => byte === 0)).toBe(true);
      }
      for (const result of [...update.mock.results, ...final.mock.results]) {
        outputs.push(result.value as Buffer);
      }
      for (const result of concat.mock.results) {
        concats.push(result.value as Buffer);
      }
      // The decipher's own outputs and the concatenated plaintext are the actual buffers, and all are zeroed.
      expect(outputs).toHaveLength(4);
      expect(
        outputs.every((buffer) => buffer.every((byte) => byte === 0)),
      ).toBe(true);
      const plaintexts = concats.filter(
        (buffer) => buffer.length === key.privateKeyDer.length,
      );
      expect(plaintexts).toHaveLength(2);
      expect(
        plaintexts.every((buffer) => buffer.every((byte) => byte === 0)),
      ).toBe(true);
      expect(signature.length).toBeGreaterThan(0);
    } finally {
      update.mockRestore();
      final.mockRestore();
      concat.mockRestore();
    }
  });

  it("reports an unusable key as ca_key_unavailable and still zeroes the buffer", async () => {
    const mock = mockKms();
    const wrapped = await wrapCaKey(
      mock.kms,
      "key-arn",
      Buffer.from("not a pkcs8 key"),
      binding,
    );
    const signer = new WrappedCaSigner({
      kms: mock.kms,
      kmsKeyId: "key-arn",
      algorithm: "ECDSA_P256",
      wrapped,
      ...binding,
    });
    await expect(signer.sign(tbs)).rejects.toMatchObject({
      statusCode: 409,
      code: "ca_key_unavailable",
    });
  });
});
