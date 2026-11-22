import { createPrivateKey, createPublicKey } from "node:crypto";
import { DecryptCommand, GenerateDataKeyCommand } from "@aws-sdk/client-kms";
import { mockKms } from "./__fixtures__/testkit";
import { ApiError } from "../domain/errors";
import {
  caEncryptionContext,
  generateCaKeyPair,
  unwrapCaKey,
  wrapCaKey,
  type PkiKmsClient,
} from "./wrapped-keys";

const binding = { caId: "ca-0a1b2c3d", environment: "prod" };

describe("wrapped CA keys", () => {
  it("generates each CA key type", async () => {
    for (const algorithm of ["ECDSA_P256", "ECDSA_P384", "ED25519"] as const) {
      const key = await generateCaKeyPair(algorithm);
      expect(key.spkiSha256).toMatch(/^[0-9a-f]{64}$/);
      const pub = createPrivateKey({
        key: key.privateKeyDer,
        format: "der",
        type: "pkcs8",
      });
      expect(
        createPublicKey(pub)
          .export({ type: "spki", format: "der" })
          .equals(key.spkiDer),
      ).toBe(true);
    }
  });

  it("wraps with GenerateDataKey under the pki-ca context and round-trips", async () => {
    const { kms, send, handedOut } = mockKms();
    const key = await generateCaKeyPair("ECDSA_P256");
    const wrapped = await wrapCaKey(
      kms,
      "arn:aws:kms:us-east-1:000000000000:key/test",
      key.privateKeyDer,
      binding,
    );

    const generate = send.mock.calls[0]?.[0] as GenerateDataKeyCommand;
    expect(generate).toBeInstanceOf(GenerateDataKeyCommand);
    expect(generate.input).toEqual({
      KeyId: "arn:aws:kms:us-east-1:000000000000:key/test",
      KeySpec: "AES_256",
      EncryptionContext: {
        service: "hemlig",
        purpose: "pki-ca",
        caId: "ca-0a1b2c3d",
        environment: "prod",
      },
    });
    expect(caEncryptionContext(binding)).toEqual(
      generate.input.EncryptionContext,
    );
    expect(Object.keys(wrapped).sort()).toEqual([
      "algorithm",
      "ciphertext",
      "encryptedDataKey",
      "iv",
      "tag",
    ]);
    expect(wrapped.algorithm).toBe("AES-256-GCM");
    expect(Buffer.from(wrapped.encryptedDataKey, "base64").toString()).toBe(
      "encrypted-data-key",
    );
    expect(Buffer.from(wrapped.iv, "base64")).toHaveLength(12);
    expect(Buffer.from(wrapped.tag, "base64")).toHaveLength(16);
    expect(
      Buffer.from(wrapped.ciphertext, "base64").includes(key.privateKeyDer),
    ).toBe(false);
    // The plaintext data key KMS returned is zeroed.
    expect(handedOut[0]?.every((byte) => byte === 0)).toBe(true);

    const unwrapped = await unwrapCaKey(
      kms,
      "arn:aws:kms:us-east-1:000000000000:key/test",
      wrapped,
      binding,
    );
    expect(unwrapped.equals(key.privateKeyDer)).toBe(true);
    const decrypt = send.mock.calls[1]?.[0] as DecryptCommand;
    expect(decrypt).toBeInstanceOf(DecryptCommand);
    expect(decrypt.input.EncryptionContext).toEqual(
      caEncryptionContext(binding),
    );
    expect(
      Buffer.from(decrypt.input.CiphertextBlob as Uint8Array).toString(),
    ).toBe("encrypted-data-key");
    expect(decrypt.input.KeyId).toBe(
      "arn:aws:kms:us-east-1:000000000000:key/test",
    );
    expect(handedOut[1]?.every((byte) => byte === 0)).toBe(true);
  });

  it("binds the blob to its CA and environment through the AAD", async () => {
    const { kms } = mockKms();
    const key = await generateCaKeyPair("ECDSA_P256");
    const wrapped = await wrapCaKey(kms, "k", key.privateKeyDer, binding);
    for (const other of [
      { caId: "ca-other", environment: "prod" },
      { caId: binding.caId, environment: "staging" },
    ]) {
      // The mock KMS ignores the context, so only the AES-GCM AAD stands between the blob and the wrong CA.
      await expect(unwrapCaKey(kms, "k", wrapped, other)).rejects.toMatchObject(
        {
          statusCode: 409,
          code: "ca_key_unavailable",
        },
      );
    }
    // A truncated GCM tag must not authenticate.
    for (const length of [0, 4, 12, 15, 17]) {
      const tag = Buffer.concat([
        Buffer.from(wrapped.tag, "base64"),
        Buffer.alloc(2),
      ]).subarray(0, length);
      await expect(
        unwrapCaKey(
          kms,
          "k",
          { ...wrapped, tag: tag.toString("base64") },
          binding,
        ),
      ).rejects.toMatchObject({ statusCode: 409, code: "ca_key_unavailable" });
    }
    const tampered = {
      ...wrapped,
      ciphertext: Buffer.alloc(8).toString("base64"),
    };
    await expect(
      unwrapCaKey(kms, "k", tampered, binding),
    ).rejects.toBeInstanceOf(ApiError);
  });

  it("maps KMS failures: undecryptable is 409, anything else is 503", async () => {
    const key = await generateCaKeyPair("ECDSA_P256");
    const { kms } = mockKms();
    const wrapped = await wrapCaKey(kms, "k", key.privateKeyDer, binding);
    const failing = (name: string): PkiKmsClient =>
      ({
        send: jest.fn(async () => {
          throw Object.assign(new Error("kms"), { name });
        }),
      }) as unknown as PkiKmsClient;
    await expect(
      unwrapCaKey(failing("InvalidCiphertextException"), "k", wrapped, binding),
    ).rejects.toMatchObject({
      statusCode: 409,
      code: "ca_key_unavailable",
    });
    for (const name of [
      "AccessDeniedException",
      "ThrottlingException",
      "KMSInternalException",
    ]) {
      await expect(
        unwrapCaKey(failing(name), "k", wrapped, binding),
      ).rejects.toMatchObject({
        statusCode: 503,
        code: "service_unavailable",
      });
    }
    await expect(
      unwrapCaKey(
        kms,
        "k",
        { ...wrapped, algorithm: "AES-128-GCM" as never },
        binding,
      ),
    ).rejects.toMatchObject({
      code: "ca_key_unavailable",
    });
  });

  it("refuses when KMS returns no key material", async () => {
    const empty = {
      send: jest.fn(async () => ({})),
    } as unknown as PkiKmsClient;
    await expect(
      wrapCaKey(empty, "k", Buffer.alloc(4), binding),
    ).rejects.toMatchObject({ statusCode: 503 });
    const key = await generateCaKeyPair("ECDSA_P256");
    const { kms } = mockKms();
    const wrapped = await wrapCaKey(kms, "k", key.privateKeyDer, binding);
    await expect(
      unwrapCaKey(empty, "k", wrapped, binding),
    ).rejects.toMatchObject({ statusCode: 503 });
  });
});
