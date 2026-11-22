import type { S3Client } from "@aws-sdk/client-s3";
import { sha256Base64 } from "../util/encoding";
import { ObjectStore } from "./object-store";

const store = (response: unknown) =>
  new ObjectStore({
    send: jest.fn(async () => response),
  } as unknown as S3Client);
const body = (bytes: Buffer) => ({
  transformToByteArray: async () => new Uint8Array(bytes),
});

describe("ObjectStore.getBytes", () => {
  it("returns the exact bytes and verifies the S3 checksum", async () => {
    const bytes = Buffer.from([0xff, 0xfe, 0x00, 0x01]);
    await expect(
      store({
        Body: body(bytes),
        ChecksumSHA256: sha256Base64(bytes),
      }).getBytes("b", "k"),
    ).resolves.toEqual(bytes);
    await expect(
      store({ Body: body(bytes) }).getBytes("b", "k"),
    ).resolves.toEqual(bytes);
  });

  it("fails with 503 on a checksum mismatch or an empty body", async () => {
    await expect(
      store({
        Body: body(Buffer.from("x")),
        ChecksumSHA256: sha256Base64(Buffer.from("y")),
      }).getBytes("b", "k"),
    ).rejects.toMatchObject({ statusCode: 503 });
    await expect(store({}).getBytes("b", "k")).rejects.toMatchObject({
      statusCode: 503,
    });
  });
});
