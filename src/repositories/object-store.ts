import {
  DeleteObjectCommand,
  GetObjectCommand,
  GetObjectRetentionCommand,
  HeadObjectCommand,
  ListObjectsV2Command,
  PutObjectCommand,
  PutObjectRetentionCommand,
  type S3Client,
} from "@aws-sdk/client-s3";
import { serviceUnavailable } from "../domain/errors";
import type { ObjectReference } from "../domain/types";
import { sha256Base64 } from "../util/encoding";

export class ObjectStore {
  public constructor(private readonly s3: S3Client) {}

  public async putImmutable(
    bucket: string,
    key: string,
    body: Buffer,
    contentType = "application/json",
  ): Promise<ObjectReference> {
    const checksumSha256 = sha256Base64(body);
    const command = new PutObjectCommand({
      Bucket: bucket,
      Key: key,
      Body: body,
      ChecksumSHA256: checksumSha256,
      IfNoneMatch: "*",
      ContentType: contentType,
    });
    const response = await this.s3.send(command);
    if (response.VersionId === undefined) {
      throw serviceUnavailable("S3 did not return an object version ID.");
    }
    return { bucket, key, versionId: response.VersionId, checksumSha256 };
  }

  public async putImmutableOrGet(
    bucket: string,
    key: string,
    body: Buffer,
    contentType = "application/json",
  ): Promise<ObjectReference> {
    try {
      return await this.putImmutable(bucket, key, body, contentType);
    } catch (error) {
      const checksumSha256 = sha256Base64(body);
      try {
        const existing = await this.s3.send(
          new GetObjectCommand({ Bucket: bucket, Key: key }),
        );
        if (existing.VersionId === undefined || existing.Body === undefined) {
          throw error;
        }
        const contents = await existing.Body.transformToByteArray();
        if (sha256Base64(Buffer.from(contents)) !== checksumSha256) {
          throw error;
        }
        return { bucket, key, versionId: existing.VersionId, checksumSha256 };
      } catch {
        throw error;
      }
    }
  }

  public async getJson<T>(
    bucket: string,
    key: string,
    versionId?: string,
  ): Promise<T> {
    const command = new GetObjectCommand({
      Bucket: bucket,
      Key: key,
      VersionId: versionId,
      ChecksumMode: "ENABLED",
    });
    const response = await this.s3.send(command);
    if (response.Body === undefined) {
      throw serviceUnavailable("S3 returned an empty object body.");
    }
    const contents = await response.Body.transformToByteArray();
    const actualChecksum = sha256Base64(Buffer.from(contents));
    if (
      response.ChecksumSHA256 !== undefined &&
      response.ChecksumSHA256 !== actualChecksum
    ) {
      throw serviceUnavailable("S3 object checksum verification failed.");
    }
    return JSON.parse(Buffer.from(contents).toString("utf8")) as T;
  }

  /**
   * Lists only object keys beneath an already-authorized prefix. Callers that
   * need content must still load every returned object through getJson(), so
   * an S3 key never becomes trusted application data on its own.
   */
  public async listKeys(
    bucket: string,
    prefix: string,
    continuationToken: string | undefined,
    maxKeys: number,
  ): Promise<{
    readonly keys: readonly string[];
    readonly nextContinuationToken?: string;
  }> {
    const response = await this.s3.send(
      new ListObjectsV2Command({
        Bucket: bucket,
        Prefix: prefix,
        ContinuationToken: continuationToken,
        MaxKeys: maxKeys,
      }),
    );
    return {
      keys: (response.Contents ?? [])
        .map((item) => item.Key)
        .filter((key): key is string => key !== undefined),
      ...(response.NextContinuationToken === undefined
        ? {}
        : { nextContinuationToken: response.NextContinuationToken }),
    };
  }

  public async existsWithChecksum(
    reference: ObjectReference,
  ): Promise<boolean> {
    const command = new HeadObjectCommand({
      Bucket: reference.bucket,
      Key: reference.key,
      VersionId: reference.versionId,
      ChecksumMode: "ENABLED",
    });
    try {
      const response = await this.s3.send(command);
      return response.ChecksumSHA256 === reference.checksumSha256;
    } catch {
      return false;
    }
  }

  public async extendComplianceRetention(
    reference: ObjectReference,
    retainUntil: Date,
  ): Promise<void> {
    const command = new PutObjectRetentionCommand({
      Bucket: reference.bucket,
      Key: reference.key,
      VersionId: reference.versionId,
      Retention: { Mode: "COMPLIANCE", RetainUntilDate: retainUntil },
    });
    await this.s3.send(command);
  }

  public async canDeleteVersion(
    reference: ObjectReference,
    now: Date = new Date(),
  ): Promise<boolean> {
    const command = new GetObjectRetentionCommand({
      Bucket: reference.bucket,
      Key: reference.key,
      VersionId: reference.versionId,
    });
    const response = await this.s3.send(command);
    const retainUntil = response.Retention?.RetainUntilDate;
    return retainUntil === undefined || retainUntil.getTime() <= now.getTime();
  }

  public async deleteVersion(reference: ObjectReference): Promise<void> {
    const command = new DeleteObjectCommand({
      Bucket: reference.bucket,
      Key: reference.key,
      VersionId: reference.versionId,
    });
    await this.s3.send(command);
  }
}
