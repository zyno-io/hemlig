import {
  DecryptCommand,
  GenerateDataKeyCommand,
  type KMSClient,
} from "@aws-sdk/client-kms";
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  X509Certificate,
} from "node:crypto";
import forge from "node-forge";
import type { AppConfig } from "../aws/config";
import { badRequest, serviceUnavailable } from "../domain/errors";
import type {
  IdentityRecord,
  IssuerKeyEnvelope,
  IssuerRecord,
} from "../domain/types";
import type { DynamoRepository } from "../repositories/dynamo";
import { isoNow } from "../util/encoding";

const issuerEncryptionContext = {
  service: "hemlig",
  purpose: "issuer-ca",
};
const maximumCsrBytes = 32_768;
const rootValidityDays = 3650;
const leafValidityDays = 365;

export interface IssuedApiIdentity {
  readonly rootFingerprint: string;
  readonly subjectUri: string;
  readonly apiIdentity: Omit<IdentityRecord, "pk" | "sk" | "status"> & {
    readonly certificatePem: string;
  };
}

/**
 * Owns the one online Hemlig issuing root for a deployment. Its private key is
 * envelope encrypted with the application's existing CMK; the root's
 * public certificate is the sole API Gateway truststore entry.
 */
export class IssuerService {
  public constructor(
    private readonly repository: DynamoRepository,
    private readonly kms: KMSClient,
    private readonly config: AppConfig,
  ) {}

  public async issueApiIdentity(
    consumerId: string,
    environment: string,
    csrPem: string,
  ): Promise<IssuedApiIdentity> {
    const csr = parseAndVerifyCsr(csrPem);
    const { issuer } = await this.getOrCreateIssuer();
    const privateKeyPem = await this.decryptPrivateKey(issuer.encryptedPrivateKey);
    try {
      const root = forge.pki.certificateFromPem(issuer.rootCertificatePem);
      const privateKey = forge.pki.privateKeyFromPem(privateKeyPem.toString("utf8"));
      const subjectUri = `spiffe://hemlig/consumer/${consumerId}`;
      const certificatePem = issueLeaf(root, privateKey, csr, consumerId, subjectUri);
      const certificate = new X509Certificate(certificatePem);
      return {
        rootFingerprint: issuer.fingerprint,
        subjectUri,
        apiIdentity: {
          fingerprint: createHash("sha256").update(certificate.raw).digest("hex"),
          consumerId,
          environment,
          kind: "api",
          notBefore: certificate.validFromDate.toISOString(),
          notAfter: certificate.validToDate.toISOString(),
          certificatePem,
        },
      };
    } catch {
      throw serviceUnavailable("Could not issue the consumer API certificate.");
    } finally {
      privateKeyPem.fill(0);
    }
  }

  public async issuerFingerprint(): Promise<string> {
    const { issuer } = await this.getOrCreateIssuer();
    return issuer.fingerprint;
  }

  /**
   * Lets an operator provision the issuing root deliberately, ahead of the
   * first enrollment, so the truststore anchor exists and can be distributed
   * in advance. This is a thin wrapper over the same getOrCreateIssuer() the
   * lazy enrollment path uses, so the two can never diverge; `created` is
   * false whenever this call observed an issuer that already existed,
   * including one a concurrent caller just created.
   */
  public async ensureIssuer(): Promise<{ readonly issuer: IssuerRecord; readonly created: boolean }> {
    return this.getOrCreateIssuer();
  }

  public certificateRequestFingerprint(csrPem: string): string {
    const csr = parseAndVerifyCsr(csrPem);
    const der = forge.asn1
      .toDer(forge.pki.certificationRequestToAsn1(csr))
      .getBytes();
    return createHash("sha256").update(Buffer.from(der, "latin1")).digest("hex");
  }

  private async getOrCreateIssuer(): Promise<{ readonly issuer: IssuerRecord; readonly created: boolean }> {
    const existing = await this.repository.getIssuer();
    if (existing !== undefined) {
      await this.repository.ensureIssuerTruststoreRoot(
        existing,
        this.config.environmentName,
      );
      return { issuer: existing, created: false };
    }
    const now = isoNow();
    const keys = forge.pki.rsa.generateKeyPair({ bits: 3072, e: 0x10001 });
    const root = forge.pki.createCertificate();
    root.publicKey = keys.publicKey;
    root.serialNumber = randomSerialNumber();
    root.validity.notBefore = new Date(Date.now() - 60_000);
    root.validity.notAfter = new Date(
      Date.now() + rootValidityDays * 24 * 60 * 60 * 1000,
    );
    const subject = [
      {
        name: "commonName",
        value: `Hemlig ${this.config.environmentName} Issuing Root`,
      },
    ];
    root.setSubject(subject);
    root.setIssuer(subject);
    root.setExtensions([
      { name: "basicConstraints", critical: true, cA: true },
      {
        name: "keyUsage",
        critical: true,
        digitalSignature: true,
        keyCertSign: true,
        cRLSign: true,
      },
      { name: "subjectKeyIdentifier" },
    ]);
    root.sign(keys.privateKey, forge.md.sha256.create());
    const rootCertificatePem = forge.pki.certificateToPem(root);
    const serializedPrivateKey = Buffer.from(
      forge.pki.privateKeyToPem(keys.privateKey),
      "utf8",
    );
    let encryptedPrivateKey: IssuerKeyEnvelope;
    try {
      encryptedPrivateKey = await this.encryptPrivateKey(serializedPrivateKey);
    } finally {
      serializedPrivateKey.fill(0);
    }
    const certificate = new X509Certificate(rootCertificatePem);
    const issuer: IssuerRecord = {
      pk: "SYSTEM#ISSUER",
      sk: "PROFILE",
      rootCertificatePem,
      encryptedPrivateKey,
      fingerprint: createHash("sha256").update(certificate.raw).digest("hex"),
      notBefore: certificate.validFromDate.toISOString(),
      notAfter: certificate.validToDate.toISOString(),
      createdAt: now,
    };
    const created = await this.repository.createIssuer(issuer, this.config.environmentName);
    // createIssuer returns the already-created issuer instead of throwing when
    // a concurrent caller won the create race, so a fingerprint mismatch here
    // means this call lost that race rather than created anything.
    return { issuer: created, created: created.fingerprint === issuer.fingerprint };
  }

  private async encryptPrivateKey(privateKeyPem: Buffer): Promise<IssuerKeyEnvelope> {
    const keyResult = await this.kms.send(
      new GenerateDataKeyCommand({
        KeyId: this.config.payloadKmsKeyArn,
        KeySpec: "AES_256",
        EncryptionContext: issuerEncryptionContext,
      }),
    );
    if (keyResult.Plaintext === undefined || keyResult.CiphertextBlob === undefined) {
      throw serviceUnavailable("KMS did not return an issuer data key.");
    }
    const key = Buffer.from(keyResult.Plaintext);
    const iv = randomBytes(12);
    try {
      const cipher = createCipheriv("aes-256-gcm", key, iv);
      cipher.setAAD(Buffer.from(JSON.stringify(issuerEncryptionContext), "utf8"));
      const ciphertext = Buffer.concat([
        cipher.update(privateKeyPem),
        cipher.final(),
      ]);
      return {
        algorithm: "AES-256-GCM",
        encryptedDataKey: Buffer.from(keyResult.CiphertextBlob).toString("base64"),
        iv: iv.toString("base64"),
        tag: cipher.getAuthTag().toString("base64"),
        ciphertext: ciphertext.toString("base64"),
      };
    } finally {
      key.fill(0);
    }
  }

  private async decryptPrivateKey(envelope: IssuerKeyEnvelope): Promise<Buffer> {
    if (envelope.algorithm !== "AES-256-GCM") {
      throw serviceUnavailable("The issuer key envelope is not supported.");
    }
    const result = await this.kms.send(
      new DecryptCommand({
        KeyId: this.config.payloadKmsKeyArn,
        CiphertextBlob: Buffer.from(envelope.encryptedDataKey, "base64"),
        EncryptionContext: issuerEncryptionContext,
      }),
    );
    if (result.Plaintext === undefined) {
      throw serviceUnavailable("KMS did not decrypt the issuer data key.");
    }
    const key = Buffer.from(result.Plaintext);
    try {
      const decipher = createDecipheriv(
        "aes-256-gcm",
        key,
        Buffer.from(envelope.iv, "base64"),
      );
      decipher.setAAD(Buffer.from(JSON.stringify(issuerEncryptionContext), "utf8"));
      decipher.setAuthTag(Buffer.from(envelope.tag, "base64"));
      return Buffer.concat([
        decipher.update(Buffer.from(envelope.ciphertext, "base64")),
        decipher.final(),
      ]);
    } catch {
      throw serviceUnavailable("The encrypted Hemlig issuing key is invalid.");
    } finally {
      key.fill(0);
    }
  }
}

const parseAndVerifyCsr = (csrPem: string): forge.pki.CertificateSigningRequest => {
  if (
    csrPem.length === 0 ||
    Buffer.byteLength(csrPem, "utf8") > maximumCsrBytes ||
    (csrPem.match(/-----BEGIN CERTIFICATE REQUEST-----/g) ?? []).length !== 1
  ) {
    throw badRequest("apiCertificateSigningRequestPem must be one CSR of at most 32 KiB.");
  }
  try {
    const csr = forge.pki.certificationRequestFromPem(csrPem, true, true);
    if (!csr.verify() || csr.publicKey === null || !("n" in csr.publicKey)) {
      throw new Error("invalid CSR");
    }
    const publicKey = csr.publicKey as forge.pki.rsa.PublicKey;
    if (publicKey.n.bitLength() < 2048) {
      throw new Error("weak key");
    }
    return csr;
  } catch {
    throw badRequest(
      "apiCertificateSigningRequestPem must be a valid signed RSA CSR with a 2048-bit-or-larger key.",
    );
  }
};

const issueLeaf = (
  root: forge.pki.Certificate,
  privateKey: forge.pki.rsa.PrivateKey,
  csr: forge.pki.CertificateSigningRequest,
  consumerId: string,
  subjectUri: string,
): string => {
  if (csr.publicKey === null) {
    throw new Error("CSR has no public key");
  }
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = csr.publicKey;
  certificate.serialNumber = randomSerialNumber();
  certificate.validity.notBefore = new Date(Date.now() - 60_000);
  const desiredExpiry = new Date(
    Date.now() + leafValidityDays * 24 * 60 * 60 * 1000,
  );
  certificate.validity.notAfter =
    root.validity.notAfter < desiredExpiry ? root.validity.notAfter : desiredExpiry;
  certificate.setSubject([{ name: "commonName", value: `hemlig-${consumerId}` }]);
  certificate.setIssuer(root.subject.attributes);
  certificate.setExtensions([
    { name: "basicConstraints", critical: true, cA: false },
    {
      name: "keyUsage",
      critical: true,
      digitalSignature: true,
      keyEncipherment: true,
    },
    { name: "extKeyUsage", clientAuth: true },
    { name: "subjectAltName", altNames: [{ type: 6, value: subjectUri }] },
    { name: "subjectKeyIdentifier" },
    {
      name: "authorityKeyIdentifier",
      keyIdentifier: root.generateSubjectKeyIdentifier().getBytes(),
    },
  ]);
  certificate.sign(privateKey, forge.md.sha256.create());
  return forge.pki.certificateToPem(certificate);
};

/** RFC 5280 serials are positive, nonzero INTEGERs. */
const randomSerialNumber = (): string => {
  const bytes = randomBytes(16);
  const first = bytes[0] ?? 0;
  bytes[0] = first & 0x7f;
  if (bytes.every((byte) => byte === 0)) {
    bytes[bytes.length - 1] = 1;
  }
  return bytes.toString("hex");
};
