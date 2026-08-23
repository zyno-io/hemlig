import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { DecryptCommand, GenerateDataKeyCommand, type KMSClient } from '@aws-sdk/client-kms';
import type { AppConfig } from '../aws/config';
import { serviceUnavailable } from '../domain/errors';
import type { Actor, EncryptedPayload, PayloadRevision, SecretPayload } from '../domain/types';
import { stableJson } from '../util/encoding';

export interface PayloadBinding {
    readonly environment: string;
    readonly secretId: string;
    readonly payloadVersionId: string;
}

export class EnvelopeCrypto {
    public constructor(
        private readonly kms: KMSClient,
        private readonly config: AppConfig,
    ) {}

    public async encrypt(
        payload: SecretPayload,
        binding: PayloadBinding,
        actor: Actor,
        createdAt: string,
    ): Promise<PayloadRevision> {
        const context = this.context(binding);
        const command = new GenerateDataKeyCommand({
            KeyId: this.config.payloadKmsKeyArn,
            KeySpec: 'AES_256',
            EncryptionContext: context,
        });
        const generated = await this.kms.send(command);
        const plaintextKey = generated.Plaintext;
        const encryptedDataKey = generated.CiphertextBlob;
        if (plaintextKey === undefined || encryptedDataKey === undefined) {
            throw serviceUnavailable('KMS did not return a data key.');
        }
        const key = Buffer.from(plaintextKey);
        try {
            const iv = randomBytes(12);
            const cipher = createCipheriv('aes-256-gcm', key, iv);
            cipher.setAAD(this.aad(binding));
            const plaintext = Buffer.from(stableJson(payload), 'utf8');
            const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
            const encrypted: EncryptedPayload = {
                algorithm: 'AES-256-GCM',
                encryptedDataKey: Buffer.from(encryptedDataKey).toString('base64'),
                iv: iv.toString('base64'),
                tag: cipher.getAuthTag().toString('base64'),
                ciphertext: ciphertext.toString('base64'),
            };
            return {
                schemaVersion: 1,
                secretId: binding.secretId,
                payloadVersionId: binding.payloadVersionId,
                environment: binding.environment,
                createdAt,
                createdBy: actor,
                payload: encrypted,
            };
        } finally {
            key.fill(0);
        }
    }

    public async decrypt(revision: PayloadRevision): Promise<SecretPayload> {
        const binding: PayloadBinding = {
            environment: revision.environment,
            secretId: revision.secretId,
            payloadVersionId: revision.payloadVersionId,
        };
        const encryptedDataKey = Buffer.from(revision.payload.encryptedDataKey, 'base64');
        const command = new DecryptCommand({
            CiphertextBlob: encryptedDataKey,
            EncryptionContext: this.context(binding),
            KeyId: this.config.payloadKmsKeyArn,
        });
        const decrypted = await this.kms.send(command);
        if (decrypted.Plaintext === undefined) {
            throw serviceUnavailable('KMS did not return plaintext key material.');
        }
        const key = Buffer.from(decrypted.Plaintext);
        try {
            const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(revision.payload.iv, 'base64'));
            decipher.setAAD(this.aad(binding));
            decipher.setAuthTag(Buffer.from(revision.payload.tag, 'base64'));
            const plaintext = Buffer.concat([
                decipher.update(Buffer.from(revision.payload.ciphertext, 'base64')),
                decipher.final(),
            ]);
            return JSON.parse(plaintext.toString('utf8')) as SecretPayload;
        } finally {
            key.fill(0);
        }
    }

    private context(binding: PayloadBinding): Record<string, string> {
        return {
            service: 'clavis',
            purpose: 'secret-payload',
            environment: binding.environment,
            secretId: binding.secretId,
            payloadVersionId: binding.payloadVersionId,
        };
    }

    private aad(binding: PayloadBinding): Buffer {
        return Buffer.from(stableJson(this.context(binding)), 'utf8');
    }
}
