import { z } from "zod";

/**
 * Parsed at the boundary so a contract drift becomes a loud failure rather
 * than an undefined field in a form that then submits a destructive payload.
 */
export const actor = z.object({
  type: z.enum(["human", "consumer", "system"]),
  id: z.string(),
  email: z.string().max(320).optional(),
  tenantId: z.string().optional(),
  consumerId: z.string().optional(),
  environment: z.string().optional(),
});

export const metadata = z.object({
  description: z.string().optional(),
  tags: z.record(z.string()).optional(),
});

export const grant = z.object({
  consumerId: z.string(),
  permissions: z.array(z.literal("read")),
});

export const secretState = z.enum([
  "PENDING_VALUE",
  "ACTIVE",
  "REVOKED",
  "ARCHIVED",
]);

export const controlRevision = z.object({
  schemaVersion: z.literal(1),
  // Optional only while older deployments are being migrated.
  secretUid: z.string().optional(),
  secretId: z.string(),
  controlVersionId: z.string(),
  payloadVersionId: z.string().optional(),
  payloadKeyCount: z.number().int().nonnegative().optional(),
  environment: z.string(),
  state: secretState,
  createdAt: z.string(),
  createdBy: actor,
  metadata,
  acl: z.array(grant),
});

export const secretReadResponse = z.object({
  secretId: z.string(),
  controlVersionId: z.string(),
  payloadVersionId: z.string(),
  payload: z.record(
    z.string(),
    z.object({ encoding: z.enum(["utf8", "base64"]), value: z.string() }),
  ),
});

export const catalogEntry = z.object({
  secretUid: z.string().optional(),
  secretId: z.string(),
  environment: z.string(),
  controlVersionId: z.string(),
  payloadVersionId: z.string().optional(),
  payloadKeyCount: z.number().int().nonnegative().optional(),
  state: secretState,
  metadata,
  updatedAt: z.string().optional(),
});

export const catalogPage = z.object({
  secrets: z.array(catalogEntry),
  // Only ever set together: `nextCursor` for an ordinary browse page,
  // `truncated` for a `q` search page, which is bounded-complete instead of
  // cursor-paginated. Both optional because a plain page (no `q`) that
  // happens to be the last one carries neither.
  nextCursor: z.string().optional(),
  truncated: z.boolean().optional(),
  generatedAt: z.string(),
});

/** Every folder is inferred from a slash-separated secret ID. */
export const folderKind = z.literal("derived");

export const secretTreeFolder = z.object({
  segment: z.string(),
  path: z.string(),
  secretCount: z.number().int().nonnegative(),
  kind: folderKind,
});

/**
 * One bounded, complete level of the path tree. Unlike `catalogPage` there is
 * no cursor: the server caps the level and sets `truncated` instead of
 * paginating it, so a level either fits or is honestly reported as
 * incomplete. `pathPrefix` is absent at the root.
 */
export const secretTreePage = z.object({
  environment: z.string(),
  pathPrefix: z.string().optional(),
  folders: z.array(secretTreeFolder),
  secrets: z.array(catalogEntry),
  truncated: z.boolean(),
  generatedAt: z.string(),
});

export const consumerSummary = z.object({
  consumerId: z.string(),
  environment: z.string(),
  status: z.enum(["PENDING", "ACTIVE", "FAILED"]),
  subjectUri: z.string(),
  createdAt: z.string(),
  activeApiIdentityCount: z.number().int().nonnegative().optional(),
});

export const consumerListPage = z.object({
  consumers: z.array(consumerSummary),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});

export const apiIdentity = z.object({
  apiFingerprint: z.string(),
  status: z.enum(["PENDING", "ACTIVE", "REVOKED", "EXPIRED", "FAILED"]),
  kind: z.string().optional(),
  notBefore: z.string(),
  notAfter: z.string(),
  apiCertificatePem: z.string().optional(),
});

export const consumerDetail = consumerSummary.extend({
  createdBy: actor.optional(),
  rootFingerprint: z.string().optional(),
  apiIdentities: z.array(apiIdentity).optional(),
});

export const consumerSecretGrant = z.object({
  secretUid: z.string(),
  secretId: z.string(),
  permissions: z.array(z.literal("read")),
  controlVersionId: z.string(),
  state: z.enum(["PENDING_VALUE", "ACTIVE"]),
});

export const consumerSecretGrantPage = z.object({
  consumerId: z.string(),
  environment: z.string(),
  grants: z.array(consumerSecretGrant),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});

export const apiIdentityListPage = z.object({
  consumerId: z.string(),
  environment: z.string(),
  rootFingerprint: z.string().optional(),
  apiIdentities: z.array(apiIdentity),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});

export const enrollmentResult = z.object({
  consumerId: z.string(),
  environment: z.string(),
  rootFingerprint: z.string(),
  apiFingerprint: z.string(),
  apiCertificatePem: z.string(),
  status: z.literal("ACTIVE"),
});

export const apiIdentityResult = z.object({
  consumerId: z.string(),
  environment: z.string(),
  rootFingerprint: z.string().optional(),
  apiFingerprint: z.string(),
  apiCertificatePem: z.string().optional(),
  status: z.enum(["ACTIVE", "REVOKED"]),
});

export const issuerStatus = z.object({
  rootFingerprint: z.string(),
  rootCertificatePem: z.string(),
  notBefore: z.string(),
  notAfter: z.string(),
  createdAt: z.string(),
  truststore: z
    .object({
      objectKey: z.string(),
      versionId: z.string(),
      anchorCount: z.number().int().nonnegative(),
    })
    .optional(),
});

export const secretRevision = z.object({
  controlVersionId: z.string(),
  payloadVersionId: z.string().optional(),
  payloadKeyCount: z.number().int().nonnegative().optional(),
  createdAt: z.string(),
  createdBy: actor,
  isCurrent: z.boolean(),
  objectAvailable: z.boolean(),
});

export const secretRevisionPage = z.object({
  secretId: z.string(),
  revisions: z.array(secretRevision),
  truncated: z.boolean(),
  generatedAt: z.string(),
});

/**
 * Environments are administrator-defined records, not a deployment constant:
 * a fresh deployment starts with none, bounded to 100, and every record
 * remembers who created it.
 */
export const environmentDefinition = z.object({
  name: z.string(),
  createdAt: z.string(),
  createdBy: actor,
});

export const environmentListResponse = z.object({
  environments: z.array(environmentDefinition),
  generatedAt: z.string(),
});

export const auditOutcome = z.enum([
  "attempted",
  "authorized",
  "succeeded",
  "failed",
]);

export const auditEvent = z.object({
  eventId: z.string(),
  at: z.string(),
  correlationId: z.string(),
  outcome: auditOutcome,
  actor,
  operation: z.string(),
  target: z.record(z.string()).optional(),
  permission: z.literal("read").optional(),
  sourceIp: z.string().optional(),
  reasonCode: z.string().optional(),
});

export const auditPage = z.object({
  date: z.string(),
  events: z.array(auditEvent).max(50),
  nextCursor: z.string().optional(),
  generatedAt: z.string(),
});

export type ControlRevision = z.infer<typeof controlRevision>;
export type CatalogEntry = z.infer<typeof catalogEntry>;
export type CatalogPage = z.infer<typeof catalogPage>;
export type FolderKind = z.infer<typeof folderKind>;
export type SecretTreeFolder = z.infer<typeof secretTreeFolder>;
export type SecretTreePage = z.infer<typeof secretTreePage>;
export type ConsumerSummary = z.infer<typeof consumerSummary>;
export type ConsumerListPage = z.infer<typeof consumerListPage>;
export type ConsumerDetail = z.infer<typeof consumerDetail>;
export type ConsumerSecretGrant = z.infer<typeof consumerSecretGrant>;
export type ConsumerSecretGrantPage = z.infer<typeof consumerSecretGrantPage>;
export type ApiIdentity = z.infer<typeof apiIdentity>;
export type ApiIdentityListPage = z.infer<typeof apiIdentityListPage>;
export type EnrollmentResult = z.infer<typeof enrollmentResult>;
export type ApiIdentityResult = z.infer<typeof apiIdentityResult>;
export type IssuerStatus = z.infer<typeof issuerStatus>;
export type SecretRevisionPage = z.infer<typeof secretRevisionPage>;
export type EnvironmentDefinition = z.infer<typeof environmentDefinition>;
export type EnvironmentListResponse = z.infer<typeof environmentListResponse>;
export type AuditEvent = z.infer<typeof auditEvent>;
export type AuditPage = z.infer<typeof auditPage>;
export type SecretReadResponse = z.infer<typeof secretReadResponse>;
export type Metadata = z.infer<typeof metadata>;
export type Grant = z.infer<typeof grant>;
