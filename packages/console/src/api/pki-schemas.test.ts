import { describe, expect, it } from "vitest";
import * as p from "./pki-schemas";

const actor = { type: "human", id: "admin-1", email: "a@example.com" };

const policy = {
  issueLeaves: true,
  issueSubordinates: false,
  maxLeafLifetimeSeconds: 7_776_000,
  leafKeyAlgorithms: ["ECDSA_P256", "ECDSA_P384"],
  capacity: 10_000,
  issuancePerHour: 1_000,
  crlValiditySeconds: 604_800,
};

const baseCa = {
  caId: "ca-0a1b2c3d",
  environment: "prod",
  name: "prod-issuing-1",
  kind: "EXTERNAL_INTERMEDIATE",
  status: "PENDING_CERTIFICATE",
  version: "v1",
  keyAlgorithm: "ECDSA_P256",
  keyState: "ACTIVE",
  createdAt: "2026-11-01T00:00:00Z",
  key: {
    custody: "KMS",
    algorithm: "ECDSA_P256",
    spkiSha256: "ab",
    state: "ACTIVE",
  },
  subject: { commonName: "prod issuing ca 1", organization: "Example" },
  subjectDn: "CN=prod issuing ca 1,O=Example",
  requestedConstraints: {},
  crlIssuers: [],
  policy,
  maxIssueLifetimeEverSeconds: 0,
  createdBy: actor,
  drained: false,
  capacity: { capacity: 10_000, issuancePerHour: 1_000 },
};

const pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

const grant = {
  consumerId: "payments",
  environment: "prod",
  name: "web",
  uid: "pkg-123",
  caId: "ca-0a1b2c3d",
  status: "ACTIVE",
  expired: false,
  displayName: "payments web certificates",
  expiresAt: "2027-12-31T00:00:00Z",
  policy: {
    names: {
      dns: {
        allow: ["**.payments.svc.cluster.local", "*.payments.example.com"],
        deny: ["internal.payments.example.com"],
        allowWildcardNames: false,
      },
      ip: { allow: ["10.20.0.0/16"], deny: [] },
      uri: { allow: ["spiffe://prod.example.com/ns/payments/**"] },
      commonName: { mode: "san", addToSans: true },
      maxSans: 50,
    },
    subject: { allow: { organizationalUnit: ["payments-*"] } },
    keyAlgorithms: ["ECDSA_P256", "ECDSA_P384", "RSA_2048", "RSA_3072"],
    keyUsages: ["digitalSignature", "keyEncipherment"],
    extendedKeyUsages: {
      allow: ["serverAuth", "clientAuth"],
      default: ["serverAuth", "clientAuth"],
    },
    lifetime: { defaultSeconds: 7_776_000, maxSeconds: 7_776_000, minSeconds: 3600 },
    forced: {
      subject: { organization: "Example Corp", country: "US" },
      sans: { uri: ["spiffe://prod.example.com/cluster/prod-a"] },
      certificatePolicies: ["1.3.6.1.4.1.55555.1.1"],
    },
    quotas: { perHour: 100, perDay: 1000 },
  },
  policyDigest: "sha256:abc",
  quotas: { perHour: 100, perDay: 1000 },
  version: "v4",
  createdAt: "2026-11-01T00:00:00Z",
  createdBy: actor,
  updatedAt: "2026-11-02T00:00:00Z",
  updatedBy: actor,
};

const certSummary = {
  caId: "ca-0a1b2c3d",
  serial: "0a1b",
  status: "ISSUED",
  storedStatus: "ISSUED",
  fingerprint: "ff",
  subject: "CN=web",
  sans: { dns: ["web.example.com"] },
  keyAlgorithm: "ECDSA_P256",
  notBefore: "2026-11-01T00:00:00Z",
  notAfter: "2026-12-01T00:00:00Z",
  issuedAt: "2026-11-01T00:00:00Z",
  requester: {
    type: "consumer",
    id: "payments",
    consumerId: "payments",
    issuanceGrant: { name: "web", uid: "pkg-123", version: "v4" },
    asserted: { kubernetes: { namespace: "payments", name: "web", uid: "abcd" } },
  },
};

describe("CA schemas", () => {
  it("parses a pending external CA with its CSR", () => {
    const parsed = p.pkiCreateCaResponse.parse({
      ...baseCa,
      csrPem: "-----BEGIN CERTIFICATE REQUEST-----\nAA\n-----END CERTIFICATE REQUEST-----\n",
      warnings: [{ code: "ed25519_compatibility", message: "m" }],
    });
    expect(parsed.status).toBe("PENDING_CERTIFICATE");
    expect(parsed.csrPem).toContain("CERTIFICATE REQUEST");
  });

  it("parses an active external CA with a root CRL view", () => {
    const parsed = p.pkiCaDetail.parse({
      ...baseCa,
      status: "ACTIVE",
      certificatePem: pem,
      chainPem: pem,
      serial: "01",
      notBefore: "2026-11-01T00:00:00Z",
      notAfter: "2027-11-01T00:00:00Z",
      fingerprint: "ee",
      parent: { type: "external", id: "ext-1" },
      crlIssuers: [{ type: "external", id: "ext-1" }],
      effectiveConstraints: { extendedKeyUsages: ["serverAuth", "1.2.3.4"] },
      rootCrl: { extId: "ext-1", state: "MISSING" },
      crl: {
        number: 3,
        thisUpdate: "2026-11-01T00:00:00Z",
        nextUpdate: "2026-11-08T00:00:00Z",
        entryCount: 0,
        sha256: "aa",
        revision: 1,
        pendingRevocations: 0,
        state: "CURRENT",
      },
    });
    expect(parsed.rootCrl?.state).toBe("MISSING");
    expect(parsed.crlIssuers[0]?.type).toBe("external");
  });

  it("parses a ROOT", () => {
    const parsed = p.pkiCaDetail.parse({
      ...baseCa,
      kind: "ROOT",
      status: "ACTIVE",
      policy: { ...policy, issueLeaves: false, issueSubordinates: true },
      crlIssuers: [{ type: "ca", id: "ca-0a1b2c3d" }],
    });
    expect(parsed.kind).toBe("ROOT");
  });

  it("fails loudly on an unknown CA status", () => {
    expect(p.pkiCaDetail.safeParse({ ...baseCa, status: "SUSPENDED" }).success).toBe(false);
  });

  it("parses a list page", () => {
    expect(
      p.pkiCaListPage.parse({ cas: [baseCa], generatedAt: "2026-11-01T00:00:00Z" }).cas,
    ).toHaveLength(1);
  });
});

describe("external CA schemas", () => {
  it("parses a summary with dependents and environments", () => {
    const parsed = p.pkiExternalCaSummary.parse({
      extId: "ext-1",
      fingerprint: "ab",
      spkiSha256: "cd",
      subjectDn: "CN=root",
      subjectKeyIdentifier: "ef",
      notAfter: "2040-01-01T00:00:00Z",
      dependents: ["ca-0a1b2c3d"],
      environments: ["prod"],
      version: "v1",
      createdAt: "2026-11-01T00:00:00Z",
      crlState: "STALE",
      crl: { numberHex: "01", nextUpdate: "2026-11-02T00:00:00Z" },
    });
    expect(parsed.dependents).toEqual(["ca-0a1b2c3d"]);
  });

  it("parses an upload result with revokedCaIds", () => {
    const parsed = p.pkiUploadCrlResponse.parse({
      extId: "ext-1",
      changed: true,
      revokedCaIds: ["ca-0a1b2c3d"],
      crl: { numberHex: "02" },
    });
    expect(parsed.revokedCaIds).toEqual(["ca-0a1b2c3d"]);
  });
});

describe("grant schemas", () => {
  it("parses the normalized grant and accepts its policy as strict", () => {
    const parsed = p.pkiIssuanceGrant.parse(grant);
    expect(p.pkiGrantPolicyStrict.safeParse(parsed.policy).success).toBe(true);
  });

  it("rejects a policy with a field the console cannot edit", () => {
    expect(
      p.pkiGrantPolicyStrict.safeParse({
        ...grant.policy,
        futureField: true,
      }).success,
    ).toBe(false);
    expect(
      p.pkiGrantPolicyStrict.safeParse({
        ...grant.policy,
        names: { ...grant.policy.names, dns: { allow: [], other: 1 } },
      }).success,
    ).toBe(false);
  });

  it("keeps the list tolerant of a future policy field", () => {
    const page = p.pkiIssuanceGrantListPage.parse({
      grants: [{ ...grant, policy: { ...grant.policy, futureField: 1 } }],
      generatedAt: "2026-11-01T00:00:00Z",
    });
    expect(page.grants).toHaveLength(1);
  });

  it("parses a validation result", () => {
    const parsed = p.pkiGrantValidationResult.parse({
      valid: false,
      errors: [{ code: "invalid_name", path: "policy.names.dns.allow[1]", message: "m" }],
      warnings: [],
    });
    expect(parsed.errors[0]?.path).toBe("policy.names.dns.allow[1]");
  });
});

describe("evaluate schemas", () => {
  const context = {
    grant: { status: "ACTIVE", expired: false },
    ca: { status: "ACTIVE", keyState: "ACTIVE" },
    capacity: { count: 5, capacity: 100 },
    quotas: {
      grantHour: { count: 0, limit: 100 },
      grantDay: { count: 0, limit: 1000 },
      caHour: { count: 1, limit: 1000 },
    },
  };

  it("parses an allow with a plan", () => {
    const parsed = p.pkiEvaluateResponse.parse({
      decision: "allow",
      trace: [{ step: 1, name: "grant_state", outcome: "pass" }],
      plan: {
        keyAlgorithm: "ECDSA_P256",
        sans: { dns: ["a.example.com"] },
        subject: "CN=a.example.com",
        keyUsages: ["digitalSignature"],
        extendedKeyUsages: ["serverAuth"],
        certificatePolicies: [],
        notBefore: "2026-11-01T00:00:00Z",
        notAfter: "2026-12-01T00:00:00Z",
        lifetimeClamped: true,
        sanCritical: false,
      },
      context,
    });
    expect(parsed.plan?.lifetimeClamped).toBe(true);
  });

  it("parses a deny with the denied name", () => {
    const parsed = p.pkiEvaluateResponse.parse({
      decision: "deny",
      denial: {
        reason: "name_not_permitted",
        detail: "not allowed",
        deniedNameType: "dns",
        deniedName: "evil.example.com",
      },
      trace: [{ step: 3, name: "names", outcome: "deny", detail: "d" }],
      context,
    });
    expect(parsed.denial?.deniedName).toBe("evil.example.com");
  });
});

describe("certificate schemas", () => {
  it("parses a summary and a detail", () => {
    expect(p.pkiCertificateSummary.parse(certSummary).requester.id).toBe("payments");
    const detail = p.pkiCertificateDetail.parse({
      ...certSummary,
      status: "REVOKED",
      storedStatus: "REVOKED",
      revocation: { at: "2026-11-02T00:00:00Z", reason: "superseded" },
      certificatePem: pem,
      spkiSha256: "aa",
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: ["serverAuth"],
    });
    expect(detail.revocation?.reason).toBe("superseded");
  });

  it("parses a revoke response", () => {
    const parsed = p.pkiRevokeCertificateResponse.parse({
      certificate: {
        ...certSummary,
        certificatePem: pem,
        spkiSha256: "aa",
        keyUsages: [],
        extendedKeyUsages: [],
      },
      crlEntry: true,
      crlPublished: false,
      changed: true,
      crl: { number: 4, pendingRevocations: 1 },
    });
    expect(parsed.crlPublished).toBe(false);
  });

  it("parses an incomplete bulk revoke", () => {
    const parsed = p.pkiBulkRevokeResponse.parse({
      consumerId: "payments",
      issuanceGrant: "web",
      complete: false,
      revoked: 10,
      alreadyRevoked: 2,
      caIds: ["ca-0a1b2c3d"],
      crls: [{ caId: "ca-0a1b2c3d", crlPublished: false }],
    });
    expect(parsed.complete).toBe(false);
  });
});
