import { describe, expect, it } from "vitest";
import {
  draftFromGrant,
  draftProblems,
  draftSnapshot,
  draftToCreateRequest,
  draftToRequest,
  editableGrant,
  emptyDraft,
  issuePathToField,
  stableJson,
} from "./pki-grant-form";
import type { PkiIssuanceGrant } from "./pki-schemas";

// The normalized example from docs/reference/api/admin-pki.md, plus the
// `deny: []` the server writes for an object that has any rule list.
const grant = (): PkiIssuanceGrant => ({
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
  createdBy: { type: "human", id: "a" },
  updatedAt: "2026-11-02T00:00:00Z",
  updatedBy: { type: "human", id: "a" },
});

const fromGrant = (g: PkiIssuanceGrant) => {
  const policy = editableGrant(g);
  if (policy === undefined) {
    throw new Error("not editable");
  }
  return draftFromGrant(g, policy);
};

describe("grant round trip", () => {
  it("returns the stored policy and envelope exactly", () => {
    const g = grant();
    const request = draftToRequest(fromGrant(g));
    expect(stableJson(request)).toBe(
      stableJson({
        ...g.policy,
        caId: g.caId,
        status: g.status,
        displayName: g.displayName,
        expiresAt: g.expiresAt,
      }),
    );
  });

  it("is lossless for a minimal policy with no optional keys", () => {
    const g = grant();
    g.displayName = undefined;
    g.expiresAt = undefined;
    g.policy = {
      names: {},
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: {},
      lifetime: { defaultSeconds: 3600, maxSeconds: 3600 },
    };
    expect(stableJson(draftToRequest(fromGrant(g)))).toBe(
      stableJson({ ...g.policy, caId: g.caId, status: "ACTIVE" }),
    );
  });

  it("omits displayName when it is emptied", () => {
    const draft = fromGrant(grant());
    draft.displayName = "   ";
    expect("displayName" in draftToRequest(draft)).toBe(false);
  });

  it("changes expiresAt only when the input changes", () => {
    const draft = fromGrant(grant());
    draft.expiresAt = "2028-01-02T03:04";
    expect(draftToRequest(draft).expiresAt).toBe(new Date("2028-01-02T03:04").toISOString());
    draft.expiresAt = "";
    expect("expiresAt" in draftToRequest(draft)).toBe(false);
  });

  it("writes edits made to list fields", () => {
    const draft = fromGrant(grant());
    draft.dnsAllow = "a.example.com\n\n  b.example.com  ";
    expect(draftToRequest(draft).names.dns?.allow).toEqual(["a.example.com", "b.example.com"]);
  });
});

describe("editableGrant", () => {
  it("rejects an unknown policy key", () => {
    const g = grant();
    g.policy = { ...g.policy, futureField: true };
    expect(editableGrant(g)).toBeUndefined();
  });

  it("rejects an unknown nested key", () => {
    const g = grant();
    g.policy = { ...g.policy, names: { ...(g.policy.names as object), srv: {} } };
    expect(editableGrant(g)).toBeUndefined();
  });

  it("accepts the normalized example", () => {
    expect(editableGrant(grant())).toBeDefined();
  });
});

describe("create drafts", () => {
  it("builds a create request with the name and omits empty optional fields", () => {
    const draft = emptyDraft({
      caId: "ca-1",
      policy: { maxLeafLifetimeSeconds: 3600 } as never,
    });
    draft.name = " web ";
    draft.dnsAllow = "*.example.com";
    const request = draftToCreateRequest(draft);
    expect(request.name).toBe("web");
    expect(request.caId).toBe("ca-1");
    expect(request.lifetime).toEqual({ defaultSeconds: 3600, maxSeconds: 3600, minSeconds: 3600 });
    expect("subject" in request).toBe(false);
    expect("forced" in request).toBe(false);
    expect(request.names).toEqual({ dns: { allow: ["*.example.com"] } });
  });

  it("reports local problems", () => {
    const draft = emptyDraft();
    draft.lifetimeMax = "soon";
    expect(draftProblems(draft)).toEqual(
      expect.arrayContaining(["Choose a CA.", expect.stringContaining("Maximum lifetime")]),
    );
  });
});

describe("draftSnapshot", () => {
  it("ignores the remembered origin but sees edits", () => {
    const a = fromGrant(grant());
    const b = fromGrant(grant());
    expect(draftSnapshot(a)).toBe(draftSnapshot(b));
    b.dnsDeny = "";
    expect(draftSnapshot(a)).not.toBe(draftSnapshot(b));
  });
});

describe("issuePathToField", () => {
  it("maps list paths to a field and zero-based line", () => {
    expect(issuePathToField("policy.names.dns.allow[1]")).toEqual({ field: "dnsAllow", line: 1 });
    expect(issuePathToField("policy.names.ip.deny[0]")).toEqual({ field: "ipDeny", line: 0 });
    expect(issuePathToField("policy.forced.sans.uri[2]")).toEqual({ field: "forcedUri", line: 2 });
  });

  it("maps scalar, record and envelope paths", () => {
    expect(issuePathToField("policy.lifetime.maxSeconds")).toEqual({ field: "lifetimeMax" });
    expect(issuePathToField("policy.subject.allow.organizationalUnit[0]")).toEqual({
      field: "subjectAllow.organizationalUnit",
      line: 0,
    });
    expect(issuePathToField("policy.forced.subject.country")).toEqual({
      field: "forcedSubject.country",
    });
    expect(issuePathToField("caId")).toEqual({ field: "caId" });
    expect(issuePathToField("something.else")).toEqual({ field: "general" });
  });
});
