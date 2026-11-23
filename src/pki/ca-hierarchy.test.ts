import { DecryptCommand, GenerateDataKeyCommand } from "@aws-sdk/client-kms";
import {
  parseCertificate,
  verifyCertificateSignature,
} from "./asn1/certificate";
import { parseCrl, verifyCrlSignature } from "./asn1/crl";
import { fromPem } from "./asn1/pem";
import { drainPoint, isDrained } from "./crl-service";
import type { CaRecord } from "./types";
import {
  admin,
  childBody,
  hierarchyHarness,
  rootBody,
  type HierarchyHarness,
} from "./__fixtures__/hierarchy-harness";
import { errorOf } from "./__fixtures__/issuance-harness";

const day = 86_400_000;

const certOf = (ca: CaRecord) =>
  parseCertificate(fromPem(ca.certificatePem!, "CERTIFICATE"));

const kmsCalls = (h: HierarchyHarness, type: "decrypt" | "generate") =>
  h.kms.send.mock.calls
    .map((call) => call[0])
    .filter((command) =>
      type === "decrypt"
        ? command instanceof DecryptCommand
        : command instanceof GenerateDataKeyCommand,
    ) as { input: { EncryptionContext?: { caId?: string } } }[];

const errorDetails = (error: { details?: { reason?: string } }) =>
  error.details?.reason;

describe("ROOT creation", () => {
  it("self-signs the root and its first CRL and wraps the key once, with no Decrypt", async () => {
    const h = hierarchyHarness();
    const result = await h.service.create(admin, h.key(), rootBody());
    const root = h.state.cas.get(result.body.caId as string)!;
    const cert = certOf(root);
    expect(result.status).toBe(201);
    expect(root).toMatchObject({
      kind: "ROOT",
      status: "ACTIVE",
      requested: { pathLen: 1 },
      maxIssueLifetimeEverSeconds: 0,
      policy: { issueLeaves: false, issueSubordinates: true },
      crlIssuers: [{ type: "ca", id: root.caId }],
    });
    expect(root.parent).toBeUndefined();
    expect(root.parentCaId).toBeUndefined();
    expect(root.chainPem).toBe(root.certificatePem);
    expect(root.effective).toEqual({
      nameConstraints: {
        permitted: [{ type: "dns", value: "example.com" }],
        excluded: [],
      },
      extendedKeyUsages: ["1.3.6.1.5.5.7.3.1"],
    });
    expect(cert.basicConstraints).toMatchObject({ ca: true, pathLen: 1 });
    expect(cert.issuerDer.equals(cert.subjectDer)).toBe(true);
    expect(verifyCertificateSignature(cert, cert.spkiDer)).toBe(true);
    expect(root.serial).toBe(cert.serialHex);
    expect(root.fingerprint).toBe(cert.fingerprint);
    expect(root.subjectKeyIdentifier).toBe(
      cert.subjectKeyIdentifier!.toString("hex"),
    );
    // CRL number 1 is stored and verifies under the root's key.
    const crl = h.state.crls.get(root.caId)!;
    expect(crl).toMatchObject({ revision: 0, lastNumber: 1 });
    expect(crl.published!.objectKey).toMatch(
      new RegExp(`^crl/${root.caId}/1-[0-9a-f]{16}\\.crl$`),
    );
    const stored = h.state.objects.get(crl.published!.objectKey)!;
    expect(verifyCrlSignature(parseCrl(stored), cert.spkiDer)).toBe(true);
    // Response: no CSR, one warning, a create audit target with the anchor.
    expect(result.body.csrPem).toBeUndefined();
    expect(result.body.warnings).toEqual([
      expect.objectContaining({ code: "external_root_recommended" }),
    ]);
    expect(result.auditTarget).toMatchObject({
      kind: "ROOT",
      fingerprint: cert.fingerprint,
      serial: cert.serialHex,
      anchorFingerprint: cert.fingerprint,
    });
    expect(result.etag).toBe(root.version);
    // One GenerateDataKey for the root's own key, no Decrypt.
    expect(kmsCalls(h, "generate")).toHaveLength(1);
    expect(kmsCalls(h, "decrypt")).toHaveLength(0);
    expect(
      h.kms.handedOut.every((buffer) => buffer.every((byte) => byte === 0)),
    ).toBe(true);
  });

  it("adds the Ed25519 warning before the root warning", async () => {
    const h = hierarchyHarness();
    const result = await h.service.create(
      admin,
      h.key(),
      rootBody({ keyAlgorithm: "ED25519" }),
    );
    expect(
      (result.body.warnings as { code: string }[]).map((w) => w.code),
    ).toEqual(["ed25519_compatibility", "external_root_recommended"]);
  });

  it("zeroes the plaintext private key before any storage call", async () => {
    const wrapped =
      jest.requireActual<typeof import("./wrapped-keys")>("./wrapped-keys");
    const original = wrapped.generateCaKeyPair;
    const seen: Buffer[] = [];
    const spy = jest
      .spyOn(wrapped, "generateCaKeyPair")
      .mockImplementation(async (algorithm) => {
        const real = await original(algorithm);
        seen.push(real.privateKeyDer);
        return real;
      });
    try {
      const h = hierarchyHarness();
      h.put.mockImplementation(async () => {
        // The first storage call: the key must already be zeroed.
        expect(seen.every((buffer) => buffer.every((byte) => byte === 0))).toBe(
          true,
        );
        return {};
      });
      await h.createRoot();
      expect(seen).toHaveLength(1);
      const root = [...h.state.cas.values()][0]!;
      h.put.mockClear();
      await h.createChild(root.caId);
      expect(seen).toHaveLength(2);
      expect(seen.every((buffer) => buffer.every((byte) => byte === 0))).toBe(
        true,
      );
    } finally {
      spy.mockRestore();
    }
  });

  it("replays the same request and refuses a different one under the same key", async () => {
    const h = hierarchyHarness();
    const key = h.key();
    const first = await h.service.create(admin, key, rootBody());
    const again = await h.service.create(admin, key, rootBody());
    expect(again.body.caId).toBe(first.body.caId);
    expect(h.pki.createCa).toHaveBeenCalledTimes(1);
    expect(
      await errorOf(
        h.service.create(admin, key, rootBody({ validitySeconds: 7_776_000 })),
      ),
    ).toMatchObject({ statusCode: 409 });
  });

  it("refuses a subject claimed by an external root and the identity root's subject", async () => {
    const h = hierarchyHarness();
    h.pki.getSubjectClaim.mockResolvedValueOnce({ ownerType: "external" });
    expect(
      await errorOf(h.service.create(admin, h.key(), rootBody())),
    ).toMatchObject({
      code: "ca_subject_in_use",
      details: { reason: "subject_claimed" },
    });
    expect(
      await errorOf(
        h.service.create(
          admin,
          h.key(),
          rootBody({ subject: { commonName: "Hemlig test Issuing Root" } }),
        ),
      ),
    ).toMatchObject({
      code: "ca_subject_in_use",
      details: { reason: "identity_root_reserved" },
    });
  });

  it("refuses a name that is already in use", async () => {
    const h = hierarchyHarness();
    await h.createRoot();
    expect(
      await errorOf(
        h.service.create(
          admin,
          h.key(),
          rootBody({ subject: { commonName: "Another Root" } }),
        ),
      ),
    ).toMatchObject({ code: "conflict", details: { reason: "name_in_use" } });
  });
});

describe("INTERMEDIATE creation", () => {
  it("signs under the root with inherited constraints and records the parent's inventory row", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    const result = await h.service.create(admin, h.key(), childBody(root.caId));
    const child = h.state.cas.get(result.body.caId as string)!;
    const cert = certOf(child);
    const rootCert = certOf(root);
    expect(result.status).toBe(201);
    expect(child).toMatchObject({
      kind: "INTERMEDIATE",
      status: "ACTIVE",
      parent: { type: "ca", id: root.caId },
      parentCaId: root.caId,
      requested: { pathLen: 0 },
      crlIssuers: [
        { type: "ca", id: child.caId },
        { type: "ca", id: root.caId },
      ],
      policy: { issueLeaves: true, issueSubordinates: false },
    });
    expect(child.chainPem).toBe(root.certificatePem!.trim() + "\n");
    expect(child.effective).toEqual(root.effective);
    expect(child.maxIssueLifetimeEverSeconds).toBe(
      child.policy.maxLeafLifetimeSeconds,
    );
    expect(verifyCertificateSignature(cert, rootCert.spkiDer)).toBe(true);
    expect(cert.issuerDer.equals(rootCert.subjectDer)).toBe(true);
    expect(
      cert.authorityKeyIdentifier!.equals(rootCert.subjectKeyIdentifier!),
    ).toBe(true);
    expect(cert.basicConstraints).toMatchObject({ ca: true, pathLen: 0 });
    expect(cert.nameConstraints?.permitted).toEqual([
      { type: "dns", value: "example.com" },
    ]);
    expect(cert.extendedKeyUsage).toEqual(["1.3.6.1.5.5.7.3.1"]);
    // The CRL #1 of the child verifies under the child's own key.
    const crl = h.state.crls.get(child.caId)!;
    expect(
      verifyCrlSignature(
        parseCrl(h.state.objects.get(crl.published!.objectKey)!),
        cert.spkiDer,
      ),
    ).toBe(true);
    // The root's inventory row.
    const row = h.state.certs.get(`${root.caId}#${child.serial}`)!;
    expect(row).toMatchObject({
      caId: root.caId,
      status: "ISSUED",
      isCa: true,
      childCaId: child.caId,
      keyUsages: ["keyCertSign", "cRLSign"],
      extendedKeyUsages: ["serverAuth"],
      fingerprint: cert.fingerprint,
      requester: { type: "human", id: admin.id },
    });
    expect(result.auditTarget).toMatchObject({
      parentCaId: root.caId,
      fingerprint: cert.fingerprint,
      anchorFingerprint: rootCert.fingerprint,
    });
    expect(result.body.warnings).toBeUndefined();
    // Decrypt ran once, with the root's context; the child's own key was generated and wrapped.
    expect(kmsCalls(h, "decrypt")).toHaveLength(1);
    expect(kmsCalls(h, "decrypt")[0]!.input.EncryptionContext!.caId).toBe(
      root.caId,
    );
  });

  it("raises the root's maximum with the first child and keeps it for a shorter one", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    expect(root.maxIssueLifetimeEverSeconds).toBe(0);
    const first = await h.createChild(root.caId);
    const lifetime = Math.ceil(
      (Date.parse(first.notAfter!) - Date.parse(first.notBefore!)) / 1000,
    );
    expect(h.pki.createIntermediateCa.mock.calls[0]![0].parent).toMatchObject({
      loadedMaxIssueLifetimeEverSeconds: 0,
      childLifetimeSeconds: lifetime,
      version: root.version,
    });
    expect(h.state.cas.get(root.caId)).toMatchObject({
      maxIssueLifetimeEverSeconds: lifetime,
      version: root.version,
    });
    await h.createChild(root.caId, {
      name: "hemlig-issuing-2",
      subject: { commonName: "Hemlig Issuing CA 2" },
      validitySeconds: 2_592_000 * 2,
    });
    const second = h.pki.createIntermediateCa.mock.calls[1]![0].parent;
    expect(second.loadedMaxIssueLifetimeEverSeconds).toBe(lifetime);
    expect(second.childLifetimeSeconds).toBeLessThan(lifetime);
    expect(h.state.cas.get(root.caId)!.maxIssueLifetimeEverSeconds).toBe(
      lifetime,
    );
  });

  it("clamps the child to a short root and charges the root's quotas", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot({ validitySeconds: 7_776_000 });
    const child = await h.createChild(root.caId);
    expect(child.notAfter).toBe(root.notAfter);
    expect(
      h.state.certs.get(`${root.caId}#${child.serial}`)!.lifetimeClamped,
    ).toBe(true);
    expect([...h.state.quotas.values()]).toEqual([1, 1]);
  });

  it("derives a requested subset and refuses broader constraints", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    const narrow = await h.createChild(root.caId, {
      requestedConstraints: {
        nameConstraints: { permitted: { dns: ["api.example.com"] } },
      },
    });
    expect(certOf(narrow).nameConstraints?.permitted).toEqual([
      { type: "dns", value: "api.example.com" },
    ]);
    expect(
      await errorOf(
        h.service.create(
          admin,
          h.key(),
          childBody(root.caId, {
            name: "hemlig-issuing-2",
            subject: { commonName: "Issuing 2" },
            requestedConstraints: {
              nameConstraints: { permitted: { dns: ["example.org"] } },
            },
          }),
        ),
      ),
    ).toMatchObject({
      statusCode: 400,
      details: { reason: "name_constraints_broader_than_parent" },
    });
    expect(
      await errorOf(
        h.service.create(
          admin,
          h.key(),
          childBody(root.caId, {
            name: "hemlig-issuing-3",
            subject: { commonName: "Issuing 3" },
            requestedConstraints: {
              extendedKeyUsages: ["serverAuth", "clientAuth"],
            },
          }),
        ),
      ),
    ).toMatchObject({
      statusCode: 400,
      details: { reason: "extended_key_usage_broader_than_parent" },
    });
  });

  describe("parent checks through the service", () => {
    const attempt = (
      h: HierarchyHarness,
      parentCaId: string,
      environment = "prod",
    ) =>
      errorOf(
        h.service.create(
          admin,
          h.key(),
          childBody(parentCaId, {
            environment,
            name: "child-x",
            subject: { commonName: "X" },
          }),
        ),
      );

    it("refuses a missing parent, another environment and a non-ROOT parent", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      expect(await attempt(h, "ca-unknown-parent")).toMatchObject({
        statusCode: 404,
        details: { reason: "parent_not_found" },
      });
      expect(await attempt(h, root.caId, "staging")).toMatchObject({
        statusCode: 409,
        details: { reason: "parent_environment_mismatch" },
      });
      const child = await h.createChild(root.caId);
      expect(await attempt(h, child.caId)).toMatchObject({
        code: "ca_not_active",
        details: { reason: "subordinates_not_permitted" },
      });
    });

    it.each([
      ["retired", { status: "RETIRED" }, "ca_not_active"],
      ["revoked", { status: "REVOKED" }, "ca_not_active"],
    ])("refuses a %s parent", async (reason, patch, code) => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      h.state.cas.set(root.caId, { ...root, ...patch } as CaRecord);
      expect(await attempt(h, root.caId)).toMatchObject({
        code,
        details: { reason },
      });
    });

    it("refuses an expired and a not-yet-valid parent and an unavailable key", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      h.state.cas.set(root.caId, {
        ...root,
        notAfter: new Date(Date.now() - day).toISOString(),
      });
      expect(await attempt(h, root.caId)).toMatchObject({
        details: { reason: "expired" },
      });
      h.state.cas.set(root.caId, {
        ...root,
        notBefore: new Date(Date.now() + day).toISOString(),
      });
      expect(await attempt(h, root.caId)).toMatchObject({
        details: { reason: "not_yet_valid" },
      });
      h.state.cas.set(root.caId, {
        ...root,
        key: { ...root.key, state: "DISABLED" },
      });
      expect(await attempt(h, root.caId)).toMatchObject({
        code: "ca_key_unavailable",
      });
    });

    it("refuses a root with less than 30 days left", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      h.state.cas.set(root.caId, {
        ...root,
        notAfter: new Date(Date.now() + 10 * day).toISOString(),
      });
      expect(await attempt(h, root.caId)).toMatchObject({
        statusCode: 409,
        details: { reason: "parent_validity_insufficient" },
      });
    });

    it("refuses a child subject equal to the root's", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      expect(
        await errorOf(
          h.service.create(
            admin,
            h.key(),
            childBody(root.caId, { subject: rootBody().subject }),
          ),
        ),
      ).toMatchObject({
        code: "ca_subject_in_use",
        details: { reason: "subject_claimed" },
      });
    });
  });

  describe("capacity and quota", () => {
    it("refuses at capacity, and a stored winner replays instead", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot({ policy: { capacity: 1 } });
      const key = h.key();
      const body = childBody(root.caId);
      const first = await h.service.create(admin, key, body);
      h.state.certificatesSince = 1;
      h.state.crls.set(root.caId, {
        ...h.state.crls.get(root.caId)!,
        capacity: undefined,
      });
      // The same request replays before the pre-check.
      const again = await h.service.create(admin, key, body);
      expect(again.body.caId).toBe(first.body.caId);
      expect(
        await errorOf(
          h.service.create(
            admin,
            h.key(),
            childBody(root.caId, {
              name: "hemlig-issuing-2",
              subject: { commonName: "Issuing 2" },
            }),
          ),
        ),
      ).toMatchObject({ code: "ca_capacity_exceeded" });
    });

    it("answers 429 with Retry-After when a counter is full", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot({ policy: { issuancePerHour: 1 } });
      await h.createChild(root.caId);
      const second = childBody(root.caId, {
        name: "hemlig-issuing-2",
        subject: { commonName: "Issuing 2" },
      });
      const refused = await errorOf(h.service.create(admin, h.key(), second));
      expect(refused).toMatchObject({
        statusCode: 429,
        code: "issuance_rate_limited",
        details: { reason: "ca_hour" },
      });
      expect(refused.headers?.["retry-after"]).toBeDefined();
    });

    it("replays a winner that appears between the first look and the pre-check", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot({ policy: { issuancePerHour: 1 } });
      const key = h.key();
      const body = childBody(root.caId);
      const winner = await h.service.create(admin, key, body);
      h.repository.getIdempotency.mockResolvedValueOnce(undefined);
      const replayed = await h.service.create(admin, key, body);
      expect(replayed.body.caId).toBe(winner.body.caId);
      expect(h.pki.createIntermediateCa).toHaveBeenCalledTimes(1);
    });

    it("maps a counter exhausted at commit to 429, or to the winner", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      h.state.createOutcomes.push({
        kind: "quotaExhausted",
        quotas: ["adminHour"],
        retryAfterSeconds: 77,
      });
      expect(
        await errorOf(h.service.create(admin, h.key(), childBody(root.caId))),
      ).toMatchObject({
        statusCode: 429,
        details: { reason: "admin_hour", retryAfterSeconds: 77 },
      });
      // A winner under the same key: the commit loses to it and the request replays.
      const key = h.key();
      const body = childBody(root.caId);
      const winner = await h.service.create(admin, key, body);
      h.state.createOutcomes.push({
        kind: "quotaExhausted",
        quotas: ["caHour"],
        retryAfterSeconds: 5,
      });
      h.repository.getIdempotency.mockResolvedValueOnce(undefined);
      const replayed = await h.service.create(admin, key, body);
      expect(replayed.body.caId).toBe(winner.body.caId);
    });
  });

  describe("commit outcomes", () => {
    it("keeps the key, CRL and envelope across a concurrent parent policy change and signs twice", async () => {
      const wrapped =
        jest.requireActual<typeof import("./wrapped-keys")>("./wrapped-keys");
      const generate = jest.spyOn(wrapped, "generateCaKeyPair");
      try {
        const h = hierarchyHarness();
        const root = await h.createRoot();
        generate.mockClear();
        h.put.mockClear();
        const decryptsBefore = kmsCalls(h, "decrypt").length;
        h.pki.createIntermediateCa.mockImplementationOnce(async () => {
          await h.service.update(admin, h.key(), root.caId, root.version, {
            policy: { issuancePerHour: 500 },
          });
          return { kind: "parentChanged" };
        });
        const result = await h.service.create(
          admin,
          h.key(),
          childBody(root.caId),
        );
        const calls = h.pki.createIntermediateCa.mock.calls.map(
          (call) => call[0],
        );
        expect(calls).toHaveLength(2);
        expect(generate).toHaveBeenCalledTimes(1);
        expect(h.put).toHaveBeenCalledTimes(1);
        expect(calls[0]!.parent).toMatchObject({
          issuancePerHour: 2000,
          version: root.version,
        });
        const reread = h.state.cas.get(root.caId)!;
        expect(calls[1]!.parent).toMatchObject({
          issuancePerHour: 500,
          version: reread.version,
        });
        expect(reread.version).not.toBe(root.version);
        expect(calls[1]!.ca.caId).toBe(calls[0]!.ca.caId);
        expect(calls[1]!.ca.key).toEqual(calls[0]!.ca.key);
        expect(calls[1]!.crl).toEqual(calls[0]!.crl);
        expect(calls[1]!.certificate.serial).not.toBe(
          calls[0]!.certificate.serial,
        );
        expect(kmsCalls(h, "decrypt").length - decryptsBefore).toBe(2);
        expect(result.status).toBe(201);
        expect(
          [...h.state.cas.values()].filter((ca) => ca.kind === "INTERMEDIATE"),
        ).toHaveLength(1);
        expect(reread.policy.issueLeaves).toBe(false);
      } finally {
        generate.mockRestore();
      }
    });

    it("reports a parent retired between attempts", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      h.pki.createIntermediateCa.mockImplementationOnce(async () => {
        h.state.cas.set(root.caId, { ...root, status: "RETIRED" });
        return { kind: "parentChanged" };
      });
      expect(
        await errorOf(h.service.create(admin, h.key(), childBody(root.caId))),
      ).toMatchObject({
        code: "ca_not_active",
        details: { reason: "retired" },
      });
    });

    it("answers 503 after three parent changes", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      for (let i = 0; i < 3; i += 1) {
        h.state.createOutcomes.push({ kind: "parentChanged" });
      }
      expect(
        await errorOf(h.service.create(admin, h.key(), childBody(root.caId))),
      ).toMatchObject({ statusCode: 503 });
      expect(h.pki.createIntermediateCa).toHaveBeenCalledTimes(3);
    });

    it("signs again with a new serial after a serial collision", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      h.state.createOutcomes.push({ kind: "serialCollision" });
      await h.service.create(admin, h.key(), childBody(root.caId));
      const [first, second] = h.pki.createIntermediateCa.mock.calls.map(
        (call) => call[0],
      );
      expect(second!.certificate.serial).not.toBe(first!.certificate.serial);
      expect(second!.ca.caId).toBe(first!.ca.caId);
    });

    it("replays a request another request committed first", async () => {
      const h = hierarchyHarness();
      const root = await h.createRoot();
      const key = h.key();
      const body = childBody(root.caId);
      const first = await h.service.create(admin, key, body);
      h.state.createOutcomes.push({ kind: "replay" });
      h.repository.getIdempotency.mockResolvedValueOnce(undefined);
      const again = await h.service.create(admin, key, body);
      expect(again.body.caId).toBe(first.body.caId);
    });
  });
});

describe("CA revoke of an INTERMEDIATE", () => {
  const setup = async (options: { now?: Date } = {}) => {
    const h = hierarchyHarness(options);
    const root = await h.createRoot();
    const child = await h.createChild(root.caId);
    return { h, root, child };
  };

  it("revokes on the root's CRL and publishes it inline", async () => {
    const { h, root, child } = await setup();
    const result = await h.service.revoke(admin, h.key(), child.caId, {
      reason: "caCompromise",
    });
    expect(result.status).toBe(200);
    expect(result.body).toMatchObject({
      changed: true,
      crlEntry: true,
      crlPublished: true,
      crlNumber: 2,
      revokedCaIds: [child.caId],
      complete: true,
      ca: { status: "REVOKED", revocationReason: "caCompromise" },
    });
    expect(h.state.cas.get(child.caId)).toMatchObject({
      status: "REVOKED",
      revocationSource: "HEMLIG",
      revocationEvidence: `parent:${root.caId}`,
      key: { state: "DISABLED" },
    });
    expect(h.state.certs.get(`${root.caId}#${child.serial}`)!.status).toBe(
      "REVOKED",
    );
    expect(h.state.entries.get(`${root.caId}#${child.serial}`)).toMatchObject({
      reason: "caCompromise",
    });
    expect(h.crls.publish).toHaveBeenCalledWith(
      expect.objectContaining({ caId: root.caId }),
      expect.objectContaining({ trigger: "inline" }),
    );
    expect(result.etag).toBe(h.state.cas.get(child.caId)!.version);
    expect(result.auditTarget).toMatchObject({
      caId: child.caId,
      reason: "caCompromise",
      changed: "true",
      crlEntry: "true",
      crlPublished: "true",
      crlNumber: "2",
      parentCaId: root.caId,
      revokedCaIds: child.caId,
      complete: "true",
    });
  });

  it("passes the invalidity date to the entry", async () => {
    const { h, root, child } = await setup();
    const date = new Date(Date.now() - day).toISOString();
    await h.service.revoke(admin, h.key(), child.caId, {
      reason: "caCompromise",
      invalidityDate: date,
    });
    expect(h.pki.revokeIntermediateCa.mock.calls[0]![0]).toMatchObject({
      reason: "caCompromise",
      invalidityDate: date,
      evidence: `parent:${root.caId}`,
    });
  });

  it("writes no entry, bumps no revision and publishes nothing for an expired child", async () => {
    const start = new Date(Date.now() - 40 * day);
    const h = hierarchyHarness({ now: start });
    const root = await h.createRoot();
    const child = await h.createChild(root.caId, {
      validitySeconds: 2_592_000,
    });
    h.clock.now = new Date();
    const revision = h.state.crls.get(root.caId)!.revision;
    const result = await h.service.revoke(admin, h.key(), child.caId, {});
    expect(result.body).toMatchObject({
      changed: true,
      crlEntry: false,
      crlPublished: false,
    });
    expect(result.body.crlNumber).toBeUndefined();
    expect(h.pki.revokeIntermediateCa.mock.calls[0]![0].row).toMatchObject({
      mode: "expired",
    });
    expect(h.state.entries.size).toBe(0);
    expect(h.state.crls.get(root.caId)!.revision).toBe(revision);
    expect(h.crls.publish).not.toHaveBeenCalled();
    expect(h.state.certs.get(`${root.caId}#${child.serial}`)!.status).toBe(
      "REVOKED",
    );
    expect(h.state.cas.get(child.caId)!.status).toBe("REVOKED");
  });

  it("uses inventory mode when the parent is REVOKED", async () => {
    const { h, root, child } = await setup();
    h.state.cas.set(root.caId, { ...root, status: "REVOKED" });
    const result = await h.service.revoke(admin, h.key(), child.caId, {});
    expect(h.pki.revokeIntermediateCa.mock.calls[0]![0].row).toMatchObject({
      mode: "inventory",
    });
    expect(result.body).toMatchObject({
      changed: true,
      crlEntry: false,
      crlPublished: false,
    });
    expect(h.state.entries.size).toBe(0);
    expect(h.crls.publish).not.toHaveBeenCalled();
  });

  it("revokes without a row item when the row is gone", async () => {
    const { h, root, child } = await setup();
    h.state.certs.delete(`${root.caId}#${child.serial}`);
    const result = await h.service.revoke(admin, h.key(), child.caId, {});
    expect(h.pki.revokeIntermediateCa.mock.calls[0]![0].row).toBeUndefined();
    expect(result.body).toMatchObject({ changed: true, crlEntry: false });
  });

  it("is a no-op for a child that is already REVOKED", async () => {
    const { h, child } = await setup();
    await h.service.revoke(admin, h.key(), child.caId, {});
    h.pki.revokeIntermediateCa.mockClear();
    const result = await h.service.revoke(admin, h.key(), child.caId, {
      reason: "superseded",
    });
    expect(h.pki.revokeIntermediateCa).not.toHaveBeenCalled();
    expect(result.body).toMatchObject({
      changed: false,
      crlEntry: true,
      revokedCaIds: [],
      complete: true,
    });
  });

  it("reruns after a profile cancellation and gives up after three", async () => {
    const { h, child } = await setup();
    h.pki.revokeIntermediateCa.mockResolvedValueOnce({
      kind: "canceled",
      failed: ["profile"],
    });
    const result = await h.service.revoke(admin, h.key(), child.caId, {});
    expect(result.body.changed).toBe(true);
    expect(h.pki.revokeIntermediateCa).toHaveBeenCalledTimes(2);

    const second = await setup();
    second.h.pki.revokeIntermediateCa.mockResolvedValue({
      kind: "canceled",
      failed: ["profile"],
    });
    expect(
      await errorOf(
        second.h.service.revoke(admin, second.h.key(), second.child.caId, {}),
      ),
    ).toMatchObject({ statusCode: 503 });
    expect(second.h.pki.revokeIntermediateCa).toHaveBeenCalledTimes(3);
  });

  it("replays with the same body and recomputes crlPublished", async () => {
    const { h, child } = await setup();
    const key = h.key();
    const first = await h.service.revoke(admin, key, child.caId, {
      reason: "superseded",
    });
    const again = await h.service.revoke(admin, key, child.caId, {
      reason: "superseded",
    });
    expect(h.pki.revokeIntermediateCa).toHaveBeenCalledTimes(1);
    expect(again.body).toMatchObject({
      changed: true,
      crlEntry: true,
      crlPublished: true,
      crlNumber: first.body.crlNumber,
      revokedCaIds: [child.caId],
    });
    expect(again.shouldWriteTerminalAudit).toBe(true);
    // The recorded revision is the root's, after the bump; the replay still sees the publication.
    expect(h.state.human.get(key)!.result).toMatchObject({ crlRevision: 1 });
    expect(again.body.crlNumber).toBe(2);
    expect(
      await errorOf(
        h.service.revoke(admin, key, child.caId, { reason: "caCompromise" }),
      ),
    ).toMatchObject({ statusCode: 409 });
  });

  it("refuses an EXTERNAL_INTERMEDIATE, keyCompromise and an unknown CA", async () => {
    const { h } = await setup();
    h.state.cas.set("ca-external-one", {
      caId: "ca-external-one",
      kind: "EXTERNAL_INTERMEDIATE",
      status: "ACTIVE",
    } as CaRecord);
    expect(
      await errorOf(h.service.revoke(admin, h.key(), "ca-external-one", {})),
    ).toMatchObject({ statusCode: 409, details: { reason: "revoke_at_root" } });
    expect(
      await errorOf(
        h.service.revoke(admin, h.key(), "ca-external-one", {
          reason: "keyCompromise",
        }),
      ),
    ).toMatchObject({ statusCode: 400, details: { reason: "invalid_reason" } });
    expect(
      await errorOf(h.service.revoke(admin, h.key(), "ca-missing-one", {})),
    ).toMatchObject({ statusCode: 404 });
  });
});

describe("local distrust of a ROOT", () => {
  const family = async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    const other = await h.createRoot({
      name: "other-root",
      subject: { commonName: "Other Root" },
    });
    const name = (n: number) => ({
      name: `hemlig-issuing-${n}`,
      subject: { commonName: `Hemlig Issuing CA ${n}` },
    });
    const c1 = await h.createChild(root.caId, name(1));
    const c2 = await h.createChild(root.caId, name(2));
    const c3 = await h.createChild(root.caId, name(3));
    const foreign = await h.createChild(other.caId, name(4));
    h.state.cas.set(c2.caId, {
      ...c2,
      status: "RETIRED",
      retiredAt: c2.createdAt,
    });
    await h.service.revoke(admin, h.key(), c3.caId, {});
    return { h, root, other, c1, c2, c3, foreign };
  };

  it("revokes the root with its key disabled, then flips ACTIVE and RETIRED children only", async () => {
    const { h, root, c1, c2, c3, foreign } = await family();
    h.crls.publish.mockClear();
    const result = await h.service.revoke(admin, h.key(), root.caId, {
      reason: "caCompromise",
    });
    expect(result.status).toBe(200);
    expect(h.state.cas.get(root.caId)).toMatchObject({
      status: "REVOKED",
      revocationSource: "HEMLIG",
      revocationEvidence: "local-distrust",
      revocationReason: "caCompromise",
      key: { state: "DISABLED" },
    });
    expect(h.pki.distrustRootCa).toHaveBeenCalledTimes(1);
    expect(result.body).toMatchObject({
      changed: true,
      crlEntry: false,
      crlPublished: false,
      complete: true,
      revokedCaIds: [c1.caId, c2.caId, c3.caId].sort(),
    });
    for (const child of [c1, c2]) {
      expect(h.state.cas.get(child.caId)).toMatchObject({
        status: "REVOKED",
        revocationEvidence: `ancestor:${root.caId}`,
        revocationReason: "caCompromise",
        key: { state: expect.stringMatching(/DISABLED/) },
      });
    }
    expect(h.state.cas.get(c3.caId)!.revocationEvidence).toBe(
      `parent:${root.caId}`,
    );
    expect(h.state.cas.get(foreign.caId)!.status).toBe("ACTIVE");
    expect(
      h.crls.publish.mock.calls.every(([ca]) => ca.caId !== root.caId),
    ).toBe(true);
    expect(result.auditTarget.revokedCaIds).toBe(
      [c1.caId, c2.caId, c3.caId].sort().join(","),
    );
  });

  it("treats a failed read in the walk as incomplete, not as an error", async () => {
    const { h, root, c1 } = await family();
    const real = h.pki.getCa.getMockImplementation()!;
    h.pki.getCa.mockImplementation(async (id: string) => {
      if (id === c1.caId) {
        throw new Error("throttled");
      }
      return real(id);
    });
    const result = await h.service.revoke(admin, h.key(), root.caId, {});
    expect(result.status).toBe(200);
    expect(result.body.complete).toBe(false);
    expect(result.body.revokedCaIds).not.toContain(c1.caId);
    expect(h.state.cas.get(root.caId)!.status).toBe("REVOKED");
  });

  it("refuses an invalidity date for a ROOT", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    expect(
      await errorOf(
        h.service.revoke(admin, h.key(), root.caId, {
          reason: "caCompromise",
          invalidityDate: new Date(Date.now() - day).toISOString(),
        }),
      ),
    ).toMatchObject({
      statusCode: 400,
      details: { reason: "invalid_invalidity_date" },
      message:
        "invalidityDate applies to an INTERMEDIATE, which is listed on its root's CRL.",
    });
    expect(h.state.cas.get(root.caId)!.status).toBe("ACTIVE");
  });

  it("reports an incomplete walk with a 200", async () => {
    const { h, root, c1, c2 } = await family();
    h.pki.revokeForRevokedAncestor.mockImplementation(async (child) => {
      if (child.caId === c1.caId) {
        throw new Error("boom");
      }
      return jest.requireActual<{ default?: unknown }>(
        "./__fixtures__/hierarchy-harness",
      )
        ? undefined
        : undefined;
    });
    const result = await h.service.revoke(admin, h.key(), root.caId, {});
    expect(result.status).toBe(200);
    expect(result.body.complete).toBe(false);
    expect(result.body.revokedCaIds).not.toContain(c1.caId);
    expect(h.state.cas.get(c1.caId)!.status).toBe("ACTIVE");
    expect(h.state.cas.get(c2.caId)!.status).toBe("RETIRED");
  });

  it("re-walks an already REVOKED root and a replay", async () => {
    const { h, root, c1 } = await family();
    // The walk is missed the first time.
    h.pki.queryDirectory.mockRejectedValueOnce(new Error("index not ready"));
    const key = h.key();
    const first = await h.service.revoke(admin, key, root.caId, {});
    expect(first.body).toMatchObject({ complete: false, revokedCaIds: [] });
    expect(h.state.cas.get(c1.caId)!.status).toBe("ACTIVE");
    // A replay under the same key re-runs the walk and finishes it.
    const replay = await h.service.revoke(admin, key, root.caId, {});
    expect(h.pki.distrustRootCa).toHaveBeenCalledTimes(1);
    expect(replay.body).toMatchObject({ complete: true, changed: true });
    expect(h.state.cas.get(c1.caId)!.status).toBe("REVOKED");
    // Another request finds the root REVOKED and is a no-op that still walks.
    const again = await h.service.revoke(admin, h.key(), root.caId, {});
    expect(h.pki.distrustRootCa).toHaveBeenCalledTimes(1);
    expect(again.body).toMatchObject({ changed: false, complete: true });
  });

  it("reruns after a version race and then takes the no-op path", async () => {
    const { h, root } = await family();
    h.pki.distrustRootCa.mockImplementationOnce(async () => {
      h.state.cas.set(root.caId, {
        ...h.state.cas.get(root.caId)!,
        status: "REVOKED",
        version: "pkv-other",
      });
      return { kind: "conditionFailed" };
    });
    const result = await h.service.revoke(admin, h.key(), root.caId, {});
    expect(result.body.changed).toBe(false);
    expect(h.pki.distrustRootCa).toHaveBeenCalledTimes(1);
  });

  it("refuses a policy leaf-field change and keeps the root a subordinate issuer", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    expect(
      await errorOf(
        h.service.update(admin, h.key(), root.caId, root.version, {
          policy: { maxLeafLifetimeSeconds: 600 },
        }),
      ),
    ).toMatchObject({ statusCode: 400, details: { reason: "invalid_policy" } });
    await h.service.update(admin, h.key(), root.caId, root.version, {
      policy: {
        maxLeafLifetimeSeconds: root.policy.maxLeafLifetimeSeconds,
        capacity: 10,
      },
    });
    const input = h.pki.updateCaPolicy.mock.calls[0]![0];
    expect("maxIssueLifetimeEverSeconds" in input).toBe(false);
    expect(input.policy).toMatchObject({
      issueLeaves: false,
      issueSubordinates: true,
      capacity: 10,
    });
  });
});

describe("retire and drain of a ROOT", () => {
  it("drains no earlier than its longest child", async () => {
    const h = hierarchyHarness();
    const root = await h.createRoot();
    const long = await h.createChild(root.caId);
    const short = await h.createChild(root.caId, {
      name: "hemlig-issuing-2",
      subject: { commonName: "Hemlig Issuing CA 2" },
      validitySeconds: 2_592_000 * 2,
    });
    await h.service.retire(admin, h.key(), root.caId);
    const retired = h.state.cas.get(root.caId)!;
    expect(retired.status).toBe("RETIRED");
    const drain = Date.parse(drainPoint(retired));
    expect(drain).toBeGreaterThanOrEqual(
      Math.max(Date.parse(long.notAfter!), Date.parse(short.notAfter!)),
    );
    const before = new Date(Date.parse(long.notAfter!) - 1000).toISOString();
    expect(
      isDrained(retired, {
        revision: 0,
        published: { thisUpdate: before } as never,
      }),
    ).toBe(false);
    expect(
      isDrained(retired, {
        revision: 0,
        published: {
          thisUpdate: new Date(drain + 1000).toISOString(),
          revision: 0,
        } as never,
      }),
    ).toBe(true);
  });
});
