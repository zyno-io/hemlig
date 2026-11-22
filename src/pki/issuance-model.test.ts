import { parseCsr } from "./csr";
import { decodeName } from "./asn1/names";
import { EXT, extension } from "./asn1/extensions";
import { encodeSubjectAltName } from "./asn1/names";
import { seq, oid, tlv, set, TAG } from "./asn1/der";
import {
  adminIssueDigest,
  assertLeafMatchesPlan,
  assembleLeaf,
  buildLeafToSign,
  chainParts,
  consumerIssueDigest,
  csrDerSha256,
  csrToPolicyRequest,
  floorToSecond,
  parseAdminIssueRequest,
  parseConsumerIssueRequest,
  planSubjectDer,
} from "./issuance-model";
import type { IssuancePlan } from "./policy-types";
import {
  csrPem,
  leafKey,
  makeCsrDer,
  makeIntermediate,
  makeRoot,
  newKey,
  subjectDer,
} from "./__fixtures__/testkit";
import { makeCsr } from "./__fixtures__/issuance-harness";

const csr = makeCsr();

describe("parseConsumerIssueRequest", () => {
  it("accepts the documented fields", () => {
    expect(
      parseConsumerIssueRequest({
        certificateSigningRequestPem: csr,
        durationSeconds: 3600,
        usages: ["server auth"],
        requester: {
          kubernetes: { namespace: "apps", name: "web.1", uid: "ab-12", revision: "3" },
        },
      }),
    ).toMatchObject({ durationSeconds: 3600, isCA: false });
  });

  it.each([
    ["sans", { sans: { dns: ["a.example.com"] } }, "names_from_csr_only"],
    ["subject", { subject: { commonName: "x" } }, "names_from_csr_only"],
    ["expectedGrantUid", { expectedGrantUid: "x" }, "unknown_field"],
    ["a bad namespace", { requester: { kubernetes: { namespace: "Bad_NS", name: "a", uid: "1" } } }, "invalid_requester"],
    ["a bad uid", { requester: { kubernetes: { namespace: "a", name: "a", uid: "zz" } } }, "invalid_requester"],
    ["a bad revision", { requester: { kubernetes: { namespace: "a", name: "a", uid: "1", revision: "x" } } }, "invalid_requester"],
    ["an extra requester key", { requester: { kubernetes: { namespace: "a", name: "a", uid: "1", extra: 1 } } }, "unknown_field"],
    ["a negative duration", { durationSeconds: -1 }, "invalid_duration"],
    ["too many usages", { usages: new Array(17).fill("x") }, "invalid_usages"],
  ])("rejects %s", (_label, extra, reason) => {
    expect(() =>
      parseConsumerIssueRequest({ certificateSigningRequestPem: csr, ...extra }),
    ).toThrow(expect.objectContaining({ safeReason: reason }));
  });

  it("denies isCA at step 1", () => {
    expect(() =>
      parseConsumerIssueRequest({ certificateSigningRequestPem: csr, isCA: true }),
    ).toThrow(expect.objectContaining({ statusCode: 403, safeReason: "ca_not_permitted" }));
  });
});

describe("parseAdminIssueRequest", () => {
  it("rejects useCsrNames with explicit names", () => {
    expect(() =>
      parseAdminIssueRequest({
        certificateSigningRequestPem: csr,
        useCsrNames: true,
        sans: { dns: ["a.example.com"] },
      }),
    ).toThrow(expect.objectContaining({ safeReason: "names_conflict" }));
  });

  it("limits each SAN list to 100", () => {
    expect(() =>
      parseAdminIssueRequest({
        certificateSigningRequestPem: csr,
        sans: { dns: new Array(101).fill("a.example.com") },
      }),
    ).toThrow(expect.objectContaining({ safeReason: "invalid_sans" }));
  });
});

describe("digests", () => {
  const sha = csrDerSha256(csr);

  it("excludes the requester and sorts and dedupes usages", () => {
    const a = parseConsumerIssueRequest({
      certificateSigningRequestPem: csr,
      usages: ["b", "a", "a"],
      requester: { kubernetes: { namespace: "a", name: "a", uid: "1" } },
    });
    const b = parseConsumerIssueRequest({
      certificateSigningRequestPem: csr,
      usages: ["a", "b"],
    });
    expect(consumerIssueDigest("c-one", "web", sha, a)).toBe(
      consumerIssueDigest("c-one", "web", sha, b),
    );
    expect(consumerIssueDigest("c-one", "web", sha, a)).not.toBe(
      consumerIssueDigest("c-two", "web", sha, a),
    );
  });

  it("separates admin requests by names", () => {
    const a = parseAdminIssueRequest({ certificateSigningRequestPem: csr, useCsrNames: true });
    const b = parseAdminIssueRequest({
      certificateSigningRequestPem: csr,
      sans: { dns: ["a.example.com"] },
    });
    expect(adminIssueDigest("ca-x", sha, a)).not.toBe(adminIssueDigest("ca-x", sha, b));
  });

  it("is invalid_csr for a malformed PEM before any lookup", () => {
    expect(() => csrDerSha256("nope")).toThrow(
      expect.objectContaining({ code: "invalid_csr" }),
    );
  });
});

describe("csrToPolicyRequest", () => {
  const input = { usages: [] as string[], isCA: false };
  const parsedOf = (extensions: Buffer[], subject = subjectDer("a.example.com")) =>
    parseCsr(
      csrPem(
        makeCsrDer({
          key: leafKey({ type: "ec", curve: "prime256v1" }),
          subject,
          extensions,
        }),
      ),
    );
  const san = (names: Parameters<typeof encodeSubjectAltName>[0]) =>
    extension(EXT.subjectAltName, false, encodeSubjectAltName(names));

  it("maps names and the common name", () => {
    const mapped = csrToPolicyRequest(
      parsedOf([san({ dns: ["a.example.com"] })]),
      input,
      "consumer",
    );
    expect(mapped).toMatchObject({
      ok: true,
      request: { sans: { dns: ["a.example.com"] }, commonName: "a.example.com", isCA: false },
    });
  });

  it("denies an email SAN", () => {
    const email = Buffer.concat([
      Buffer.from([0x81, 0x0b]),
      Buffer.from("a@b.example", "ascii"),
    ]);
    const mapped = csrToPolicyRequest(
      parsedOf([extension(EXT.subjectAltName, false, seq(email))]),
      input,
      "consumer",
    );
    expect(mapped).toMatchObject({
      ok: false,
      denial: { reason: "name_not_permitted", denied: { type: "subject", value: "email" } },
    });
  });

  it("denies an unknown subject attribute and a second CN", () => {
    const rdn = (typeOid: string, value: string) =>
      set(seq(oid(typeOid), tlv(TAG.utf8String, Buffer.from(value))));
    const unknown = parsedOf([], seq(rdn("2.5.4.5", "serial-1")));
    expect(csrToPolicyRequest(unknown, input, "consumer")).toMatchObject({
      ok: false,
      denial: { reason: "subject_not_permitted" },
    });
    const twice = parsedOf([], seq(rdn("2.5.4.3", "a.example.com"), rdn("2.5.4.3", "b.example.com")));
    expect(csrToPolicyRequest(twice, input, "consumer")).toMatchObject({
      ok: false,
      denial: { reason: "subject_not_permitted" },
    });
  });

  it("treats BasicConstraints cA as isCA", () => {
    const bc = extension(EXT.basicConstraints, true, seq(Buffer.from([0x01, 0x01, 0xff])));
    expect(
      csrToPolicyRequest(parsedOf([bc]), input, "consumer"),
    ).toMatchObject({ ok: true, request: { isCA: true } });
  });

  it("reads usages from the CSR only when the body has none", () => {
    const ku = extension(EXT.keyUsage, true, Buffer.from([0x03, 0x02, 0x07, 0x80]));
    const parsed = parsedOf([ku]);
    expect(csrToPolicyRequest(parsed, input, "consumer")).toMatchObject({
      ok: true,
      request: { usages: ["digitalSignature"] },
    });
    expect(
      csrToPolicyRequest(parsed, { usages: ["server auth"], isCA: false }, "consumer"),
    ).toMatchObject({ ok: true, request: { usages: ["server auth"] } });
    const bad = extension(EXT.keyUsage, true, Buffer.from([0x03, 0x02, 0x06, 0x40]));
    expect(csrToPolicyRequest(parsedOf([bad]), input, "consumer")).toMatchObject({
      ok: false,
      denial: { reason: "key_usage_not_permitted" },
    });
  });

  it("takes admin names from the request unless useCsrNames", () => {
    const parsed = parsedOf([san({ dns: ["csr.example.com"] })]);
    expect(
      csrToPolicyRequest(parsed, input, "admin", {
        sans: { dns: ["given.example.com"] },
        subject: { commonName: "given.example.com", organization: "Org" },
      }),
    ).toMatchObject({
      ok: true,
      request: {
        sans: { dns: ["given.example.com"] },
        commonName: "given.example.com",
        subject: [{ type: "organization", value: "Org" }],
      },
    });
  });
});

describe("leaf construction and self-check", () => {
  const setup = async () => {
    const root = await makeRoot();
    const ca = await makeIntermediate(root, { key: await newKey("ECDSA_P256") });
    const key = leafKey({ type: "ec", curve: "prime256v1" });
    const plan: IssuancePlan = {
      keyAlgorithm: "ECDSA_P256",
      sans: { dns: ["a.example.com"], ip: [], uri: [] },
      subject: [
        { type: "country", value: "US" },
        { type: "commonName", value: "a.example.com" },
      ],
      commonName: "a.example.com",
      sanCritical: false,
      keyUsages: ["digitalSignature"],
      extendedKeyUsages: ["serverAuth"],
      certificatePolicies: [],
      notBefore: new Date(Date.now() - 1234),
      notAfter: new Date(Date.now() + 3_600_789),
      lifetimeClamped: false,
    };
    const built = buildLeafToSign(plan, ca.cert, key.spkiDer);
    const der = assembleLeaf(built, ca.key.sign(built.tbs));
    return { root, ca, key, plan, built, der };
  };

  it("floors times and encodes C as a PrintableString", async () => {
    const { built, plan } = await setup();
    expect(built.notBefore.getTime() % 1000).toBe(0);
    expect(built.notBefore).toEqual(floorToSecond(plan.notBefore));
    const [country] = decodeName(planSubjectDer(plan));
    expect(country?.[0]).toMatchObject({ value: "US", kind: "printable" });
  });

  it("passes for a faithful certificate", async () => {
    const { ca, key, plan, built, der } = await setup();
    expect(
      assertLeafMatchesPlan(der, { built, plan, caCert: ca.cert, spkiDer: key.spkiDer })
        .serialHex,
    ).toBe(built.serialHex);
  });

  it.each([
    ["serial", (e: any) => ({ ...e, built: { ...e.built, serialHex: "01" } })],
    ["subject", (e: any) => ({ ...e, built: { ...e.built, subjectDer: Buffer.from([0x30, 0x00]) } })],
    ["validity", (e: any) => ({ ...e, built: { ...e.built, notBefore: new Date(e.built.notBefore.getTime() + 1000) } })],
    ["keyUsage", (e: any) => ({ ...e, plan: { ...e.plan, keyUsages: ["digitalSignature", "keyEncipherment"] } })],
    ["extendedKeyUsage", (e: any) => ({ ...e, plan: { ...e.plan, extendedKeyUsages: ["clientAuth"] } })],
    ["subjectAltName", (e: any) => ({ ...e, plan: { ...e.plan, sans: { dns: ["b.example.com"], ip: [], uri: [] } } })],
    ["certificatePolicies", (e: any) => ({ ...e, plan: { ...e.plan, certificatePolicies: ["1.2.3.4"] } })],
    ["spki", (e: any) => ({ ...e, spkiDer: leafKey({ type: "ec", curve: "prime256v1" }).spkiDer })],
    ["issuer", (e: any) => ({ ...e, caCert: e.other })],
  ])("fails when %s differs", async (field, tamper) => {
    const setupped = await setup();
    const other = await makeIntermediate(setupped.root, {
      key: await newKey("ECDSA_P256"),
      subject: "Another CA",
    });
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      const expected = tamper({
        built: setupped.built,
        plan: setupped.plan,
        caCert: setupped.ca.cert,
        spkiDer: setupped.key.spkiDer,
        other: other.cert,
      });
      delete expected.other;
      expect(() => assertLeafMatchesPlan(setupped.der, expected)).toThrow(
        expect.objectContaining({ statusCode: 503 }),
      );
      expect(JSON.stringify(spy.mock.calls)).not.toContain("-----BEGIN");
    } finally {
      spy.mockRestore();
    }
  });

  it("requires the emitted policy OIDs to equal the plan, including the largest accepted arc", async () => {
    const { ca, key, plan } = await setup();
    const withPolicies = { ...plan, certificatePolicies: ["1.3.4294967295", "2.5.29.32.0"] };
    const built = buildLeafToSign(withPolicies, ca.cert, key.spkiDer);
    const der = assembleLeaf(built, ca.key.sign(built.tbs));
    expect(
      assertLeafMatchesPlan(der, { built, plan: withPolicies, caCert: ca.cert, spkiDer: key.spkiDer })
        .serialHex,
    ).toBe(built.serialHex);
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      for (const other of [
        ["2.5.29.32.0", "1.3.4294967295"],
        ["1.3.4294967295", "2.5.29.32.1"],
        ["1.3.4294967295"],
      ]) {
        expect(() =>
          assertLeafMatchesPlan(der, {
            built,
            plan: { ...withPolicies, certificatePolicies: other },
            caCert: ca.cert,
            spkiDer: key.spkiDer,
          }),
        ).toThrow(expect.objectContaining({ statusCode: 503 }));
      }
    } finally {
      spy.mockRestore();
    }
  });

  it("fails on a signature by another key and on garbage", async () => {
    const { ca, key, plan, built } = await setup();
    const forged = assembleLeaf(built, (await newKey("ECDSA_P256")).sign(built.tbs));
    const spy = jest.spyOn(console, "error").mockImplementation(() => undefined);
    try {
      expect(() =>
        assertLeafMatchesPlan(forged, { built, plan, caCert: ca.cert, spkiDer: key.spkiDer }),
      ).toThrow(expect.objectContaining({ statusCode: 503 }));
      expect(() =>
        assertLeafMatchesPlan(Buffer.from([1, 2, 3]), {
          built,
          plan,
          caCert: ca.cert,
          spkiDer: key.spkiDer,
        }),
      ).toThrow(expect.objectContaining({ statusCode: 503 }));
    } finally {
      spy.mockRestore();
    }
  });
});

describe("chainParts", () => {
  it("excludes the anchor from the chain and returns it as caPem", () => {
    const pem = (label: string) =>
      `-----BEGIN CERTIFICATE-----\n${label}\n-----END CERTIFICATE-----\n`;
    expect(
      chainParts({ certificatePem: pem("CA"), chainPem: pem("ROOT") }),
    ).toEqual({ chainPem: pem("CA"), caPem: pem("ROOT") });
    expect(
      chainParts({ certificatePem: pem("CA"), chainPem: pem("MID") + pem("ROOT") }),
    ).toEqual({ chainPem: pem("CA") + pem("MID"), caPem: pem("ROOT") });
  });
});
