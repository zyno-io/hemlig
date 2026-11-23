import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import { parse } from "yaml";
import { pkiAdminRoutes } from "../handlers/pki-admin-routes";
import { pkiIssuerRoutes } from "../handlers/pki-issuer-routes";
import {
  parseActivateRequest,
  parseCreateCaRequest,
  parseUpdateCaRequest,
  parseUploadCrlRequest,
} from "./ca-model";
import {
  parseBulkRevokeRequest,
  parseRevokeRequest,
} from "./certificate-service";
import { caBundleView } from "./bundle-model";
import { parseRevokeCaRequest } from "./hierarchy-model";
import { parseGrantRequest } from "./grant-model";
import { validateGrantPolicy } from "./grant-policy";
import {
  parseAdminIssueRequest,
  parseConsumerIssueRequest,
} from "./issuance-model";
import { parseEvaluateRequest } from "./issuance-service";
import type { CaRecord } from "./types";

const document = parse(
  readFileSync(join(__dirname, "../../openapi/consumer-secrets.yaml"), "utf8"),
) as {
  paths: Record<string, Record<string, unknown>>;
  components: {
    schemas: Record<
      string,
      { properties: { error: { properties: { code: { enum: string[] } } } } }
    >;
  };
};
const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(document, "openapi.json");
const schema = (name: string) =>
  ajv.compile({ $ref: `openapi.json#/components/schemas/${name}` });

const subject = { commonName: "Prod CA", organization: "Example" };
const create = (extra: Record<string, unknown> = {}) => ({
  environment: "prod",
  name: "prod-ca-1",
  kind: "EXTERNAL_INTERMEDIATE",
  keyAlgorithm: "ECDSA_P256",
  subject,
  ...extra,
});


const futureNow = new Date("2026-06-01T00:00:00.000Z");
const grantPolicy = {
  names: { dns: { allow: ["*.example.com"] }, maxSans: 10 },
  keyUsages: ["digitalSignature"],
  extendedKeyUsages: { allow: ["serverAuth"], default: ["serverAuth"] },
  lifetime: { defaultSeconds: 3600, maxSeconds: 86400 },
};
const grant = (extra: Record<string, unknown> = {}) => ({
  name: "web",
  caId: "ca-test-one",
  ...grantPolicy,
  ...extra,
});
const parseGrant =
  (kind: "create" | "update") =>
  (body: unknown): unknown => {
    const { policyFields } = parseGrantRequest(body, kind, futureNow, "web");
    const result = validateGrantPolicy(policyFields);
    if (!result.ok) {
      throw new Error("invalid policy");
    }
    return result;
  };
const grantCases = (kind: "create" | "update"): [string, unknown][] => {
  const named = (extra: Record<string, unknown>) =>
    kind === "create"
      ? grant(extra)
      : (({ name: _name, ...rest }) => rest)(grant(extra));
  return [
    ["minimal", named({})],
    ["envelope", named({ displayName: "Web", status: "DISABLED", expiresAt: "2999-01-01T00:00:00Z" })],
    ["unknown key", named({ other: 1 })],
    ["expectedGrantUid", named({ expectedGrantUid: "pkg-x" })],
    ["status DELETED", named({ status: "DELETED" })],
    ["bad caId", named({ caId: "x" })],
    ["missing caId", { ...named({}), caId: undefined }],
    ["missing names", { ...named({}), names: undefined }],
    ["missing lifetime", { ...named({}), lifetime: undefined }],
    ["quotas", named({ quotas: { perHour: 5, perDay: 50 } })],
    ["unknown quota key", named({ quotas: { perWeek: 5 } })],
    ["display name too long", named({ displayName: "x".repeat(129) })],
  ];
};
const issueBody = (extra: Record<string, unknown> = {}) => ({
  certificateSigningRequestPem: "csr",
  ...extra,
});

const corpora: [string, (body: unknown) => unknown, [string, unknown][]][] = [
  [
    "PkiCreateCaRequest",
    parseCreateCaRequest,
    [
      ["minimal", create()],
      ["unknown top-level key", create({ extra: 1 })],
      [
        "unknown subject key",
        create({ subject: { commonName: "x", cn: "y" } }),
      ],
      ["missing subject", { ...create(), subject: undefined }],
      ["other kind", create({ kind: "BOGUS" })],
      ["root minimal", create({ kind: "ROOT" })],
      ["root min validity", create({ kind: "ROOT", validitySeconds: 7_776_000 })],
      ["root short validity", create({ kind: "ROOT", validitySeconds: 7_775_999 })],
      ["root max validity", create({ kind: "ROOT", validitySeconds: 630_720_000 })],
      ["root long validity", create({ kind: "ROOT", validitySeconds: 630_720_001 })],
      ["root capacity", create({ kind: "ROOT", policy: { capacity: 100 } })],
      ["root leaf lifetime", create({ kind: "ROOT", policy: { maxLeafLifetimeSeconds: 3600 } })],
      ["root leaf algorithms", create({ kind: "ROOT", policy: { leafKeyAlgorithms: ["ECDSA_P256"] } })],
      ["root with parent", create({ kind: "ROOT", parentCaId: "ca-root-one" })],
      ["intermediate", create({ kind: "INTERMEDIATE", parentCaId: "ca-root-one" })],
      ["intermediate without parent", create({ kind: "INTERMEDIATE" })],
      ["intermediate bad parent", create({ kind: "INTERMEDIATE", parentCaId: "x" })],
      ["intermediate min validity", create({ kind: "INTERMEDIATE", parentCaId: "ca-root-one", validitySeconds: 2_592_000 })],
      ["intermediate short validity", create({ kind: "INTERMEDIATE", parentCaId: "ca-root-one", validitySeconds: 2_591_999 })],
      ["external validity", create({ validitySeconds: 2_592_000 })],
      ["external parent", create({ parentCaId: "ca-root-one" })],
      ["bad algorithm", create({ keyAlgorithm: "DSA" })],
      ["bad name", create({ name: "Bad Name" })],
      ["policy bounds", create({ policy: { capacity: 12001 } })],
      ["policy low bound", create({ policy: { crlValiditySeconds: 10 } })],
      ["policy key", create({ policy: { bogus: 1 } })],
      [
        "policy ok",
        create({
          policy: {
            capacity: 100,
            issuancePerHour: 10,
            leafKeyAlgorithms: ["ECDSA_P256"],
          },
        }),
      ],
      ["empty algorithms", create({ policy: { leafKeyAlgorithms: [] } })],
      [
        "duplicate algorithms",
        create({ policy: { leafKeyAlgorithms: ["ECDSA_P256", "ECDSA_P256"] } }),
      ],
      ["crl validity", create({ crl: { validitySeconds: 3600 } })],
      ["crl unknown key", create({ crl: { other: 1 } })],
      [
        "eku",
        create({ requestedConstraints: { extendedKeyUsages: ["serverAuth"] } }),
      ],
      [
        "bad eku",
        create({
          requestedConstraints: { extendedKeyUsages: ["codeSigning"] },
        }),
      ],
      [
        "constraints key",
        create({
          requestedConstraints: {
            nameConstraints: { permitted: { email: ["a"] } },
          },
        }),
      ],
      ["display name too long", create({ displayName: "x".repeat(129) })],
      ["display name", create({ displayName: "Prod" })],
    ],
  ],
  [
    "PkiUpdateCaRequest",
    parseUpdateCaRequest,
    [
      ["policy only", { policy: { capacity: 5 } }],
      ["empty policy", { policy: {} }],
      ["missing policy", {}],
      ["unknown key", { policy: {}, extra: 1 }],
      ["null display name", { policy: {}, displayName: null }],
      ["empty display name", { policy: {}, displayName: "" }],
      ["bad bound", { policy: { issuancePerHour: 0 } }],
    ],
  ],
  [
    "PkiActivateCaRequest",
    parseActivateRequest,
    [
      ["minimal", { certificatePem: "a", chainPem: "b" }],
      [
        "with crl",
        {
          certificatePem: "a",
          chainPem: "b",
          rootCrl: "c",
          acceptBroaderConstraints: true,
        },
      ],
      ["missing chain", { certificatePem: "a" }],
      ["unknown", { certificatePem: "a", chainPem: "b", x: 1 }],
      [
        "bad boolean",
        { certificatePem: "a", chainPem: "b", acceptBroaderConstraints: "yes" },
      ],
    ],
  ],
  [
    "PkiUploadCrlRequest",
    parseUploadCrlRequest,
    [
      ["ok", { crl: "x" }],
      ["missing", {}],
      ["unknown", { crl: "x", y: 1 }],
      ["not a string", { crl: 1 }],
    ],
  ],
  ["PkiCreateIssuanceGrantRequest", parseGrant("create"), grantCases("create")],
  ["PkiIssuanceGrantInput", parseGrant("update"), grantCases("update")],
  [
    "PkiIssueCertificateRequest",
    parseConsumerIssueRequest,
    [
      ["minimal", issueBody()],
      ["full", issueBody({ durationSeconds: 60, usages: ["server auth"], requester: { kubernetes: { namespace: "a", name: "b", uid: "1" } } })],
      ["sans refused", issueBody({ sans: { dns: ["a"] } })],
      ["unknown", issueBody({ extra: 1 })],
      ["expectedGrantUid", issueBody({ expectedGrantUid: "x" })],
      ["missing csr", {}],
      ["csr not string", { certificateSigningRequestPem: 1 }],
      ["zero duration", issueBody({ durationSeconds: 0 })],
      ["too many usages", issueBody({ usages: new Array(17).fill("a") })],
      ["requester unknown", issueBody({ requester: { other: 1 } })],
      ["requester bad uid", issueBody({ requester: { kubernetes: { namespace: "a", name: "b", uid: "zz" } } })],
      ["requester missing name", issueBody({ requester: { kubernetes: { namespace: "a", uid: "1" } } })],
    ],
  ],
  [
    "PkiAdminIssueCertificateRequest",
    parseAdminIssueRequest,
    [
      ["minimal", issueBody()],
      ["names", issueBody({ sans: { dns: ["a.example.com"] }, subject: { commonName: "a", country: "US" } })],
      ["csr names", issueBody({ useCsrNames: true })],
      ["unknown", issueBody({ extra: 1 })],
      ["unknown sans key", issueBody({ sans: { email: [] } })],
      ["unknown subject key", issueBody({ subject: { title: "x" } })],
      ["useCsrNames not boolean", issueBody({ useCsrNames: "yes" })],
      ["too many sans", issueBody({ sans: { dns: new Array(101).fill("a.example.com") } })],
    ],
  ],
  [
    "PkiRevokeCertificateRequest",
    (body: unknown) => parseRevokeRequest(body, futureNow),
    [
      ["empty", {}],
      ["reason", { reason: "superseded" }],
      ["keyCompromise date", { reason: "keyCompromise", invalidityDate: "2026-05-01T00:00:00Z" }],
      ["caCompromise", { reason: "caCompromise" }],
      ["unknown", { other: 1 }],
      ["reason not string", { reason: 1 }],
    ],
  ],
  [
    "PkiRevokeCaRequest",
    (body: unknown) => parseRevokeCaRequest(body, futureNow),
    [
      ["empty", {}],
      ["caCompromise", { reason: "caCompromise" }],
      ["caCompromise date", { reason: "caCompromise", invalidityDate: "2026-05-01T00:00:00Z" }],
      ["keyCompromise", { reason: "keyCompromise" }],
      ["unknown", { other: 1 }],
      ["reason not string", { reason: 1 }],
    ],
  ],
  [
    "PkiBulkRevokeRequest",
    (body: unknown) => parseBulkRevokeRequest(body, futureNow),
    [
      ["empty", {}],
      ["grant", { issuanceGrant: "web", issuanceGrantUid: "pkg-1" }],
      ["unknown", { other: 1 }],
      ["grant not string", { issuanceGrant: 1 }],
    ],
  ],
  [
    "PkiEvaluateRequest",
    parseEvaluateRequest,
    [
      ["csr", { certificateSigningRequestPem: "x" }],
      ["names", { keyAlgorithm: "ECDSA_P256", sans: { dns: ["a.example.com"] }, commonName: "a.example.com" }],
      ["unknown", { keyAlgorithm: "ECDSA_P256", sans: {}, other: 1 }],
      ["unknown sans", { keyAlgorithm: "ECDSA_P256", sans: { email: [] } }],
      ["bad duration", { keyAlgorithm: "ECDSA_P256", sans: {}, durationSeconds: 0 }],
      ["isCA not boolean", { keyAlgorithm: "ECDSA_P256", sans: {}, isCA: "x" }],
    ],
  ],
];

describe("PKI admin OpenAPI contract", () => {
  for (const [name, parser, cases] of corpora) {
    const validate = schema(name);
    it.each(cases)(`${name}: %s agrees with the parser`, (_label, body) => {
      let parserAccepts = true;
      try {
        parser(JSON.parse(JSON.stringify(body)));
      } catch {
        parserAccepts = false;
      }
      expect(validate(JSON.parse(JSON.stringify(body)))).toBe(parserAccepts);
    });
  }

  const openApiPath = (source: string): string => {
    const names = source.includes("consumers")
      ? ["{consumerId}", "{name}"]
      : ["{name}"];
    // `/consumers/C/issuance-grants` and `/consumers/C/certificates` carry no grant name.
    return source
      .replace(/^\^/, "")
      .replace(/\\\//g, "/")
      .replace(/\$$/, "")
      .replace(
        /\((ca-[^)]*\|ext-[^)]*)\)|\(ca-[^)]*\)|\(ext-[^)]*\)/g,
        (match) =>
          match.startsWith("(ext-")
            ? "{extId}"
            : match.includes("|")
              ? "{id}"
              : "{caId}",
      )
      .replace(/\(\[a-z\]\[a-z0-9-\]\{2,63\}\)/g, () => names.shift() as string)
      .replace(/\(\[0-9a-f\]\{2,40\}\)/g, "{serial}");
  };

  it("documents every routed path and method", () => {
    for (const route of [...pkiAdminRoutes, ...pkiIssuerRoutes]) {
      const path = openApiPath(route.pattern.source);
      const entry = document.paths[path];
      expect({ path, entry: entry !== undefined }).toEqual({ path, entry: true });
      expect(entry?.[route.method.toLowerCase()]).toBeDefined();
    }
  });

  it("PkiCaBundle matches caBundleView", () => {
    const validate = schema("PkiCaBundle");
    const view = caBundleView(
      {
        caId: "ca-0a1b",
        name: "prod-issuing-1",
        status: "ACTIVE",
        crlIssuers: [
          { type: "ca", id: "ca-0a1b" },
          { type: "external", id: `ext-${"a".repeat(40)}` },
        ],
        certificatePem:
          "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n",
        chainPem:
          "-----BEGIN CERTIFICATE-----\nBB\n-----END CERTIFICATE-----\n",
        fingerprint: "ab".repeat(32),
        notAfter: "2028-01-01T00:00:00.000Z",
      } as unknown as CaRecord,
      undefined,
    );
    expect(validate(JSON.parse(JSON.stringify(view)))).toBe(true);
    expect(validate({ ...view, extra: 1 })).toBe(false);
  });

  it("lists every PKI error code", () => {
    const codes =
      document.components.schemas.ErrorEnvelope!.properties.error.properties
        .code.enum;
    for (const code of [
      "chain_invalid",
      "crl_invalid",
      "crl_not_newer",
      "ca_subject_in_use",
      "ca_not_active",
      "ca_key_unavailable",
      "ca_issuance_budget_exceeded",
      "issuance_denied",
      "issuance_grant_not_found",
      "issuance_grant_inactive",
      "ca_capacity_exceeded",
      "issuance_revoked",
      "issuance_expired",
      "issuance_rate_limited",
    ]) {
      expect(codes).toContain(code);
    }
  });

  it("types pendingRevocations as an integer", () => {
    const view = (
      document.components.schemas as unknown as Record<
        string,
        { properties: Record<string, { type: string }> }
      >
    ).PkiCrlView!;
    expect(view.properties.pendingRevocations!.type).toBe("integer");
  });
});
