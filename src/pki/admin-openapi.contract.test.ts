import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import { parse } from "yaml";
import { pkiAdminRoutes } from "../handlers/pki-admin-routes";
import {
  parseActivateRequest,
  parseCreateCaRequest,
  parseUpdateCaRequest,
  parseUploadCrlRequest,
} from "./ca-model";

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
      ["other kind", create({ kind: "ROOT" })],
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

  it("documents every routed path and method", () => {
    for (const route of pkiAdminRoutes) {
      const path = route.pattern.source
        .replace(/^\^\\\/v1\\\/admin\\\/pki/, "/v1/admin/pki")
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
        );
      const entry = document.paths[path];
      expect(entry).toBeDefined();
      expect(entry?.[route.method.toLowerCase()]).toBeDefined();
    }
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
