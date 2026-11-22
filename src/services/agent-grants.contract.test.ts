import { readFileSync } from "node:fs";
import { join } from "node:path";
import Ajv2020 from "ajv/dist/2020";
import { parse } from "yaml";
import type { DynamoRepository } from "../repositories/dynamo";
import type { AgentNotificationService } from "./agent-notifications";
import { AgentGrantService } from "./agent-grants";
import type { ConsumerService } from "./consumers";
import type { EnvironmentService } from "./environments";
import type { SecretService } from "./secrets";

// The OpenAPI pairing rule for CreateAgentGrantRequest must agree with the service.
const document = parse(
  readFileSync(join(__dirname, "../../openapi/consumer-secrets.yaml"), "utf8"),
) as Record<string, unknown>;
const ajv = new Ajv2020({ strict: false, validateFormats: false });
ajv.addSchema(document, "openapi.json");
const validate = ajv.compile({
  $ref: "openapi.json#/components/schemas/CreateAgentGrantRequest",
});

const service = new AgentGrantService(
  {
    getConsumer: jest.fn(async () => undefined),
    requireHead: jest.fn(async () => ({ secretUid: "sec-x" })),
    createAgentGrant: jest.fn(async () => undefined),
  } as unknown as DynamoRepository,
  {} as ConsumerService,
  { require: jest.fn(async () => undefined) } as unknown as EnvironmentService,
  {} as AgentNotificationService,
  { reconcileAgentReadAccess: jest.fn() } as unknown as SecretService,
);

const grant = [{ secretId: "payments/api", permissions: ["read"] }];
const corpus: [string, unknown[], unknown[]][] = [
  ["both empty", [], []],
  ["read with one read grant", ["read"], grant],
  ["empty capabilities with a grant", [], grant],
  ["read with no grants", ["read"], []],
];

describe("CreateAgentGrantRequest pairing rule", () => {
  it.each(corpus)(
    "%s: schema and service agree",
    async (_name, capabilities, secretGrants) => {
      const request = {
        consumerId: "pki-only-agent",
        environment: "prod",
        capabilities,
        secretGrants,
      };
      let serviceAccepts = true;
      try {
        await service.create({
          consumerId: request.consumerId,
          environment: request.environment,
          capabilities,
          secretGrants,
          actor: { type: "human", id: "admin" },
        });
      } catch {
        serviceAccepts = false;
      }
      expect(validate(request)).toBe(serviceAccepts);
    },
  );

  it("covers both accepted and rejected verdicts", () => {
    const verdicts = corpus.map(([, capabilities, secretGrants]) =>
      validate({
        consumerId: "pki-only-agent",
        environment: "prod",
        capabilities,
        secretGrants,
      }),
    );
    expect(verdicts).toEqual([true, true, false, false]);
  });
});
