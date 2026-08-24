import type { EnrollmentRecord } from "../domain/types";

const getApplication = jest.fn();

jest.mock("./shared", () => ({ getApplication }));

import { handler } from "./recovery";

describe("recovery handler", () => {
  it("fails a stale enrollment that cannot publish its truststore and releases its lease", async () => {
    const enrollment = {
      pk: "ENROLLMENT#operation-1",
      sk: "STATE",
      operationId: "operation-1",
      operationType: "consumer.enroll",
      consumerId: "staging-old-agent",
      environment: "staging",
      rootFingerprint: "a".repeat(64),
      apiFingerprint: "b".repeat(64),
      apiCertificatePem: "certificate",
      createdAt: "2026-08-24T07:00:00.000Z",
      workflowState: "PREPARED",
      requestDigest: "digest",
      actor: { type: "system", id: "controller" },
      idempotencyKey: "key",
    } satisfies EnrollmentRecord;
    const repository = {
      listExpiredPrepared: jest.fn(async () => [
        {
          operationId: enrollment.operationId,
          workflowKind: "consumer.enrollment",
        },
      ]),
      getEnrollment: jest.fn(async () => enrollment),
      failEnrollment: jest.fn(async () => undefined),
      getTruststoreState: jest.fn(async () => undefined),
    };
    const consumers = {
      resume: jest.fn(async () => {
        throw new Error("API Gateway is still updating");
      }),
      reconcileTruststore: jest.fn(async () => undefined),
    };
    const audit = { write: jest.fn(async () => ({ eventId: "event-1" })) };
    getApplication.mockReturnValue({ repository, consumers, audit });

    await handler({} as never, {} as never, () => undefined);

    expect(repository.failEnrollment).toHaveBeenCalledWith(enrollment);
    expect(audit.write).toHaveBeenCalledWith(
      expect.objectContaining({
        correlationId: enrollment.operationId,
        reasonCode: "enrollment_expired",
      }),
    );
    expect(consumers.reconcileTruststore).toHaveBeenCalledTimes(1);
  });
});
