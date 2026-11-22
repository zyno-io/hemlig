const mockHasAnyCa = jest.fn();
const mockRunPass = jest.fn();
const now = new Date("2026-11-22T10:00:00.000Z");
jest.mock("./pki-shared", () => ({
  getPkiApplication: () => ({ pki: { hasAnyCa: mockHasAnyCa }, now: () => now }),
}));
jest.mock("../pki/maintenance", () => ({
  runMaintenancePass: (...args: unknown[]) => mockRunPass(...args),
}));

import { PkiIndexNotReadyError } from "../repositories/pki";
import { handler } from "./pki-maintenance";

describe("pki-maintenance handler", () => {
  afterEach(() => {
    jest.restoreAllMocks();
    mockHasAnyCa.mockReset();
    mockRunPass.mockReset();
  });

  it("reports idle when no CA exists", async () => {
    const out = jest
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    mockHasAnyCa.mockResolvedValue(false);
    await expect(handler()).resolves.toEqual({ status: "idle" });
    expect(out).toHaveBeenCalledWith('{"event":"pki_maintenance_idle"}\n');
  });

  it("delegates to the maintenance pass once a CA exists", async () => {
    mockHasAnyCa.mockResolvedValue(true);
    const summary = { status: "ok", cas: 1, failures: 0 };
    mockRunPass.mockResolvedValue(summary);
    const context = { getRemainingTimeInMillis: () => 123_456, awsRequestId: "req-9" };
    await expect(handler({}, context)).resolves.toEqual(summary);
    const call = mockRunPass.mock.calls[0]?.[0] as {
      now: Date;
      correlationId: string;
      remainingMs: () => number;
    };
    expect(call.now).toBe(now);
    expect(call.correlationId).toBe("req-9");
    expect(call.remainingMs()).toBe(123_456);
  });

  it("propagates a failed pass so the Errors metric counts it", async () => {
    mockHasAnyCa.mockResolvedValue(true);
    mockRunPass.mockRejectedValue(new Error("PKI maintenance finished with 1 failure(s)."));
    await expect(handler()).rejects.toThrow("1 failure");
  });

  it("treats a backfilling index as idle with a log line", async () => {
    const out = jest.spyOn(process.stdout, "write").mockImplementation(() => true);
    mockHasAnyCa.mockRejectedValue(new PkiIndexNotReadyError());
    await expect(handler()).resolves.toEqual({
      status: "idle",
      reason: "index_not_ready",
    });
    expect(out).toHaveBeenCalledWith(
      '{"event":"pki_maintenance_idle","reason":"index_not_ready"}\n',
    );
  });

  it("propagates errors", async () => {
    mockHasAnyCa.mockRejectedValue(new Error("AccessDenied"));
    await expect(handler()).rejects.toThrow("AccessDenied");
  });
});
