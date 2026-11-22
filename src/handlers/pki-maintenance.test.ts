const mockHasAnyCa = jest.fn();
jest.mock("./pki-shared", () => ({
  getPkiApplication: () => ({ pki: { hasAnyCa: mockHasAnyCa } }),
}));

import { handler } from "./pki-maintenance";

describe("pki-maintenance handler", () => {
  afterEach(() => {
    jest.restoreAllMocks();
    mockHasAnyCa.mockReset();
  });

  it("reports idle when no CA exists", async () => {
    const out = jest
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    mockHasAnyCa.mockResolvedValue(false);
    await expect(handler()).resolves.toEqual({ status: "idle" });
    expect(out).toHaveBeenCalledWith('{"event":"pki_maintenance_idle"}\n');
  });

  it("is a no-op once a CA exists", async () => {
    mockHasAnyCa.mockResolvedValue(true);
    await expect(handler()).resolves.toEqual({ status: "noop" });
  });

  it("propagates errors", async () => {
    mockHasAnyCa.mockRejectedValue(new Error("AccessDenied"));
    await expect(handler()).rejects.toThrow("AccessDenied");
  });
});
