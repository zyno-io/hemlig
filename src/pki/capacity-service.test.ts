import { countFrom, CapacityService } from "./capacity-service";
import { buildSignedCrl } from "./crl-service";
import { makeIntermediate, makeRoot, newKey } from "./__fixtures__/testkit";
import { parseCrl } from "./asn1/crl";

const now = new Date("2026-06-01T12:00:00.000Z");

describe("countFrom", () => {
  it.each([
    ["now when nothing is pending", {}, now.toISOString()],
    [
      "dirtySince when it is earlier",
      { dirtySince: "2026-06-01T10:00:00.000Z" },
      "2026-06-01T10:00:00.000Z",
    ],
    [
      "dropDueAt when it is earlier",
      { published: { dropDueAt: "2026-06-01T09:00:00.000Z" } },
      "2026-06-01T09:00:00.000Z",
    ],
    [
      "the earlier of both",
      {
        dirtySince: "2026-06-01T08:00:00.000Z",
        published: { dropDueAt: "2026-06-01T09:00:00.000Z" },
      },
      "2026-06-01T08:00:00.000Z",
    ],
    [
      "now when they are later",
      {
        dirtySince: "2026-06-02T08:00:00.000Z",
        published: { dropDueAt: "2026-06-03T09:00:00.000Z" },
      },
      now.toISOString(),
    ],
  ])("is %s", (_label, crl, expected) => {
    expect(countFrom(crl as never, now)).toBe(expected);
  });
});

describe("CapacityService", () => {
  const setup = () => {
    const pki = {
      countCertificatesSince: jest.fn(async () => 42),
      storeCapacityCount: jest.fn(async () => undefined),
    };
    return { pki, service: new CapacityService(pki as never) };
  };

  it("recounts from countFrom and stores the result", async () => {
    const { pki, service } = setup();
    const crl = { revision: 3, lastNumber: 2, dirtySince: "2026-06-01T08:00:00.000Z" };
    expect(await service.recount({ caId: "ca-x" }, crl, now)).toBe(42);
    expect(pki.countCertificatesSince).toHaveBeenCalledWith(
      "ca-x",
      "2026-06-01T08:00:00.000Z",
    );
    expect(pki.storeCapacityCount).toHaveBeenCalledWith("ca-x", {
      count: 42,
      countFrom: "2026-06-01T08:00:00.000Z",
      countedAt: now.toISOString(),
    });
  });

  it("uses a fresh count and recounts a stale or missing one", async () => {
    const { pki, service } = setup();
    const fresh = {
      revision: 0,
      lastNumber: 1,
      capacity: {
        count: 5,
        countFrom: now.toISOString(),
        countedAt: new Date(now.getTime() - 29 * 60_000).toISOString(),
      },
    };
    expect(await service.current({ caId: "ca-x" }, fresh, now)).toBe(5);
    const stale = {
      ...fresh,
      capacity: {
        ...fresh.capacity,
        countedAt: new Date(now.getTime() - 31 * 60_000).toISOString(),
      },
    };
    expect(await service.current({ caId: "ca-x" }, stale, now)).toBe(42);
    expect(
      await service.current({ caId: "ca-x" }, { revision: 0, lastNumber: 1 }, now),
    ).toBe(42);
    expect(pki.countCertificatesSince).toHaveBeenCalledTimes(2);
  });

  it("is a 503 without CRL state", async () => {
    const { service } = setup();
    await expect(
      service.current({ caId: "ca-x" }, undefined, now),
    ).rejects.toMatchObject({ statusCode: 503 });
  });
});

describe("worst-case CRL", () => {
  it("fits 12,000 keyCompromise entries with invalidity dates under RSA-4096 in 1,000,000 bytes", async () => {
    const root = await makeRoot();
    const key = await newKey("RSA_4096");
    const cert = await makeIntermediate(root, { key });
    const entries = Array.from({ length: 12_000 }, (_, i) => ({
      caId: "ca-x",
      serial: `7f${i.toString(16).padStart(38, "0")}`,
      revokedAt: "2026-06-01T00:00:00.000Z",
      reason: "keyCompromise" as const,
      invalidityDate: "2026-05-31T00:00:00.000Z",
      notAfter: "2027-01-01T00:00:00.000Z",
    }));
    const built = await buildSignedCrl(
      {
        subjectDer: cert.cert.subjectDer.toString("base64"),
        subjectKeyIdentifier: cert.cert.subjectKeyIdentifier!.toString("hex"),
        spkiDer: cert.cert.spkiDer,
      },
      { algorithm: "RSA_4096", sign: async (tbs) => key.sign(tbs) },
      {
        number: 1,
        thisUpdate: new Date("2026-06-01T00:00:00Z"),
        nextUpdate: new Date("2026-06-08T00:00:00Z"),
        entries,
      },
    );
    expect(parseCrl(built.der).entries).toHaveLength(12_000);
    expect(built.der.length).toBeLessThanOrEqual(1_000_000);
  }, 120_000);
});
