import { createHash } from "node:crypto";
import { ExternalCaService } from "./external-ca-service";
import {
  crlPem,
  makeCrl,
  makeIntermediate,
  makeRoot,
  rawReasonExtension,
  type TestCert,
} from "./__fixtures__/testkit";
import type { CaRecord, ExternalCaRecord } from "./types";

const actor = { type: "human" as const, id: "admin-1" };
const hour = 3_600_000;
let root: TestCert;
let child: TestCert;
let extId: string;

beforeAll(async () => {
  root = await makeRoot();
  child = await makeIntermediate(root);
  extId = `ext-${root.cert.spkiSha256.slice(0, 40)}`;
});

const crl = (
  number: bigint,
  entries: { serialHex: string; hold?: boolean }[] = [],
  thisUpdate = new Date(Date.now() - 2 * hour + Number(number) * 1000),
) =>
  crlPem(
    makeCrl({
      ca: root,
      number,
      thisUpdate,
      nextUpdate: new Date(Date.now() + 30 * 24 * hour),
      entries: entries.map((entry) => ({
        serialHex: entry.serialHex,
        date: thisUpdate,
        ...(entry.hold === true ? { extensions: [rawReasonExtension(6)] } : {}),
      })),
    }),
  );

const ext = (overrides: Partial<ExternalCaRecord> = {}): ExternalCaRecord => ({
  extId,
  certificatePem: root.pem,
  fingerprint: "f",
  spkiSha256: "s",
  subjectDer: "",
  subjectAttributes: [],
  subjectKey: "k",
  subjectKeyIdentifier: "aa",
  notAfter: "2030-01-01T00:00:00.000Z",
  createdAt: "2026-01-01T00:00:00.000Z",
  dependents: new Set<string>(),
  environments: new Set(["prod"]),
  version: "pkv-1",
  ...overrides,
});
const ca = (caId: string, overrides: Partial<CaRecord> = {}): CaRecord =>
  ({
    caId,
    status: "ACTIVE",
    serial: child.cert.serialHex,
    key: { state: "ACTIVE" },
    parent: { type: "external", id: extId },
    ...overrides,
  }) as CaRecord;

const setup = (
  record: ExternalCaRecord | (() => ExternalCaRecord),
  cas: Record<string, CaRecord> = {},
  overrides: Record<string, unknown> = {},
) => {
  const read = () => (typeof record === "function" ? record() : record);
  const pki = {
    getExternalCa: jest.fn(async () => read()),
    getCa: jest.fn(async (id: string) => cas[id]),
    putHumanIdempotency: jest.fn(async () => "committed"),
    revokeCaExternally: jest.fn(async () => "revoked"),
    commitExternalCrl: jest.fn(async () => "committed"),
    ...overrides,
  };
  const repository = { getIdempotency: jest.fn(async () => undefined) };
  const put = jest.fn(async () => ({}));
  const service = new ExternalCaService({
    pki,
    repository,
    objects: { putImmutableOrGet: put },
    config: { pkiBucketName: "pki" },
    now: () => new Date(),
    cursors: { encode: jest.fn(), decode: jest.fn() },
  } as never);
  return { service, pki: pki as any, repository: repository as any, put };
};
const errorOf = async (work: Promise<unknown>) => {
  try {
    await work;
  } catch (error) {
    return error as {
      statusCode: number;
      code: string;
      details?: { reason?: string };
    };
  }
  throw new Error("expected an error");
};
const stored = (pem: string, number: bigint): ExternalCaRecord["crl"] => {
  const der = Buffer.from(
    pem.replace(/-----[A-Z0-9 ]+-----/g, "").replace(/\s+/g, ""),
    "base64",
  );
  return {
    numberHex: number.toString(16).padStart(40, "0"),
    thisUpdate: new Date(
      Date.now() - 2 * hour + Number(number) * 1000,
    ).toISOString(),
    nextUpdate: new Date(Date.now() + hour).toISOString(),
    sha256: createHash("sha256").update(der).digest("hex"),
    objectKey: "k",
    uploadedAt: "2026-01-01T00:00:00.000Z",
    uploadedBy: actor,
  };
};

describe("ExternalCaService.uploadCrl", () => {
  it("acknowledges an identical CRL with only the idempotency write", async () => {
    const pem = crl(2n);
    const { service, pki, put } = setup(ext({ crl: stored(pem, 2n) }));
    const result = await service.uploadCrl(actor, "idem-key-0001", extId, {
      crl: pem,
    });
    expect(result.body).toMatchObject({ changed: false, revokedCaIds: [] });
    expect(result.auditTarget.unchanged).toBe("true");
    expect(pki.putHumanIdempotency).toHaveBeenCalledTimes(1);
    expect(pki.commitExternalCrl).not.toHaveBeenCalled();
    expect(put).not.toHaveBeenCalled();
  });

  it("refuses a lower or equal number and an earlier thisUpdate", async () => {
    const current = stored(crl(5n), 5n);
    const { service } = setup(ext({ crl: current }));
    for (const pem of [
      crl(4n),
      crl(5n, [{ serialHex: "01" }]),
      crl(6n, [], new Date(Date.parse(current!.thisUpdate) - 1000)),
    ]) {
      expect(
        await errorOf(
          service.uploadCrl(actor, "idem-key-0002", extId, { crl: pem }),
        ),
      ).toMatchObject({
        statusCode: 409,
        code: "crl_not_newer",
      });
    }
  });

  it("flips listed dependents by canonical serial, any reason, skipping others", async () => {
    const dependents = new Set([
      "ca-listed",
      "ca-held",
      "ca-other",
      "ca-revoked",
      "ca-pending",
      "ca-missing",
    ]);
    const other = await makeIntermediate(root, {
      serial: Buffer.from([9, 9, 9, 9, 9, 9, 9, 1]),
    });
    const cas = {
      "ca-listed": ca("ca-listed"),
      "ca-held": ca("ca-held", {
        serial: other.cert.serialHex,
        key: { state: "DESTROYED" } as CaRecord["key"],
      }),
      "ca-other": ca("ca-other", { serial: "deadbeef" }),
      "ca-revoked": ca("ca-revoked", { status: "REVOKED" }),
      "ca-pending": ca("ca-pending", { status: "PENDING_CERTIFICATE" }),
    };
    const { service, pki } = setup(ext({ dependents }), cas);
    const result = await service.uploadCrl(actor, "idem-key-0003", extId, {
      crl: crl(3n, [
        { serialHex: child.cert.serialHex },
        { serialHex: other.cert.serialHex, hold: true },
        { serialHex: child.cert.serialHex },
      ]),
    });
    expect((result.body.revokedCaIds as string[]).sort()).toEqual([
      "ca-held",
      "ca-listed",
    ]);
    const calls = pki.revokeCaExternally.mock.calls;
    expect(calls).toHaveLength(2);
    const held = calls.find((call: any[]) => call[0].caId === "ca-held")!;
    expect(held[1]).toMatchObject({
      reason: "certificateHold",
      evidence: `crl:${(3).toString(16).padStart(40, "0")}`,
    });
    expect(held[0].key.state).toBe("DESTROYED");
    expect(pki.commitExternalCrl).toHaveBeenCalledTimes(1);
  });

  it("retries a stale flip against a fresh record", async () => {
    const dependents = new Set(["ca-a"]);
    const { service, pki } = setup(ext({ dependents }), { "ca-a": ca("ca-a") });
    pki
      .revokeCaExternally!.mockResolvedValueOnce("stale")
      .mockResolvedValueOnce("revoked");
    const result = await service.uploadCrl(actor, "idem-key-0004", extId, {
      crl: crl(3n, [{ serialHex: child.cert.serialHex }]),
    });
    expect(result.body.revokedCaIds).toEqual(["ca-a"]);
    expect(pki.revokeCaExternally).toHaveBeenCalledTimes(2);
  });

  it("re-runs on a version conflict, picks up a new dependent and flips it", async () => {
    let record = ext({ dependents: new Set<string>() });
    const cas = { "ca-new": ca("ca-new") };
    const { service, pki } = setup(() => record, cas);
    pki
      .commitExternalCrl!.mockImplementationOnce(async () => {
        record = ext({ dependents: new Set(["ca-new"]), version: "pkv-2" });
        return "externalChanged";
      })
      .mockResolvedValueOnce("committed");
    const result = await service.uploadCrl(actor, "idem-key-0005", extId, {
      crl: crl(3n, [{ serialHex: child.cert.serialHex }]),
    });
    expect(result.body.revokedCaIds).toEqual(["ca-new"]);
    expect(pki.commitExternalCrl.mock.calls[1]![0].loadedVersion).toBe("pkv-2");
  });

  it("returns crl_not_newer when the re-run finds a newer stored CRL", async () => {
    let record = ext();
    const { service, pki } = setup(() => record);
    pki.commitExternalCrl!.mockImplementationOnce(async () => {
      record = ext({ crl: stored(crl(9n), 9n), version: "pkv-2" });
      return "externalChanged";
    });
    expect(
      await errorOf(
        service.uploadCrl(actor, "idem-key-0006", extId, { crl: crl(3n) }),
      ),
    ).toMatchObject({ code: "crl_not_newer" });
  });

  it("gives up after three loops", async () => {
    const { service } = setup(
      ext(),
      {},
      { commitExternalCrl: jest.fn(async () => "externalChanged") },
    );
    expect(
      await errorOf(
        service.uploadCrl(actor, "idem-key-0007", extId, { crl: crl(3n) }),
      ),
    ).toMatchObject({ statusCode: 503 });
  });

  it("replays when the idempotency record already exists", async () => {
    const { service, repository } = setup(
      ext({ crl: stored(crl(3n), 3n) }),
      {},
      { commitExternalCrl: jest.fn(async () => "replay") },
    );
    const pem = crl(4n);
    repository.getIdempotency.mockResolvedValueOnce(undefined);
    const digest = jest
      .requireActual("./ca-model")
      .requestDigest("pki.external-ca.upload-crl", {
        extId,
        crlSha256: createHash("sha256").update(pem).digest("hex"),
      });
    repository.getIdempotency.mockResolvedValueOnce({
      operationType: "pki.external-ca.upload-crl",
      requestDigest: digest,
      status: "COMMITTED",
      result: { extId, numberHex: "04", revokedCaIds: ["ca-x"], changed: true },
    });
    const result = await service.uploadCrl(actor, "idem-key-0008", extId, {
      crl: pem,
    });
    expect(result.body).toMatchObject({
      changed: true,
      revokedCaIds: ["ca-x"],
    });
  });

  it("rejects an invalid CRL and an unknown external CA", async () => {
    const { service } = setup(ext());
    expect(
      await errorOf(
        service.uploadCrl(actor, "idem-key-0009", extId, { crl: "garbage" }),
      ),
    ).toMatchObject({ code: "crl_invalid" });
    const missing = setup(
      ext(),
      {},
      { getExternalCa: jest.fn(async () => undefined) },
    );
    expect(
      await errorOf(
        missing.service.uploadCrl(actor, "idem-key-0009", extId, {
          crl: crl(3n),
        }),
      ),
    ).toMatchObject({
      statusCode: 404,
      details: { reason: "external_ca_not_found" },
    });
  });

  it("keeps a CA flipped in an earlier loop in the committed result", async () => {
    const live = ca("ca-a");
    let record = ext({ dependents: new Set(["ca-a"]) });
    const cas: Record<string, CaRecord> = { "ca-a": live };
    const { service, pki } = setup(() => record, cas, {
      revokeCaExternally: jest.fn(async () => {
        cas["ca-a"] = ca("ca-a", {
          status: "REVOKED",
          revocationSource: "EXTERNAL",
          revocationEvidence: `crl:${(3).toString(16).padStart(40, "0")}`,
        });
        return "revoked";
      }),
    });
    pki
      .commitExternalCrl!.mockImplementationOnce(async () => {
        record = ext({ dependents: new Set(["ca-a"]), version: "pkv-2" });
        return "externalChanged";
      })
      .mockResolvedValueOnce("committed");
    const result = await service.uploadCrl(actor, "idem-key-0010", extId, {
      crl: crl(3n, [{ serialHex: child.cert.serialHex }]),
    });
    expect(result.body.revokedCaIds).toEqual(["ca-a"]);
    expect(result.auditTarget.revokedCaIds).toBe("ca-a");
    const committed = pki.commitExternalCrl!.mock.calls[1]![0];
    expect(committed.idempotency.result.revokedCaIds).toEqual(["ca-a"]);
    expect(pki.revokeCaExternally).toHaveBeenCalledTimes(1);
  });

  it("counts a CA this CRL already revoked before an earlier crash, but not another CRL's", async () => {
    const number = (3).toString(16).padStart(40, "0");
    const cas = {
      "ca-crashed": ca("ca-crashed", {
        status: "REVOKED",
        revocationSource: "EXTERNAL",
        revocationEvidence: `crl:${number}`,
      }),
      "ca-older": ca("ca-older", {
        status: "REVOKED",
        revocationSource: "EXTERNAL",
        revocationEvidence: `crl:${(2).toString(16).padStart(40, "0")}`,
      }),
    };
    const { service, pki } = setup(
      ext({ dependents: new Set(["ca-crashed", "ca-older"]) }),
      cas,
    );
    const result = await service.uploadCrl(actor, "idem-key-0011", extId, {
      crl: crl(3n, [{ serialHex: child.cert.serialHex }]),
    });
    expect(result.body.revokedCaIds).toEqual(["ca-crashed"]);
    expect(pki.revokeCaExternally).not.toHaveBeenCalled();
  });
});
