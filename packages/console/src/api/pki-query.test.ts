import { QueryClient } from "@tanstack/vue-query";
import { describe, expect, it } from "vitest";
import {
  applyCertificateRevoked,
  markEnvCertificatesStale,
  pkiKeys,
  type EnvCertificateSlice,
} from "./pki-query";
import type { PkiCertificateSummary } from "./pki-schemas";

const cert = (over: Partial<PkiCertificateSummary> = {}): PkiCertificateSummary => ({
  caId: "ca-a",
  serial: "01",
  status: "ISSUED",
  storedStatus: "ISSUED",
  fingerprint: "ff",
  subject: "CN=x",
  sans: {},
  keyAlgorithm: "ECDSA_P256",
  notBefore: "2026-01-01T00:00:00Z",
  notAfter: "2099-01-01T00:00:00Z",
  issuedAt: "2026-01-01T00:00:00Z",
  requester: { type: "consumer", id: "c" },
  ...over,
});
const slice = (certificates: PkiCertificateSummary[]): EnvCertificateSlice => ({
  caId: "ca-a",
  certificates,
  nextCursor: undefined,
  error: undefined,
  outdated: false,
});

const seed = () => {
  const qc = new QueryClient();
  for (const f of ["active", "expired", "revoked", "all"]) {
    qc.setQueryData([...pkiKeys.envCertificates("prod", f), ["ca-a"]], [slice([cert()])]);
  }
  return qc;
};
const data = (qc: QueryClient, f: string) =>
  qc.getQueryData<EnvCertificateSlice[]>([...pkiKeys.envCertificates("prod", f), ["ca-a"]]);
const state = (qc: QueryClient, f: string) =>
  qc.getQueryState([...pkiKeys.envCertificates("prod", f), ["ca-a"]]);

describe("env-wide certificate cache after a revoke", () => {
  it("drops the row from Active and Expired, patches All, and marks Revoked stale without a read", () => {
    const qc = seed();
    const revoked = cert({ status: "REVOKED", storedStatus: "REVOKED" });
    applyCertificateRevoked(qc, revoked);
    expect(data(qc, "active")?.[0]?.certificates).toEqual([]);
    expect(data(qc, "expired")?.[0]?.certificates).toEqual([]);
    expect(data(qc, "all")?.[0]?.certificates[0]?.status).toBe("REVOKED");
    expect(data(qc, "revoked")?.[0]?.certificates).toHaveLength(1);
    expect(state(qc, "revoked")?.isInvalidated).toBe(true);
    expect(state(qc, "all")?.isInvalidated).toBe(false);
  });

  it("marks every list stale after a bulk revoke", () => {
    const qc = seed();
    markEnvCertificatesStale(qc);
    for (const f of ["active", "expired", "revoked", "all"]) {
      expect(state(qc, f)?.isInvalidated).toBe(true);
    }
  });

  it("keeps an earlier stale mark when a single revoke touches other lists", () => {
    const qc = seed();
    markEnvCertificatesStale(qc);
    // A certificate none of the cached lists hold: the write is skipped.
    applyCertificateRevoked(qc, cert({ serial: "other", status: "REVOKED", storedStatus: "REVOKED" }));
    for (const f of ["active", "expired", "revoked", "all"]) {
      expect(state(qc, f)?.isInvalidated).toBe(true);
    }
    // One they do hold: patched, and still marked stale for the next mount.
    applyCertificateRevoked(qc, cert({ status: "REVOKED", storedStatus: "REVOKED" }));
    expect(data(qc, "active")?.[0]?.certificates).toEqual([]);
    expect(state(qc, "active")?.isInvalidated).toBe(true);
    expect(state(qc, "all")?.isInvalidated).toBe(true);
  });
});
