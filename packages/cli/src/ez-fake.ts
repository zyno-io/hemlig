import { createHash } from "node:crypto";
import type { HemligTransport, TransportRequest, TransportResponse } from "@zyno-io/hemlig-client";
import { makeTestCsr, type TestCsrOptions } from "./ez-testkit";
import { fromPem, parseCertificate, parseCrl, sha256Hex, type CrlEntry } from "./ez-x509";
import type { TerminalInput } from "./tty";

/** Test doubles for the EZ commands: a scripted terminal and a fake Hemlig admin API. Not used at runtime. */

/** A terminal that replays queued keystrokes; reading past the end is EOF. Supports the stream features `tty.ts` uses. */
export class FakeTerminal implements TerminalInput {
  public readonly isTTY = true;
  public readonly rawModes: boolean[] = [];
  public destroyed = false;
  readonly #queue: (string | number)[];

  /** Strings are keystroke chunks; a number waits that many milliseconds before the next chunk arrives. */
  public constructor(...input: (string | number)[]) {
    this.#queue = [...input];
  }

  public setRawMode(mode: boolean): void {
    this.rawModes.push(mode);
  }
  public pause(): void {}
  public resume(): void {}
  public destroy(): void {
    this.destroyed = true;
  }
  public unshift(chunk: Buffer): void {
    this.#queue.unshift(chunk.toString("utf8"));
  }
  public iterator(): AsyncIterator<string> {
    return {
      next: async () => {
        while (typeof this.#queue[0] === "number") await new Promise((resolve) => setTimeout(resolve, this.#queue.shift() as number));
        return this.#queue.length > 0 ? { done: false, value: this.#queue.shift() as string } : { done: true, value: undefined };
      },
      return: async () => ({ done: true, value: undefined }),
    };
  }
  public [Symbol.asyncIterator](): AsyncIterator<string> {
    return this.iterator();
  }
  /** Keystrokes still unread. */
  public get remaining(): string[] {
    return this.#queue.filter((x): x is string => typeof x === "string");
  }
}

/** A piped stdin (not a terminal). */
export const pipeInput = (text = ""): TerminalInput => ({
  async *[Symbol.asyncIterator]() {
    if (text !== "") yield text;
  },
});

export interface FakeCa {
  readonly caId: string;
  readonly environment: string;
  readonly name: string;
  kind: string;
  status: string;
  version: string;
  fingerprint?: string;
  parent?: { type: string; id: string };
  readonly spkiSha256: string;
  readonly subject: { commonName: string; organization?: string };
  readonly requestedConstraints: Record<string, unknown>;
  csrPem: string;
  certificateSerial?: string;
}

export const caIdOf = (n: number): string => `ca-11111111-2222-3333-4444-${String(n).padStart(12, "0")}`;

/** A pending EXTERNAL_INTERMEDIATE record with a Hemlig-style CSR. */
export const pendingCa = (
  n: number,
  csrOptions: TestCsrOptions & { requested?: Record<string, unknown> } = {},
): { record: FakeCa; csr: ReturnType<typeof makeTestCsr> } => {
  const subject = csrOptions.subject ?? { O: "Example Corp", CN: `Prod Issuing CA ${n}` };
  const csr = makeTestCsr({ ...csrOptions, subject });
  return {
    csr,
    record: {
      caId: caIdOf(n),
      environment: "prod",
      name: `prod-issuing-${n}`,
      kind: "EXTERNAL_INTERMEDIATE",
      status: "PENDING_CERTIFICATE",
      version: "v1",
      spkiSha256: sha256Hex(csr.spkiDer),
      subject: { commonName: subject.CN, ...(subject.O === undefined ? {} : { organization: subject.O }) },
      requestedConstraints: csrOptions.requested ?? {},
      csrPem: csr.pem,
    },
  };
};

interface FakeExternal {
  extId: string;
  fingerprint: string;
  crlPem?: string;
  crl?: { numberHex: string; sha256: string; thisUpdate: string; nextUpdate: string };
  dependents: Set<string>;
  serials: Map<string, string>;
}

const errorResponse = (status: number, code: string, details: Record<string, string> = {}): TransportResponse => ({
  status,
  headers: {},
  body: { error: { code, message: code, details } },
});

/** A stateful stand-in for the admin API routes the EZ commands use, with the server's activation and CRL rules. */
export class FakeServer implements HemligTransport {
  public readonly cas = new Map<string, FakeCa>();
  public readonly externals = new Map<string, FakeExternal>();
  public readonly requests: TransportRequest[] = [];
  public dateHeader: string | undefined;
  /** Fail (throw a transport error) on the next request whose path ends with this suffix, after (`after`) or before processing. */
  public failNext: { suffix: string; after: boolean } | undefined;
  /** Ignore CRL uploads' revocations (to test `revocation_not_applied`). */
  public ignoreRevocations = false;
  readonly #replays = new Map<string, TransportResponse>();

  public add(record: FakeCa): void {
    this.cas.set(record.caId, record);
  }

  public async request(request: TransportRequest): Promise<TransportResponse> {
    this.requests.push(request);
    const path = request.url.pathname;
    const failing = this.failNext !== undefined && path.endsWith(this.failNext.suffix);
    if (failing && !this.failNext?.after) {
      this.failNext = undefined;
      throw new TypeError("fetch failed");
    }
    const key = request.headers?.["idempotency-key"];
    let response: TransportResponse;
    if (key !== undefined && this.#replays.has(`${path}|${key}`)) response = this.#replays.get(`${path}|${key}`) as TransportResponse;
    else {
      response = this.route(request);
      if (key !== undefined && response.status < 300) this.#replays.set(`${path}|${key}`, response);
    }
    if (failing) {
      this.failNext = undefined;
      throw new TypeError("fetch failed");
    }
    return this.dateHeader === undefined ? response : { ...response, headers: { ...response.headers, date: this.dateHeader } };
  }

  /** Requests that changed something, in order. */
  public get mutations(): TransportRequest[] {
    return this.requests.filter((r) => r.method === "POST");
  }

  private detail(ca: FakeCa): Record<string, unknown> {
    return {
      caId: ca.caId,
      environment: ca.environment,
      name: ca.name,
      kind: ca.kind,
      status: ca.status,
      version: ca.version,
      keyAlgorithm: "ECDSA_P256",
      keyState: "ACTIVE",
      key: { custody: "KMS", algorithm: "ECDSA_P256", spkiSha256: ca.spkiSha256, state: "ACTIVE" },
      subject: ca.subject,
      requestedConstraints: ca.requestedConstraints,
      csrPem: ca.status === "PENDING_CERTIFICATE" ? ca.csrPem : undefined,
      ...(ca.fingerprint === undefined ? {} : { fingerprint: ca.fingerprint }),
      ...(ca.parent === undefined ? {} : { parent: ca.parent }),
      createdAt: "2026-11-25T00:00:00.000Z",
    };
  }

  private externalDetail(ext: FakeExternal): Record<string, unknown> {
    return {
      extId: ext.extId,
      fingerprint: ext.fingerprint,
      subjectDn: "x",
      notAfter: "2046-01-01T00:00:00.000Z",
      crlState: "OK",
      version: "e1",
      createdAt: "2026-11-25T00:00:00.000Z",
      ...(ext.crl === undefined ? {} : { crl: ext.crl }),
    };
  }

  private applyCrl(ext: FakeExternal, pem: string): TransportResponse {
    const der = fromPem(pem, "X509 CRL");
    const crl = parseCrl(der);
    const sha256 = sha256Hex(der);
    const number = (crl.number as bigint).toString(16).padStart(2, "0");
    if (ext.crl?.sha256 === sha256) return { status: 200, headers: {}, body: { extId: ext.extId, crl: ext.crl, changed: false, revokedCaIds: this.revoked(ext, crl.entries) } };
    if (ext.crl !== undefined && BigInt(`0x${ext.crl.numberHex}`) >= (crl.number as bigint)) return errorResponse(409, "crl_not_newer");
    ext.crlPem = pem;
    ext.crl = { numberHex: number, sha256, thisUpdate: crl.thisUpdate.toISOString(), nextUpdate: (crl.nextUpdate as Date).toISOString() };
    return { status: 200, headers: {}, body: { extId: ext.extId, crl: ext.crl, changed: true, revokedCaIds: this.revoked(ext, crl.entries) } };
  }

  private revoked(ext: FakeExternal, entries: readonly CrlEntry[]): string[] {
    if (this.ignoreRevocations) return [];
    const listed = new Set(entries.map((e) => e.serial));
    const out: string[] = [];
    for (const [serial, caId] of ext.serials) {
      if (!listed.has(serial)) continue;
      out.push(caId);
      const ca = this.cas.get(caId);
      if (ca !== undefined) ca.status = "REVOKED";
    }
    return out;
  }

  private route(request: TransportRequest): TransportResponse {
    const path = request.url.pathname;
    const body = request.body as Record<string, string | undefined> | undefined;
    let match = /^\/v1\/admin\/pki\/cas\/([^/]+)$/.exec(path);
    if (match !== null && request.method === "GET") {
      const ca = this.cas.get(match[1] as string);
      return ca === undefined ? errorResponse(404, "not_found") : { status: 200, headers: {}, body: this.detail(ca) };
    }
    match = /^\/v1\/admin\/pki\/cas\/([^/]+)\/certificate$/.exec(path);
    if (match !== null && request.method === "POST") return this.activate(this.cas.get(match[1] as string), body);
    if (path === "/v1/admin/pki/external-cas" && request.method === "GET") {
      return {
        status: 200,
        headers: {},
        body: { externalCas: [...this.externals.values()].map((e) => this.externalDetail(e)), generatedAt: "2026-11-25T00:00:00.000Z" },
      };
    }
    match = /^\/v1\/admin\/pki\/external-cas\/([^/]+)$/.exec(path);
    if (match !== null && request.method === "GET") {
      const ext = this.externals.get(match[1] as string);
      return ext === undefined ? errorResponse(404, "not_found") : { status: 200, headers: {}, body: this.externalDetail(ext) };
    }
    match = /^\/v1\/admin\/pki\/external-cas\/([^/]+)\/crl$/.exec(path);
    if (match !== null && request.method === "POST") {
      const ext = this.externals.get(match[1] as string);
      return ext === undefined ? errorResponse(404, "not_found") : this.applyCrl(ext, body?.crl as string);
    }
    return errorResponse(404, "not_found");
  }

  private activate(ca: FakeCa | undefined, body: Record<string, string | undefined> | undefined): TransportResponse {
    if (ca === undefined) return errorResponse(404, "not_found");
    if (ca.status !== "PENDING_CERTIFICATE") return errorResponse(409, "conflict", { reason: "ca_not_pending" });
    const cert = parseCertificate(fromPem(body?.certificatePem as string, "CERTIFICATE"));
    const root = parseCertificate(fromPem(body?.chainPem as string, "CERTIFICATE"));
    if (cert.spkiSha256 !== ca.spkiSha256) return errorResponse(422, "chain_invalid", { reason: "spki_mismatch" });
    const extId = `ext-${root.spkiSha256.slice(0, 40)}`;
    let ext = this.externals.get(extId);
    if (ext !== undefined && body?.rootCrl !== undefined) {
      const stored = ext.crlPem === undefined ? undefined : sha256Hex(fromPem(ext.crlPem, "X509 CRL"));
      if (stored !== sha256Hex(fromPem(body.rootCrl, "X509 CRL"))) return errorResponse(409, "crl_invalid", { reason: "upload_first" });
    }
    if (body?.rootCrl !== undefined) {
      const crl = parseCrl(fromPem(body.rootCrl, "X509 CRL"));
      if (crl.entries.some((e) => e.serial === cert.serialHex)) return errorResponse(409, "ca_not_active", { reason: "revoked_by_parent" });
    }
    if (ext === undefined) {
      ext = { extId, fingerprint: root.fingerprint, dependents: new Set(), serials: new Map() };
      this.externals.set(extId, ext);
      if (body?.rootCrl !== undefined) this.applyCrl(ext, body.rootCrl);
    }
    ext.dependents.add(ca.caId);
    ext.serials.set(cert.serialHex, ca.caId);
    ca.status = "ACTIVE";
    ca.fingerprint = cert.fingerprint;
    ca.certificateSerial = cert.serialHex;
    ca.parent = { type: "external", id: extId };
    ca.version = `v${Number(ca.version.slice(1)) + 1}`;
    return { status: 200, headers: {}, body: this.detail(ca) };
  }

  /** The activation requests, as `{caId, key, body}`. */
  public activations(): { caId: string; key: string | undefined; body: Record<string, string | undefined> }[] {
    return this.requests
      .filter((r) => r.method === "POST" && r.url.pathname.endsWith("/certificate"))
      .map((r) => ({
        caId: /cas\/([^/]+)\//.exec(r.url.pathname)?.[1] as string,
        key: r.headers?.["idempotency-key"],
        body: r.body as Record<string, string | undefined>,
      }));
  }

  public uploads(): { extId: string; key: string | undefined; sha256: string; number: bigint }[] {
    return this.requests
      .filter((r) => r.method === "POST" && r.url.pathname.endsWith("/crl"))
      .map((r) => {
        const der = fromPem((r.body as { crl: string }).crl, "X509 CRL");
        return {
          extId: /external-cas\/([^/]+)\//.exec(r.url.pathname)?.[1] as string,
          key: r.headers?.["idempotency-key"],
          sha256: createHash("sha256").update(der).digest("hex"),
          number: parseCrl(der).number as bigint,
        };
      });
  }
}
