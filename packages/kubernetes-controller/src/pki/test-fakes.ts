// Shared fakes for the PKI tests. Compiled as a regular module, never run as a test.
import {
  HemligClient,
  type HemligTransport,
  type TransportRequest,
  type TransportResponse,
} from "@zyno-io/hemlig-client";
import type { ConsumerRegistry, RegisteredConsumer } from "../v1beta";
import { CertificateRequestReconciler } from "./certificate-requests";
import { IssuerReconciler, type PkiDeps } from "./issuers";
import { KeyedWorkQueue } from "./queue";
import { TrustBundleReconciler } from "./trust-bundles";
import { CONFIGMAP_MAX_BYTES, type Scheduler, type WatchApi } from "./types";
import { createHash } from "node:crypto";

export const flush = async (): Promise<void> => {
  for (let i = 0; i < 5; i += 1) {
    await new Promise<void>((resolve) => setImmediate(resolve));
  }
};

export class FakeScheduler implements Scheduler {
  public time = Date.parse("2026-06-01T00:00:00Z");
  public randomValue = 0;
  private nextId = 1;
  private readonly timers = new Map<number, { at: number; fn: () => void }>();

  public now(): number {
    return this.time;
  }
  public random(): number {
    return this.randomValue;
  }
  public setTimeout(fn: () => void, ms: number): unknown {
    const id = this.nextId++;
    this.timers.set(id, { at: this.time + ms, fn });
    return id;
  }
  public clearTimeout(handle: unknown): void {
    this.timers.delete(handle as number);
  }
  public get pendingTimers(): number {
    return this.timers.size;
  }
  /** Runs due timers in order, letting promises settle after each. */
  public async advance(ms: number): Promise<void> {
    const target = this.time + ms;
    for (;;) {
      let next: [number, { at: number; fn: () => void }] | undefined;
      for (const entry of this.timers) {
        if (
          entry[1].at <= target &&
          (next === undefined || entry[1].at < next[1].at)
        ) {
          next = entry;
        }
      }
      if (next === undefined) break;
      this.timers.delete(next[0]);
      this.time = Math.max(this.time, next[1].at);
      next[1].fn();
      await flush();
    }
    this.time = target;
    await flush();
  }
}

export interface CallRecord {
  readonly method: string;
  readonly plural?: string;
  readonly name?: string;
  readonly namespace?: string;
  readonly body?: unknown;
}

type Obj = {
  metadata: Record<string, any>;
  spec?: any;
  status?: any;
  [key: string]: any;
};

const apiError = (code: number): Error =>
  Object.assign(new Error(`api ${code}`), { code });

export class FakeCustom {
  public readonly calls: CallRecord[] = [];
  public readonly absent = new Set<string>();
  public readonly forbidden = new Set<string>();
  public pageSize: number | undefined;
  private readonly store = new Map<string, Obj>();
  private version = 100;
  private replaceHook: ((obj: Obj) => void) | undefined;

  private key(plural: string, namespace: string | undefined, name: string) {
    return `${plural}|${namespace ?? ""}|${name}`;
  }

  public put(plural: string, object: Obj): Obj {
    const stored = structuredClone(object);
    stored.metadata.resourceVersion = String(this.version++);
    this.store.set(
      this.key(plural, stored.metadata.namespace, stored.metadata.name),
      stored,
    );
    return stored;
  }
  public remove(plural: string, namespace: string | undefined, name: string) {
    this.store.delete(this.key(plural, namespace, name));
  }
  public peek(plural: string, namespace: string | undefined, name: string) {
    return this.store.get(this.key(plural, namespace, name));
  }
  public beforeReplace(fn: (obj: Obj) => void): void {
    this.replaceHook = fn;
  }
  /** Mutate a stored object (bumps its resourceVersion). */
  public update(
    plural: string,
    namespace: string | undefined,
    name: string,
    fn: (obj: Obj) => void,
  ): void {
    const obj = this.peek(plural, namespace, name)!;
    fn(obj);
    obj.metadata.resourceVersion = String(this.version++);
  }
  public count(method: string, plural?: string): number {
    return this.calls.filter(
      (call) =>
        call.method === method &&
        (plural === undefined || call.plural === plural),
    ).length;
  }

  public async getNamespacedCustomObject(input: {
    plural: string;
    namespace: string;
    name: string;
  }) {
    this.calls.push({ method: "get", ...input });
    const value = this.store.get(
      this.key(input.plural, input.namespace, input.name),
    );
    if (value === undefined) throw apiError(404);
    return structuredClone(value);
  }
  public async getClusterCustomObject(input: { plural: string; name: string }) {
    this.calls.push({ method: "getCluster", ...input });
    const value = this.store.get(this.key(input.plural, undefined, input.name));
    if (value === undefined) throw apiError(404);
    return structuredClone(value);
  }
  private list(input: { plural: string; limit?: number; _continue?: string }) {
    this.calls.push({ method: "list", plural: input.plural });
    if (this.absent.has(input.plural)) throw apiError(404);
    if (this.forbidden.has(input.plural)) throw apiError(403);
    const all = [...this.store.entries()]
      .filter(([key]) => key.startsWith(`${input.plural}|`))
      .map(([, value]) => structuredClone(value));
    const size =
      input.limit === 1 ? 1 : (this.pageSize ?? input.limit ?? all.length);
    const start = input._continue === undefined ? 0 : Number(input._continue);
    const items = all.slice(start, start + size);
    const more = start + size < all.length;
    return {
      items,
      metadata: {
        resourceVersion: String(this.version),
        ...(more ? { continue: String(start + size) } : {}),
      },
    };
  }
  public async listClusterCustomObject(input: any) {
    return this.list(input);
  }
  public async listCustomObjectForAllNamespaces(input: any) {
    return this.list(input);
  }
  public async replaceNamespacedCustomObjectStatus(input: {
    plural: string;
    namespace: string;
    name: string;
    body: Obj;
  }) {
    this.calls.push({
      method: "replaceStatus",
      plural: input.plural,
      namespace: input.namespace,
      name: input.name,
      body: structuredClone(input.body),
    });
    const stored = this.store.get(
      this.key(input.plural, input.namespace, input.name),
    );
    if (stored === undefined) throw apiError(404);
    this.replaceHook?.(stored);
    this.replaceHook = undefined;
    const current = this.store.get(
      this.key(input.plural, input.namespace, input.name),
    );
    if (
      current === undefined ||
      current.metadata.uid !== input.body.metadata.uid ||
      current.metadata.resourceVersion !== input.body.metadata.resourceVersion
    ) {
      throw apiError(409);
    }
    current.status = structuredClone(input.body.status);
    current.metadata.resourceVersion = String(this.version++);
    return structuredClone(current);
  }
  public async patchNamespacedCustomObjectStatus(input: {
    plural: string;
    namespace: string;
    name: string;
    body: { value: unknown }[];
  }) {
    this.calls.push({ method: "patchStatus", ...input });
    const stored = this.store.get(
      this.key(input.plural, input.namespace, input.name),
    );
    if (stored === undefined) throw apiError(404);
    stored.status = structuredClone(input.body[0]!.value);
    stored.metadata.resourceVersion = String(this.version++);
  }
  public async patchClusterCustomObjectStatus(input: {
    plural: string;
    name: string;
    body: { value: unknown }[];
  }) {
    this.calls.push({ method: "patchClusterStatus", ...input });
    const stored = this.store.get(
      this.key(input.plural, undefined, input.name),
    );
    if (stored === undefined) throw apiError(404);
    stored.status = structuredClone(input.body[0]!.value);
    stored.metadata.resourceVersion = String(this.version++);
  }
}

export interface ConfigMapCall {
  readonly op: "read" | "create" | "replace" | "delete";
  readonly namespace: string;
  readonly name: string;
  readonly body?: any;
}

export class FakeCore {
  public readonly labels = new Map<string, Record<string, string>>();
  public readonly configMapCalls: ConfigMapCall[] = [];
  /** Names the fake API server refuses with 422. */
  public readonly rejectConfigMaps = new Set<string>();
  public secretWrites = 0;
  /** The largest values-only payload any create or replace carried. */
  public maxWrittenBytes = 0;
  private readonly configMaps = new Map<string, any>();
  private uidCounter = 1;
  private cmVersion = 1;

  public async readNamespace(input: { name: string }) {
    const labels = this.labels.get(input.name);
    if (labels === undefined) throw apiError(404);
    return { metadata: { name: input.name, labels } };
  }
  public async createNamespacedSecret() {
    this.secretWrites += 1;
  }
  public async replaceNamespacedSecret() {
    this.secretWrites += 1;
  }
  public async deleteNamespacedSecret() {
    this.secretWrites += 1;
  }

  /** Seeds a ConfigMap as another actor would have created it. */
  public seedConfigMap(namespace: string, object: any): any {
    const stored = structuredClone(object);
    stored.metadata = {
      ...stored.metadata,
      namespace,
      uid: stored.metadata.uid ?? `cm-uid-${this.uidCounter++}`,
      resourceVersion: String(this.cmVersion++),
    };
    this.configMaps.set(`${namespace}/${stored.metadata.name}`, stored);
    return stored;
  }
  public configMap(namespace: string, name: string): any | undefined {
    return this.configMaps.get(`${namespace}/${name}`);
  }
  public configMapNames(namespace: string): string[] {
    return [...this.configMaps.keys()]
      .filter((key) => key.startsWith(`${namespace}/`))
      .map((key) => key.slice(namespace.length + 1))
      .sort();
  }
  public callsOf(op: ConfigMapCall["op"], name?: string): ConfigMapCall[] {
    return this.configMapCalls.filter(
      (call) => call.op === op && (name === undefined || call.name === name),
    );
  }

  public async readNamespacedConfigMap(input: {
    name: string;
    namespace: string;
  }) {
    this.configMapCalls.push({ op: "read", ...input });
    const value = this.configMap(input.namespace, input.name);
    if (value === undefined) throw apiError(404);
    return structuredClone(value);
  }
  private checkWrite(name: string, body: any): void {
    if (this.rejectConfigMaps.has(name)) throw apiError(422);
    let bytes = 0;
    for (const value of Object.values<string>(body.data ?? {})) {
      bytes += Buffer.byteLength(value, "utf8");
    }
    for (const value of Object.values<string>(body.binaryData ?? {})) {
      bytes += Buffer.from(value, "base64").length;
    }
    this.maxWrittenBytes = Math.max(this.maxWrittenBytes, bytes);
    if (bytes > CONFIGMAP_MAX_BYTES) throw apiError(422);
  }
  public async createNamespacedConfigMap(input: {
    namespace: string;
    body: any;
  }) {
    const name = input.body.metadata.name as string;
    this.configMapCalls.push({
      op: "create",
      namespace: input.namespace,
      name,
      body: structuredClone(input.body),
    });
    if (this.configMap(input.namespace, name) !== undefined) {
      throw apiError(409);
    }
    this.checkWrite(name, input.body);
    return this.seedConfigMap(input.namespace, input.body);
  }
  public async replaceNamespacedConfigMap(input: {
    name: string;
    namespace: string;
    body: any;
  }) {
    this.configMapCalls.push({
      op: "replace",
      namespace: input.namespace,
      name: input.name,
      body: structuredClone(input.body),
    });
    const current = this.configMap(input.namespace, input.name);
    if (current === undefined) throw apiError(404);
    if (
      input.body.metadata.resourceVersion !== current.metadata.resourceVersion
    ) {
      throw apiError(409);
    }
    this.checkWrite(input.name, input.body);
    return this.seedConfigMap(input.namespace, {
      ...input.body,
      metadata: { ...input.body.metadata, uid: current.metadata.uid },
    });
  }
  public async deleteNamespacedConfigMap(input: {
    name: string;
    namespace: string;
    body?: { preconditions?: { uid?: string; resourceVersion?: string } };
  }) {
    this.configMapCalls.push({
      op: "delete",
      namespace: input.namespace,
      name: input.name,
      body: structuredClone(input.body),
    });
    const current = this.configMap(input.namespace, input.name);
    if (current === undefined) throw apiError(404);
    const uid = input.body?.preconditions?.uid;
    if (uid !== undefined && uid !== current.metadata.uid) throw apiError(409);
    const version = input.body?.preconditions?.resourceVersion;
    if (version !== undefined && version !== current.metadata.resourceVersion) {
      throw apiError(409);
    }
    this.configMaps.delete(`${input.namespace}/${input.name}`);
  }
}

interface Watcher {
  readonly path: string;
  readonly query: Record<string, unknown>;
  readonly onEvent: (phase: string, object: unknown) => void;
  readonly done: (error: unknown) => void;
  readonly controller: AbortController;
}

export class FakeWatch implements WatchApi {
  public readonly watches: Watcher[] = [];
  public async watch(
    path: string,
    query: Record<string, unknown>,
    onEvent: (phase: string, object: unknown) => void,
    done: (error: unknown) => void,
  ): Promise<AbortController> {
    const controller = new AbortController();
    this.watches.push({ path, query, onEvent, done, controller });
    return controller;
  }
  public active(path: string): Watcher | undefined {
    return this.watches
      .filter((w) => w.path === path && !w.controller.signal.aborted)
      .at(-1);
  }
  public paths(): string[] {
    return this.watches.map((w) => w.path);
  }
  public emit(path: string, phase: string, object: unknown): void {
    const watcher = this.active(path);
    if (watcher === undefined) throw new Error(`no watch for ${path}`);
    watcher.onEvent(phase, object);
  }
  public end(path: string, error?: unknown): void {
    const watcher = this.active(path);
    if (watcher === undefined) throw new Error(`no watch for ${path}`);
    watcher.done(error);
  }
}

export class FakeTransport implements HemligTransport {
  public readonly requests: TransportRequest[] = [];
  public handler: (
    request: TransportRequest,
  ) => TransportResponse | Promise<TransportResponse>;
  public constructor() {
    this.handler = (request) => defaultResponse(request);
  }
  public async request(request: TransportRequest): Promise<TransportResponse> {
    this.requests.push({
      ...request,
      body:
        request.body === undefined ? undefined : structuredClone(request.body),
    });
    return this.handler(request);
  }
  public posts(): TransportRequest[] {
    return this.requests.filter((request) => request.method === "POST");
  }
}

export const leafPem =
  "-----BEGIN CERTIFICATE-----\nTEVBRg==\n-----END CERTIFICATE-----\n";
export const chainPem =
  "-----BEGIN CERTIFICATE-----\nSU5U\n-----END CERTIFICATE-----\n";
export const rootPem =
  "-----BEGIN CERTIFICATE-----\nUk9PVA==\n-----END CERTIFICATE-----\n";

export const grantBody = (overrides: Record<string, unknown> = {}) => ({
  name: "grant-one",
  uid: "grant-uid",
  status: "ACTIVE",
  expired: false,
  version: "gv1",
  policy: {},
  quotas: {},
  ca: {
    caId: "ca-issuing-1",
    fingerprint: "ab:cd",
    notAfter: "2030-01-01T00:00:00Z",
    status: "ACTIVE",
  },
  ...overrides,
});

export const errorResponse = (
  status: number,
  code?: string,
  details?: Record<string, string | number | boolean>,
  headers: Record<string, string> = {},
): TransportResponse => ({
  status,
  headers,
  body: {
    error: { code, message: "SECRET server message", details },
  },
});

const defaultResponse = (request: TransportRequest): TransportResponse => {
  if (request.method === "GET")
    return { status: 200, headers: {}, body: grantBody() };
  return {
    status: 201,
    headers: {},
    body: {
      caId: "ca-issuing-1",
      serial: "0a1b2c3d",
      fingerprint: "ff",
      certificatePem: leafPem,
      chainPem,
      caPem: rootPem,
      notBefore: "2026-06-01T00:00:00Z",
      notAfter: "2026-06-01T01:00:00Z",
      lifetimeClamped: false,
    },
  };
};

export class FakeRegistry implements ConsumerRegistry {
  public readonly entries = new Map<string, RegisteredConsumer>();
  public readonly listeners = new Set<(changed: ReadonlySet<string>) => void>();
  public get(key: string) {
    return this.entries.get(key);
  }
  public onChange(listener: (changed: ReadonlySet<string>) => void) {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }
  public fire(...keys: string[]): void {
    for (const listener of [...this.listeners]) listener(new Set(keys));
  }
}

export const registered = (
  transport: HemligTransport,
  overrides: Partial<RegisteredConsumer> = {},
): RegisteredConsumer => ({
  key: "app/consumer",
  uid: "consumer-uid",
  generation: 1,
  resource: {} as never,
  provider: {
    metadata: { generation: 1 },
    spec: {
      apiUrl: "https://api.test",
      allowedNamespaces: { matchLabels: {} },
    },
  } as never,
  client: new HemligClient(new URL("https://api.test"), transport),
  consumerId: "agent",
  environment: "prod",
  identityFingerprint: "fp1",
  ...overrides,
});

export const csrPem =
  "-----BEGIN CERTIFICATE REQUEST-----\nQ1NS\n-----END CERTIFICATE REQUEST-----\n";
export const crUid = "11111111-2222-3333-4444-555555555555";

export const consumerObject = (spec: Record<string, unknown> = {}): Obj => ({
  metadata: {
    name: "consumer",
    namespace: "app",
    uid: "consumer-uid",
    generation: 1,
  },
  spec: { providerRef: "p", ...spec },
});

export const issuerObject = (
  options: {
    ready?: boolean;
    generation?: number;
    observed?: number;
    consumerId?: string;
    spec?: Record<string, unknown>;
  } = {},
): Obj => {
  const generation = options.generation ?? 1;
  return {
    metadata: {
      name: "issuer",
      namespace: "app",
      uid: "issuer-uid",
      generation,
    },
    spec: {
      consumerRef: "consumer",
      issuanceGrant: "grant-one",
      ...options.spec,
    },
    status: {
      observedGeneration: options.observed ?? generation,
      consumerId: options.consumerId ?? "agent",
      conditions: [
        {
          type: "Ready",
          status: options.ready === false ? "False" : "True",
          reason: options.ready === false ? "CaNotActive" : "Ready",
          message: "m",
          lastTransitionTime: "2026-05-01T00:00:00Z",
        },
      ],
    },
  };
};

export const crObject = (
  options: {
    approved?: boolean;
    spec?: Record<string, unknown>;
    metadata?: Record<string, unknown>;
    conditions?: object[];
    name?: string;
    uid?: string;
  } = {},
): Obj => ({
  apiVersion: "cert-manager.io/v1",
  kind: "CertificateRequest",
  metadata: {
    name: options.name ?? "cr-1",
    namespace: "app",
    uid: options.uid ?? crUid,
    ...options.metadata,
  },
  spec: {
    request: Buffer.from(csrPem).toString("base64"),
    issuerRef: {
      group: "hemlig.zyno.io",
      kind: "HemligIssuer",
      name: "issuer",
    },
    usages: ["server auth"],
    duration: "1h",
    username: "system:serviceaccount:cert-manager:cert-manager",
    groups: ["system:serviceaccounts"],
    ...options.spec,
  },
  status: {
    conditions: options.conditions ?? [
      ...(options.approved === false
        ? []
        : [
            {
              type: "Approved",
              status: "True",
              reason: "cert-manager.io",
              message: "Approved by cert-manager",
              lastTransitionTime: "2026-06-01T00:00:00Z",
            },
          ]),
    ],
  },
});

/** Queue + both reconcilers wired the way the module does, without streams. */
export const rig = (options: { concurrency?: number } = {}) => {
  const scheduler = new FakeScheduler();
  const custom = new FakeCustom();
  const core = new FakeCore();
  core.labels.set("app", {});
  const registry = new FakeRegistry();
  const transport = new FakeTransport();
  registry.entries.set("app/consumer", registered(transport));
  custom.put("hemligconsumers", consumerObject());
  const deps: PkiDeps = {
    core: core as never,
    custom: custom as never,
    registry,
    scheduler,
  };
  const pending = new Set<string>();
  const queue: KeyedWorkQueue = new KeyedWorkQueue(
    (key, context) =>
      key.startsWith("cr/")
        ? requests.reconcile(key, context)
        : issuers.reconcile(key, context),
    {
      concurrency: options.concurrency ?? 4,
      groupConcurrency: 2,
      scheduler,
    },
  );
  const issuers = new IssuerReconciler(deps, queue);
  const requests = new CertificateRequestReconciler(
    deps,
    issuers,
    queue,
    pending,
  );
  const run = async (key: string) => {
    queue.add(key);
    await queue.whenIdle();
    await flush();
  };
  const cr = (name = "cr-1") =>
    custom.peek("certificaterequests", "app", name)!;
  const ready = (name = "cr-1") =>
    cr(name).status?.conditions?.find((c: any) => c.type === "Ready");
  return {
    scheduler,
    custom,
    core,
    registry,
    transport,
    deps,
    pending,
    queue,
    issuers,
    requests,
    run,
    cr,
    ready,
  };
};

// -- Trust bundles ---------------------------------------------------------------

export const pemOf = (label: string): string =>
  `-----BEGIN CERTIFICATE-----\n${Buffer.from(label).toString("base64")}\n-----END CERTIFICATE-----\n`;

export const sha256Of = (bytes: Uint8Array): string =>
  createHash("sha256").update(bytes).digest("hex");

export interface Fault {
  readonly fault: true;
  readonly status: number;
  readonly code?: string;
  readonly reason?: string;
}

export interface CrlFixture {
  readonly der: Buffer;
  readonly number: string;
  readonly thisUpdate: string;
  readonly nextUpdate: string;
}

export const fault = (
  status: number,
  code?: string,
  reason?: string,
): Fault => ({
  fault: true,
  status,
  ...(code === undefined ? {} : { code }),
  ...(reason === undefined ? {} : { reason }),
});

export const caView = (
  id: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> => ({
  caId: id,
  name: id,
  status: "ACTIVE",
  drained: false,
  fingerprint: "ff",
  notAfter: "2030-01-01T00:00:00.000Z",
  anchorPem: rootPem,
  anchorTrusted: true,
  chainPem: pemOf(id),
  crlIssuers: [{ id, source: "GENERATED" }],
  ...overrides,
});

export const crlFixture = (
  size: number,
  number: string,
  nextUpdate = "2026-06-08T00:00:00.000Z",
  fill = 7,
): CrlFixture => ({
  der: Buffer.alloc(size, fill),
  number,
  thisUpdate: "2026-06-01T00:00:00.000Z",
  nextUpdate,
});

/** Answers the consumer bundle and CRL routes from in-memory fixtures. */
export class BundleServer {
  public readonly views = new Map<string, Record<string, unknown> | Fault>();
  public readonly crls = new Map<string, CrlFixture | Fault>();

  public readonly handler = (request: TransportRequest): TransportResponse => {
    const path = request.url.pathname;
    const bundle = /^\/v1\/pki\/cas\/([^/]+)\/bundle$/.exec(path);
    if (bundle !== null) {
      return this.answer(this.views.get(bundle[1] as string), (view) => ({
        status: 200,
        headers: {},
        body: view,
      }));
    }
    const crl = /^\/v1\/pki\/crls\/([^/]+)$/.exec(path);
    if (crl !== null) {
      return this.answer(this.crls.get(crl[1] as string), (entry) => {
        const etag = sha256Of(entry.der);
        const headers = {
          etag,
          "content-type": "application/pkix-crl",
          "hemlig-crl-number": entry.number,
          "hemlig-crl-this-update": entry.thisUpdate,
          "hemlig-crl-next-update": entry.nextUpdate,
        };
        const sent = request.headers?.["if-none-match"]?.replace(/"/g, "");
        return sent === etag || sent === "*"
          ? { status: 304, headers }
          : { status: 200, headers, bytes: Uint8Array.from(entry.der) };
      });
    }
    return errorResponse(404, "not_found");
  };

  private answer<T extends object>(
    value: T | Fault | undefined,
    ok: (value: T) => TransportResponse,
  ): TransportResponse {
    if (value === undefined) {
      return errorResponse(404, "not_found", { reason: "ca_not_found" });
    }
    if ("fault" in value && (value as Fault).fault === true) {
      const failure = value as Fault;
      return errorResponse(
        failure.status,
        failure.code,
        failure.reason === undefined ? undefined : { reason: failure.reason },
      );
    }
    return ok(value as T);
  }
}

export const bundleObject = (
  spec: Record<string, unknown> = {},
  options: { generation?: number; name?: string } = {},
): Obj => ({
  apiVersion: "hemlig.zyno.io/v1alpha1",
  kind: "HemligTrustBundle",
  metadata: {
    name: options.name ?? "bundle",
    namespace: "app",
    uid: "bundle-uid",
    generation: options.generation ?? 1,
  },
  spec: {
    consumerRef: "consumer",
    caIds: ["ca-aaa"],
    target: { name: "trust" },
    ...spec,
  },
});

/** The trust-bundle reconciler on its own queue, wired like `rig()`. */
export const bundleRig = (options: { concurrency?: number } = {}) => {
  const scheduler = new FakeScheduler();
  const custom = new FakeCustom();
  const core = new FakeCore();
  core.labels.set("app", {});
  const registry = new FakeRegistry();
  const transport = new FakeTransport();
  const server = new BundleServer();
  transport.handler = server.handler;
  registry.entries.set("app/consumer", registered(transport));
  custom.put("hemligconsumers", consumerObject());
  const deps: PkiDeps = {
    core: core as never,
    custom: custom as never,
    registry,
    scheduler,
  };
  const queue: KeyedWorkQueue = new KeyedWorkQueue(
    (key, context) => reconciler.reconcile(key, context),
    {
      concurrency: options.concurrency ?? 4,
      groupConcurrency: 2,
      scheduler,
    },
  );
  const reconciler = new TrustBundleReconciler(deps, queue);
  const key = "bundle/app/bundle";
  const run = async (target: string = key) => {
    queue.add(target);
    await queue.whenIdle();
    await flush();
  };
  const bundle = (name = "bundle") =>
    custom.peek("hemligtrustbundles", "app", name)!;
  const ready = (name = "bundle") =>
    bundle(name).status?.conditions?.find((c: any) => c.type === "Ready");
  /** Edits the stored bundle spec and bumps its generation, like an apply would. */
  const edit = (spec: Record<string, unknown>) => {
    custom.update("hemligtrustbundles", "app", "bundle", (o) => {
      o.spec = { ...o.spec, ...spec };
      o.metadata.generation += 1;
    });
  };
  return {
    scheduler,
    custom,
    core,
    registry,
    transport,
    server,
    deps,
    queue,
    reconciler,
    key,
    run,
    bundle,
    ready,
    edit,
  };
};
