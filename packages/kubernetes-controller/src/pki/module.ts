import type { ConsumerRegistry, CoreApi, CustomApi } from "../v1beta";
import { CertificateRequestReconciler } from "./certificate-requests";
import { isHemligRequest, isTerminal } from "./cert-manager";
import { IssuerReconciler } from "./issuers";
import { KeyedWorkQueue, type Outcome, type WorkContext } from "./queue";
import {
  CLUSTER_ISSUER_PLURAL,
  CM_GROUP,
  CM_VERSION,
  CR_PLURAL,
  GROUP_CONCURRENCY,
  HEMLIG_GROUP,
  ISSUER_PLURAL,
  ISSUER_VERSION,
  RELIST_PAGE,
  RESYNC_MS,
  clusterIssuerKey,
  isForbidden,
  isGone,
  isNotFound,
  issuerKey,
  log,
  realScheduler,
  requestKey,
  unwrap,
  type CertificateRequest,
  type PkiConfig,
  type Scheduler,
  type WatchApi,
} from "./types";

export interface PkiModuleDeps {
  readonly core: CoreApi;
  readonly custom: CustomApi;
  readonly watch: WatchApi;
  readonly registry: ConsumerRegistry;
  readonly config: PkiConfig;
  readonly scheduler?: Scheduler;
}

interface ObjectLike {
  readonly metadata?: {
    readonly name?: string;
    readonly namespace?: string;
    readonly generation?: number;
    readonly resourceVersion?: string;
  };
  readonly status?: { readonly observedGeneration?: number };
}

interface StreamResource {
  readonly name: string;
  readonly group: string;
  readonly version: string;
  readonly plural: string;
  readonly scope: "all" | "cluster";
  readonly onEvent: (phase: string, object: unknown) => void;
  /** Maps a listed item to the key worth keeping; pages are filtered as they arrive. */
  readonly keyOf: (item: unknown) => string | undefined;
  readonly onRelist: (keys: readonly string[]) => void;
}

interface Feature {
  readonly name: string;
  readonly resources: readonly StreamResource[];
  enabled: boolean;
  readonly streams: Map<StreamResource, Stream>;
  /** Drops every key and in-memory record the feature owns. */
  readonly clear: () => void;
}

const watchPath = (resource: StreamResource): string =>
  `/apis/${resource.group}/${resource.version}/${resource.plural}`;

const RETRY_WATCH_MS = 1_000;
const RETRY_RELIST_MS = 5_000;

/** One list-then-watch loop for a single resource. */
class Stream {
  private rv: string | undefined;
  private controller: AbortController | undefined;
  private active = false;
  private generation = 0;
  private relisting: Promise<void> | undefined;
  /** A 410 arrived while a relist was in flight: relist once more afterwards. */
  private relistAgain = false;
  private timer: unknown;

  public constructor(
    private readonly resource: StreamResource,
    private readonly custom: CustomApi,
    private readonly watchApi: WatchApi,
    private readonly scheduler: Scheduler,
  ) {}

  public get running(): boolean {
    return this.active;
  }

  public start(): Promise<void> {
    if (this.active) return Promise.resolve();
    this.active = true;
    return this.relist();
  }

  public stop(): void {
    this.active = false;
    this.abortWatch();
    if (this.timer !== undefined) this.scheduler.clearTimeout(this.timer);
    this.timer = undefined;
  }

  private abortWatch(): void {
    this.generation += 1;
    this.controller?.abort();
    this.controller = undefined;
  }

  /** Single-flight. */
  public relist(): Promise<void> {
    if (this.relisting !== undefined) {
      this.relistAgain = true;
      return this.relisting;
    }
    this.relisting = this.doRelist()
      .finally(() => {
        this.relisting = undefined;
      })
      .then(() => {
        if (!this.relistAgain) return undefined;
        this.relistAgain = false;
        return this.active ? this.relist() : undefined;
      });
    return this.relisting;
  }

  private async doRelist(): Promise<void> {
    this.abortWatch();
    const generation = this.generation;
    let keys: string[] = [];
    let resourceVersion: string | undefined;
    try {
      for (;;) {
        try {
          keys = [];
          let token: string | undefined;
          do {
            const page = unwrap(
              await (this.resource.scope === "cluster"
                ? this.custom.listClusterCustomObject({
                    group: this.resource.group,
                    version: this.resource.version,
                    plural: this.resource.plural,
                    limit: RELIST_PAGE,
                    ...(token === undefined ? {} : { _continue: token }),
                  })
                : this.custom.listCustomObjectForAllNamespaces({
                    group: this.resource.group,
                    version: this.resource.version,
                    plural: this.resource.plural,
                    limit: RELIST_PAGE,
                    ...(token === undefined ? {} : { _continue: token }),
                  })),
            ) as {
              items?: unknown[];
              metadata?: { continue?: string; resourceVersion?: string };
            };
            for (const item of page.items ?? []) {
              const key = this.resource.keyOf(item);
              if (key !== undefined) keys.push(key);
            }
            resourceVersion = page.metadata?.resourceVersion;
            token = page.metadata?.continue || undefined;
          } while (token !== undefined);
          break;
        } catch (error) {
          // An expired continue token restarts from the first page.
          if (!isGone(error)) throw error;
        }
      }
    } catch (error) {
      this.failed(error, generation, RETRY_RELIST_MS, () => void this.relist());
      return;
    }
    if (!this.active || generation !== this.generation) return;
    this.rv = resourceVersion;
    this.resource.onRelist(keys);
    await this.watchNow();
  }

  private async watchNow(): Promise<void> {
    if (!this.active) return;
    this.abortWatch();
    const generation = this.generation;
    try {
      const controller = await this.watchApi.watch(
        watchPath(this.resource),
        {
          allowWatchBookmarks: true,
          ...(this.rv === undefined ? {} : { resourceVersion: this.rv }),
          timeoutSeconds: 300 + Math.floor(this.scheduler.random() * 300),
        },
        (phase, object) => this.onEvent(phase, object, generation),
        (error) => this.done(error, generation),
      );
      if (generation !== this.generation) controller.abort();
      else this.controller = controller;
    } catch (error) {
      this.done(error, generation);
    }
  }

  private onEvent(phase: string, object: unknown, generation: number): void {
    if (generation !== this.generation || !this.active) return;
    if (phase === "ERROR") {
      if (isGone(object)) void this.relist();
      return;
    }
    const version = (object as ObjectLike | null)?.metadata?.resourceVersion;
    if (typeof version === "string") this.rv = version;
    if (phase === "BOOKMARK") return;
    this.resource.onEvent(phase, object);
  }

  private done(error: unknown, generation: number): void {
    if (generation !== this.generation || !this.active) return;
    this.failed(error, generation, RETRY_WATCH_MS, () => {
      if (this.rv === undefined) void this.relist();
      else void this.watchNow();
    });
  }

  /** Shared reaction to a failed list or a closed watch. */
  private failed(
    error: unknown,
    generation: number,
    delay: number,
    retry: () => void,
  ): void {
    if (!this.active || generation !== this.generation) return;
    if (isGone(error)) {
      this.rv = undefined;
      void this.relist();
      return;
    }
    if (isNotFound(error) || isForbidden(error)) {
      // The next resync re-probes the resource.
      this.active = false;
      return;
    }
    this.timer = this.scheduler.setTimeout(() => {
      this.timer = undefined;
      if (this.active && generation === this.generation) retry();
    }, delay);
  }
}

/**
 * Request-driven PKI controller. It has its own queue, watches, relist and
 * resync, and never touches the consumer reconcile pass.
 */
export class PkiModule {
  public readonly queue: KeyedWorkQueue;
  private readonly scheduler: Scheduler;
  private readonly issuers: IssuerReconciler;
  private readonly requests: CertificateRequestReconciler;
  private readonly pending = new Set<string>();
  private readonly issuerKeys = new Set<string>();
  private readonly features: Feature[];
  private readonly loggedRbac = new Set<string>();
  private resyncTimer: unknown;
  private resyncing: Promise<void> | undefined;
  private unsubscribe: (() => void) | undefined;
  private started = false;
  private stopped = false;

  public constructor(private readonly deps: PkiModuleDeps) {
    this.scheduler = deps.scheduler ?? realScheduler;
    this.queue = new KeyedWorkQueue(
      (key, context) => this.handle(key, context),
      {
        concurrency: deps.config.concurrency,
        groupConcurrency: GROUP_CONCURRENCY,
        scheduler: this.scheduler,
      },
    );
    const shared = {
      core: deps.core,
      custom: deps.custom,
      registry: deps.registry,
      scheduler: this.scheduler,
    };
    this.issuers = new IssuerReconciler(shared, this.queue);
    this.requests = new CertificateRequestReconciler(
      shared,
      this.issuers,
      this.queue,
      this.pending,
    );
    const resources: StreamResource[] = [
      {
        name: CR_PLURAL,
        group: CM_GROUP,
        version: CM_VERSION,
        plural: CR_PLURAL,
        scope: "all",
        onEvent: (phase, object) => this.onRequestEvent(phase, object),
        keyOf: (item) => this.relistRequestKey(item),
        onRelist: (keys) => this.onRequestRelist(keys),
      },
      {
        name: ISSUER_PLURAL,
        group: HEMLIG_GROUP,
        version: ISSUER_VERSION,
        plural: ISSUER_PLURAL,
        scope: "all",
        onEvent: (phase, object) => this.onIssuerEvent(phase, object, false),
        keyOf: (item) => this.issuerKeyOf(item, false),
        onRelist: (keys) => this.onIssuerRelist(keys, false),
      },
      {
        name: CLUSTER_ISSUER_PLURAL,
        group: HEMLIG_GROUP,
        version: ISSUER_VERSION,
        plural: CLUSTER_ISSUER_PLURAL,
        scope: "cluster",
        onEvent: (phase, object) => this.onIssuerEvent(phase, object, true),
        keyOf: (item) => this.issuerKeyOf(item, true),
        onRelist: (keys) => this.onIssuerRelist(keys, true),
      },
    ];
    // Phase 6 appends a trust-bundle feature; each feature is enabled on its own.
    this.features = [
      {
        name: "cert-manager issuer",
        resources,
        enabled: false,
        streams: new Map(),
        clear: () => {
          this.queue.forgetWhere(
            (key) =>
              key.startsWith("cr/") ||
              key.startsWith("issuer/") ||
              key.startsWith("clusterissuer/"),
          );
          this.pending.clear();
          this.issuerKeys.clear();
          this.issuers.reset();
        },
      },
    ];
  }

  public get enabled(): boolean {
    return this.features.some((feature) => feature.enabled);
  }

  /** Idempotent. Fire-and-forget; errors are handled here. */
  public start(signal: AbortSignal): void {
    if (this.started || this.stopped) return;
    this.started = true;
    this.unsubscribe = this.deps.registry.onChange(() => {
      for (const key of this.issuerKeys) {
        this.queue.add(key, { resetBackoff: true });
      }
    });
    if (signal.aborted) {
      this.stop();
      return;
    }
    signal.addEventListener("abort", () => this.stop(), { once: true });
    void this.resyncLoop();
  }

  public stop(): void {
    if (this.stopped) return;
    this.stopped = true;
    if (this.resyncTimer !== undefined) {
      this.scheduler.clearTimeout(this.resyncTimer);
    }
    this.resyncTimer = undefined;
    this.unsubscribe?.();
    for (const feature of this.features) {
      for (const stream of feature.streams.values()) stream.stop();
    }
    this.queue.stop();
  }

  private async resyncLoop(): Promise<void> {
    await this.resyncNow();
    if (this.stopped) return;
    this.resyncTimer = this.scheduler.setTimeout(
      () => void this.resyncLoop(),
      RESYNC_MS * (0.9 + 0.2 * this.scheduler.random()),
    );
  }

  /** Test hook. Overlapping calls share one run. */
  public resyncNow(): Promise<void> {
    this.resyncing ??= this.resync()
      .catch(() => {
        log("resync failed");
      })
      .finally(() => {
        this.resyncing = undefined;
      });
    return this.resyncing;
  }

  private async probe(
    resource: StreamResource,
  ): Promise<"present" | "absent" | "unknown"> {
    try {
      const input = {
        group: resource.group,
        version: resource.version,
        plural: resource.plural,
        limit: 1,
      };
      await (resource.scope === "cluster"
        ? this.deps.custom.listClusterCustomObject(input)
        : this.deps.custom.listCustomObjectForAllNamespaces(input));
      return "present";
    } catch (error) {
      if (isForbidden(error)) {
        if (!this.loggedRbac.has(resource.name)) {
          this.loggedRbac.add(resource.name);
          log(`RBAC missing for ${resource.name}`);
        }
        return "absent";
      }
      if (isNotFound(error)) return "absent";
      return "unknown";
    }
  }

  private async resync(): Promise<void> {
    for (const feature of this.features) {
      const probes = await Promise.all(
        feature.resources.map(async (resource) => ({
          resource,
          state: await this.probe(resource),
        })),
      );
      if (this.stopped) return;
      const missing = probes.find((entry) => entry.state === "absent");
      if (missing !== undefined) {
        if (feature.enabled) {
          feature.enabled = false;
          for (const stream of feature.streams.values()) stream.stop();
          feature.streams.clear();
          feature.clear();
          log(`${feature.name} disabled (${missing.resource.name} not found)`);
        }
        continue;
      }
      if (probes.some((entry) => entry.state === "unknown")) continue;
      if (!feature.enabled) {
        feature.enabled = true;
        log(`${feature.name} enabled`);
        await Promise.all(
          feature.resources.map((resource) => {
            const stream = new Stream(
              resource,
              this.deps.custom,
              this.deps.watch,
              this.scheduler,
            );
            feature.streams.set(resource, stream);
            return stream.start();
          }),
        );
        continue;
      }
      const restarts: Promise<void>[] = [];
      for (const stream of feature.streams.values()) {
        if (!stream.running) restarts.push(stream.start());
      }
      await Promise.all(restarts);
      // Resync uses the in-memory pending set: CR objects carry the CSR and
      // certificate, so relisting them every five minutes is too heavy.
      for (const key of this.issuerKeys) this.queue.add(key);
      for (const key of this.pending) this.queue.add(key);
    }
  }

  private handle(key: string, context: WorkContext): Promise<Outcome> {
    if (!this.enabled) return Promise.resolve({ kind: "done" });
    if (key.startsWith("cr/")) return this.requests.reconcile(key, context);
    if (key.startsWith("issuer/") || key.startsWith("clusterissuer/")) {
      return this.issuers.reconcile(key, context);
    }
    return Promise.resolve({ kind: "done" });
  }

  // -- CertificateRequest events ---------------------------------------------

  private requestKeyOf(object: unknown): string | undefined {
    const metadata = (object as ObjectLike | null)?.metadata;
    return metadata?.namespace === undefined || metadata.name === undefined
      ? undefined
      : requestKey(metadata.namespace, metadata.name);
  }

  private onRequestEvent(phase: string, object: unknown): void {
    const key = this.requestKeyOf(object);
    if (key === undefined) return;
    if (phase === "DELETED") {
      this.pending.delete(key);
      this.queue.forget(key);
      this.issuers.stopWaiting(key);
      return;
    }
    const cr = object as CertificateRequest;
    if (isHemligRequest(cr) && !isTerminal(cr)) {
      this.pending.add(key);
      this.queue.add(key);
    } else {
      this.pending.delete(key);
    }
  }

  /** Only Hemlig, non-terminal requests are kept from a relist. */
  private relistRequestKey(item: unknown): string | undefined {
    const key = this.requestKeyOf(item);
    const cr = item as CertificateRequest;
    return key !== undefined && isHemligRequest(cr) && !isTerminal(cr)
      ? key
      : undefined;
  }

  private onRequestRelist(keys: readonly string[]): void {
    const next = new Set(keys);
    for (const key of this.pending) {
      if (!next.has(key)) {
        this.queue.forget(key);
        this.issuers.stopWaiting(key);
      }
    }
    this.pending.clear();
    for (const key of next) this.pending.add(key);
    for (const key of next) this.queue.add(key);
  }

  // -- Issuer events ---------------------------------------------------------

  private issuerKeyOf(object: unknown, cluster: boolean): string | undefined {
    const metadata = (object as ObjectLike | null)?.metadata;
    if (metadata?.name === undefined) return undefined;
    if (cluster) return clusterIssuerKey(metadata.name);
    return metadata.namespace === undefined
      ? undefined
      : issuerKey(metadata.namespace, metadata.name);
  }

  private onIssuerEvent(
    phase: string,
    object: unknown,
    cluster: boolean,
  ): void {
    const key = this.issuerKeyOf(object, cluster);
    if (key === undefined) return;
    if (phase === "DELETED") {
      this.issuerKeys.delete(key);
      this.queue.forget(key);
      this.issuers.onGone(key);
      return;
    }
    const issuer = object as ObjectLike;
    // Our own status write: nothing to do.
    if (
      phase === "MODIFIED" &&
      issuer.metadata?.generation !== undefined &&
      issuer.status?.observedGeneration === issuer.metadata.generation
    ) {
      this.issuerKeys.add(key);
      return;
    }
    this.issuerKeys.add(key);
    // A real change outranks a pending backoff.
    this.queue.add(key, { resetBackoff: true });
  }

  private onIssuerRelist(keys: readonly string[], cluster: boolean): void {
    const prefix = cluster ? "clusterissuer/" : "issuer/";
    const next = new Set(keys);
    for (const key of [...this.issuerKeys]) {
      if (key.startsWith(prefix) && !next.has(key)) {
        this.issuerKeys.delete(key);
        this.queue.forget(key);
        this.issuers.onGone(key);
      }
    }
    for (const key of next) {
      this.issuerKeys.add(key);
      this.queue.add(key);
    }
  }
}
