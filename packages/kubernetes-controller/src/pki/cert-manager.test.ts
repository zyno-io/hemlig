import assert from "node:assert/strict";
import test from "node:test";
import { HemligError } from "@zyno-io/hemlig-client";
import {
  buildIssueRequest,
  classifyIssueError,
  decodeCsr,
  isHemligRequest,
  isTerminal,
  issuedStatusFields,
  k8sTime,
  mapUsages,
  parseDurationSeconds,
  readyUnchanged,
  requesterFor,
  safeText,
  withReady,
} from "./cert-manager";
import type { CertificateRequest } from "./types";

const csrPem =
  "-----BEGIN CERTIFICATE REQUEST-----\nQUJD\n-----END CERTIFICATE REQUEST-----\n";
const csrB64 = Buffer.from(csrPem).toString("base64");
const baseCr = (
  spec: Record<string, unknown> = {},
  metadata: Record<string, unknown> = {},
): CertificateRequest => ({
  metadata: {
    name: "cr-1",
    namespace: "ns",
    uid: "11111111-2222-3333-4444-555555555555",
    ...metadata,
  },
  spec: {
    request: csrB64,
    issuerRef: { group: "hemlig.zyno.io", kind: "HemligIssuer", name: "i" },
    ...spec,
  },
});

test("usage mapping covers the table, dedupes, sorts and omits empty", () => {
  assert.deepEqual(mapUsages(["digital signature"]), {
    ok: true,
    usages: ["digitalSignature"],
  });
  assert.deepEqual(mapUsages(["signing", "digital signature"]), {
    ok: true,
    usages: ["digitalSignature"],
  });
  assert.deepEqual(
    mapUsages(["server auth", "client auth", "key encipherment"]),
    { ok: true, usages: ["clientAuth", "keyEncipherment", "serverAuth"] },
  );
  assert.deepEqual(mapUsages([]), { ok: true });
  assert.deepEqual(mapUsages(undefined), { ok: true });
  for (const bad of ["code signing", "cert sign", "any", "wat"]) {
    assert.deepEqual(mapUsages(["server auth", bad]), {
      ok: false,
      usage: bad,
    });
  }
});

test("durations follow the Go grammar and floor to seconds", () => {
  const seconds = (value: string) => {
    const result = parseDurationSeconds(value);
    return result.ok ? result.seconds : "invalid";
  };
  assert.equal(seconds("2160h0m0s"), 7_776_000);
  assert.equal(seconds("1h30m"), 5_400);
  assert.equal(seconds("1.5h"), 5_400);
  assert.equal(seconds("1m30.5s"), 90);
  assert.equal(seconds("90s"), 90);
  for (const bad of ["", "abc", "-1h", "0s", "500ms", "1d"]) {
    assert.equal(seconds(bad), "invalid", bad);
  }
  assert.deepEqual(parseDurationSeconds(undefined), { ok: true });
});

test("decodeCsr accepts PEM and rejects everything else without echoing it", () => {
  assert.equal(decodeCsr(csrB64), csrPem);
  const secret = Buffer.from("secret-not-pem").toString("base64");
  assert.equal(decodeCsr(secret), undefined);
  assert.equal(decodeCsr("%%%"), undefined);
  assert.equal(decodeCsr(undefined), undefined);
  const result = buildIssueRequest(baseCr({ request: secret }));
  assert.equal(result.ok, false);
  assert.ok(!JSON.stringify(result).includes("secret-not-pem"));
  assert.ok(!JSON.stringify(result).includes(secret));
});

test("requesterFor drops bad optional fields and keeps the uid", () => {
  const cr = baseCr(
    {},
    {
      annotations: {
        "cert-manager.io/certificate-name": "Bad Name",
        "cert-manager.io/certificate-revision": "x1",
      },
    },
  );
  assert.deepEqual(requesterFor(cr), {
    kubernetes: {
      namespace: "ns",
      name: "cr-1",
      uid: "11111111-2222-3333-4444-555555555555",
    },
  });
  const good = baseCr(
    {},
    {
      annotations: {
        "cert-manager.io/certificate-name": "web",
        "cert-manager.io/certificate-revision": "3",
      },
    },
  );
  assert.deepEqual(requesterFor(good)?.kubernetes, {
    namespace: "ns",
    name: "cr-1",
    uid: "11111111-2222-3333-4444-555555555555",
    certificateName: "web",
    revision: "3",
  });
  assert.equal(requesterFor(baseCr({}, { uid: "not a uid!" })), undefined);
});

test("buildIssueRequest sends exactly the five fields and checks in order", () => {
  const ok = buildIssueRequest(
    baseCr({
      duration: "1h",
      usages: ["server auth"],
      username: "system:admin",
      groups: ["g"],
    }),
  );
  assert.ok(ok.ok);
  assert.deepEqual(Object.keys(ok.body).sort(), [
    "certificateSigningRequestPem",
    "durationSeconds",
    "isCA",
    "requester",
    "usages",
  ]);
  assert.equal(ok.body.isCA, false);
  assert.equal(ok.body.durationSeconds, 3600);
  const order = buildIssueRequest(
    baseCr({ isCA: true, usages: ["any"], duration: "x", request: "" }),
  );
  assert.deepEqual(order, {
    ok: false,
    message: "UnsupportedRequest: CA certificates are not issued by Hemlig",
  });
  const usage = buildIssueRequest(
    baseCr({ usages: ["code signing"], duration: "x", request: "" }),
  );
  assert.equal(
    !usage.ok && usage.message,
    'UnsupportedRequest: usage "code signing" is not supported',
  );
  const duration = buildIssueRequest(baseCr({ duration: "x", request: "" }));
  assert.equal(
    !duration.ok && duration.message,
    "UnsupportedRequest: spec.duration is invalid",
  );
  const csr = buildIssueRequest(baseCr({ request: "" }));
  assert.equal(
    !csr.ok && csr.message,
    "UnsupportedRequest: spec.request is not a PEM certificate request",
  );
});

test("issuedStatusFields concatenates leaf and chain exactly", () => {
  const leaf = "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n";
  const chain = "-----BEGIN CERTIFICATE-----\nBBB\n-----END CERTIFICATE-----\n";
  const root = "-----BEGIN CERTIFICATE-----\nCCC\n-----END CERTIFICATE-----\n";
  assert.deepEqual(
    issuedStatusFields({ certificatePem: leaf, chainPem: chain, caPem: root }),
    {
      certificate: Buffer.from(leaf + chain, "utf8").toString("base64"),
      ca: Buffer.from(root, "utf8").toString("base64"),
    },
  );
  assert.equal(
    issuedStatusFields({ certificatePem: "x", chainPem: chain, caPem: root }),
    undefined,
  );
  assert.equal(
    issuedStatusFields({
      certificatePem: leaf.trimEnd(),
      chainPem: chain,
      caPem: root,
    }),
    undefined,
  );
  assert.equal(
    issuedStatusFields({ certificatePem: leaf, chainPem: 1, caPem: root }),
    undefined,
  );
});

test("isHemligRequest gates on group and kind", () => {
  const ref = (issuerRef: Record<string, string>) =>
    isHemligRequest({ metadata: {}, spec: { issuerRef } });
  assert.equal(ref({ group: "hemlig.zyno.io", kind: "HemligIssuer" }), true);
  assert.equal(
    ref({ group: "hemlig.zyno.io", kind: "HemligClusterIssuer" }),
    true,
  );
  assert.equal(ref({ group: "hemlig.zyno.io", kind: "" }), false);
  assert.equal(ref({ group: "", kind: "HemligIssuer" }), false);
  assert.equal(ref({ group: "cert-manager.io", kind: "Issuer" }), false);
  assert.equal(ref({ group: "hemlig.zyno.io", kind: "Issuer" }), false);
});

test("isTerminal truth table", () => {
  const status = (conditions: object[], certificate?: string) => ({
    status: {
      conditions: conditions as never,
      ...(certificate ? { certificate } : {}),
    },
  });
  assert.equal(isTerminal({}), false);
  assert.equal(
    isTerminal(status([{ type: "Ready", status: "True", reason: "Issued" }])),
    true,
  );
  assert.equal(
    isTerminal(status([{ type: "Ready", status: "False", reason: "Failed" }])),
    true,
  );
  assert.equal(
    isTerminal(status([{ type: "Ready", status: "False", reason: "Denied" }])),
    true,
  );
  assert.equal(
    isTerminal(status([{ type: "Ready", status: "False", reason: "Pending" }])),
    false,
  );
  assert.equal(
    isTerminal(status([{ type: "Approved", status: "True" }])),
    false,
  );
  assert.equal(isTerminal(status([], "Zm9v")), true);
  assert.equal(isTerminal({ status: { certificate: "" } }), false);
});

test("withReady keeps foreign conditions by reference and order", () => {
  const approved = { type: "Approved", status: "True", reason: "x" };
  const foreign = { type: "Other", status: "True" };
  const old = {
    type: "Ready",
    status: "False",
    reason: "Pending",
    message: "a",
    lastTransitionTime: "2026-01-01T00:00:00Z",
  };
  const status = { conditions: [approved, old, foreign], extra: 1 };
  const next = withReady(
    status,
    { status: "False", reason: "Pending", message: "b" },
    Date.parse("2026-02-02T00:00:00.123Z"),
  );
  assert.equal(next.conditions?.[0], approved);
  assert.equal(next.conditions?.[2], foreign);
  assert.equal(next.conditions?.[1]?.type, "Ready");
  assert.equal(
    next.conditions?.[1]?.lastTransitionTime,
    "2026-01-01T00:00:00Z",
  );
  assert.equal(next.extra, 1);
  const flipped = withReady(
    status,
    { status: "True", reason: "Issued", message: "ok" },
    Date.parse("2026-02-02T00:00:00.123Z"),
    { certificate: "c", ca: "d" },
  );
  assert.equal(
    flipped.conditions?.[1]?.lastTransitionTime,
    "2026-02-02T00:00:00Z",
  );
  assert.equal(flipped.certificate, "c");
  const appended = withReady(
    { conditions: [approved] },
    { status: "False", reason: "Pending", message: "w" },
    0,
  );
  assert.equal(appended.conditions?.length, 2);
  assert.equal(appended.conditions?.[0], approved);
  assert.ok(
    readyUnchanged(
      next,
      withReady(next, { status: "False", reason: "Pending", message: "b" }, 5),
    ),
  );
  assert.ok(!readyUnchanged(status, next));
});

test("k8sTime has second precision", () => {
  assert.equal(
    k8sTime(Date.parse("2026-02-02T03:04:05.678Z")),
    "2026-02-02T03:04:05Z",
  );
});

test("safeText drops PEM-like and non-printable text", () => {
  assert.equal(safeText("api.example.com"), "api.example.com");
  assert.equal(safeText("-----BEGIN"), undefined);
  assert.equal(safeText("a\nb"), undefined);
  assert.equal(safeText("a\u0000b"), undefined);
  assert.equal(safeText(""), undefined);
});

const err = (
  status: number,
  code?: string,
  details?: Record<string, string | number | boolean>,
  retryAfter?: number,
) => new HemligError(status, "SECRET message", code, details, retryAfter);

test("classifyIssueError covers every row", () => {
  assert.deepEqual(classifyIssueError(new Error("boom")), {
    kind: "fast",
    message: "HemligUnavailable: network error",
  });
  assert.deepEqual(
    classifyIssueError(err(400, "bad_request", { reason: "invalid_usages" })),
    { kind: "failed", message: "bad_request (invalid_usages)" },
  );
  assert.deepEqual(
    classifyIssueError(err(400, "invalid_csr", { reason: "bad_signature" })),
    { kind: "failed", message: "invalid_csr (bad_signature)" },
  );
  assert.deepEqual(
    classifyIssueError(
      err(403, "issuance_denied", {
        reason: "name_not_permitted",
        deniedNameType: "dns",
        deniedName: "evil.example.com",
      }),
    ),
    {
      kind: "failed",
      message: "issuance_denied (name_not_permitted): dns evil.example.com",
    },
  );
  assert.equal(
    classifyIssueError(
      err(403, "issuance_denied", {
        reason: "name_not_permitted",
        deniedNameType: "dns",
        deniedName: "-----BEGIN x",
      }),
    ).message,
    "issuance_denied (name_not_permitted)",
  );
  assert.equal(
    classifyIssueError(
      err(403, "issuance_denied", {
        reason: "name_not_permitted",
        deniedNameType: "dns",
        deniedName: "a\u0007b",
      }),
    ).message,
    "issuance_denied (name_not_permitted)",
  );
  for (const code of ["issuance_revoked", "issuance_expired", "conflict"]) {
    assert.equal(
      classifyIssueError(err(409, code, { reason: "r" })).kind,
      "failed",
    );
  }
  assert.deepEqual(
    classifyIssueError(err(404, "issuance_grant_not_found", { reason: "r" })),
    {
      kind: "slow",
      message: "issuance_grant_not_found (r)",
      refreshIssuer: true,
    },
  );
  assert.equal(
    (
      classifyIssueError(err(403, "issuance_grant_inactive")) as {
        refreshIssuer: boolean;
      }
    ).refreshIssuer,
    true,
  );
  assert.equal(
    (
      classifyIssueError(err(409, "ca_not_active", { reason: "retired" })) as {
        refreshIssuer: boolean;
      }
    ).refreshIssuer,
    true,
  );
  for (const code of ["ca_capacity_exceeded", "ca_key_unavailable"]) {
    const result = classifyIssueError(err(409, code));
    assert.equal(result.kind, "slow");
    assert.equal((result as { refreshIssuer: boolean }).refreshIssuer, false);
  }
  const identity = "identity_not_active: Hemlig rejected the consumer identity";
  assert.equal(
    classifyIssueError(err(403, "identity_not_active")).message,
    identity,
  );
  assert.equal(classifyIssueError(err(403)).message, identity);
  assert.deepEqual(
    classifyIssueError(
      err(429, "issuance_rate_limited", { reason: "grant_hour" }, 120),
    ),
    {
      kind: "retryAfter",
      delayMs: 120_000,
      message: "issuance_rate_limited (grant_hour)",
    },
  );
  assert.equal(
    (
      classifyIssueError(
        err(429, "issuance_rate_limited", {
          reason: "x",
          retryAfterSeconds: 7,
        }),
      ) as { delayMs: number }
    ).delayMs,
    7_000,
  );
  assert.equal(
    (
      classifyIssueError(err(429, "issuance_rate_limited", {}, 999_999)) as {
        delayMs: number;
      }
    ).delayMs,
    86_400_000,
  );
  assert.deepEqual(classifyIssueError(err(429)), {
    kind: "fast",
    message: "HemligUnavailable (429)",
  });
  assert.deepEqual(classifyIssueError(err(429, "issuance_rate_limited")), {
    kind: "fast",
    message: "HemligUnavailable (429)",
  });
  assert.deepEqual(classifyIssueError(err(503, undefined, undefined, 5)), {
    kind: "fast",
    message: "HemligUnavailable (503)",
    minDelayMs: 5_000,
  });
  assert.deepEqual(classifyIssueError(err(404, "not_found")), {
    kind: "slow",
    message: "HemligError (404 not_found)",
    refreshIssuer: false,
  });
  assert.equal(classifyIssueError(err(403, "forbidden")).kind, "slow");
  assert.equal(classifyIssueError(err(418, "teapot")).kind, "slow");
});

test("classification never leaks the HemligError message", () => {
  for (const status of [400, 403, 404, 409, 429, 500]) {
    assert.ok(!classifyIssueError(err(status, "x")).message.includes("SECRET"));
  }
});
