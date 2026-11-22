import { stableJson } from "../util/encoding";
import {
  GRANT_POLICY_MAX_BYTES,
  type GrantCaContext,
  compileGrantPolicy,
  policyDigest,
  validateGrantPolicy,
} from "./grant-policy";

const DAY = 86400;

const validPolicy = (): Record<string, any> => ({
  names: {
    dns: {
      allow: [
        "**.payments.svc.cluster.local",
        "api.payments.example.com",
        "*.payments.example.com",
      ],
      deny: ["internal.payments.example.com"],
      allowWildcardNames: false,
    },
    ip: { allow: ["10.20.0.0/16"] },
    uri: { allow: ["spiffe://prod.example.com/ns/payments/**"] },
    commonName: { mode: "san", addToSans: true },
    maxSans: 50,
  },
  subject: { allow: { organizationalUnit: ["payments-*"] } },
  keyAlgorithms: ["ECDSA_P256", "ECDSA_P384", "RSA_2048", "RSA_3072"],
  keyUsages: ["digitalSignature", "keyEncipherment"],
  extendedKeyUsages: {
    allow: ["serverAuth", "clientAuth"],
    default: ["serverAuth", "clientAuth"],
  },
  lifetime: { defaultSeconds: 7776000, maxSeconds: 7776000, minSeconds: 3600 },
  forced: {
    subject: { organization: "Example Corp", country: "US" },
    sans: { uri: ["spiffe://prod.example.com/cluster/prod-a"] },
    certificatePolicies: ["1.3.6.1.4.1.55555.1.1"],
  },
  quotas: { perHour: 100, perDay: 1000 },
});

const ca = (overrides: Partial<GrantCaContext> = {}): GrantCaContext => ({
  leafKeyAlgorithms: [
    "ECDSA_P256",
    "ECDSA_P384",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
  ],
  maxLeafLifetimeSeconds: 397 * DAY,
  ...overrides,
});

const codes = (issues: { code: string }[]) => issues.map((i) => i.code);

describe("validateGrantPolicy", () => {
  it("accepts the plan example", () => {
    const result = validateGrantPolicy(validPolicy(), { ca: ca() });
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.compiled?.dns.allow).toHaveLength(3);
    expect(result.compiled?.forcedSans.uri).toEqual([
      "spiffe://prod.example.com/cluster/prod-a",
    ]);
  });

  it("rejects non-objects, unknown fields and missing required fields", () => {
    expect(validateGrantPolicy("nope").ok).toBe(false);
    expect(validateGrantPolicy([]).ok).toBe(false);
    expect(
      codes(validateGrantPolicy({ ...validPolicy(), surprise: 1 }).errors),
    ).toContain("unknown_field");
    for (const field of [
      "names",
      "keyUsages",
      "extendedKeyUsages",
      "lifetime",
    ]) {
      const policy = validPolicy();
      delete policy[field];
      expect(codes(validateGrantPolicy(policy).errors)).toContain(
        "missing_field",
      );
    }
  });

  it("rejects wrongly typed and unsupported values", () => {
    const mutate = (change: (p: Record<string, any>) => void) => {
      const policy = validPolicy();
      change(policy);
      return validateGrantPolicy(policy).errors;
    };
    expect(codes(mutate((p) => (p.names.dns.allow = "x")))).toContain(
      "invalid_type",
    );
    expect(codes(mutate((p) => (p.names.maxSans = 0)))).toContain(
      "invalid_value",
    );
    expect(codes(mutate((p) => (p.names.maxSans = 101)))).toContain(
      "invalid_value",
    );
    expect(codes(mutate((p) => (p.names.commonName.mode = "other")))).toContain(
      "invalid_value",
    );
    expect(codes(mutate((p) => (p.keyUsages = ["keyCertSign"])))).toContain(
      "unsupported_value",
    );
    expect(
      codes(mutate((p) => (p.extendedKeyUsages.allow = ["codeSigning"]))),
    ).toContain("unsupported_value");
    expect(codes(mutate((p) => (p.keyAlgorithms = ["RSA_1024"])))).toContain(
      "unsupported_value",
    );
    expect(codes(mutate((p) => (p.lifetime.maxSeconds = 1.5)))).toContain(
      "invalid_value",
    );
    expect(
      codes(mutate((p) => (p.subject.allow.commonName = ["*"]))),
    ).toContain("unknown_field");
    expect(codes(mutate((p) => (p.quotas.perHour = 0)))).toContain(
      "invalid_value",
    );
  });
});

describe("rule parsing and reserved names", () => {
  const errorsFor = (
    change: (p: Record<string, any>) => void,
    context = {},
  ) => {
    const policy = validPolicy();
    change(policy);
    return validateGrantPolicy(policy, context).errors;
  };

  it("reports every unparsable rule with its path", () => {
    const errors = errorsFor((p) => {
      p.names.dns.allow = ["**.com", "ok.example.com", "bad_name.example.com"];
      p.names.dns.deny = ["*"];
      p.names.ip.allow = ["10.0.0.1/8", "nope"];
      p.names.uri.allow = ["spiffe://x/**/a", "no-scheme"];
    });
    expect(
      errors.filter((e) => e.code === "invalid_rule").map((e) => e.path),
    ).toEqual([
      "policy.names.dns.allow[0]",
      "policy.names.dns.allow[2]",
      "policy.names.dns.deny[0]",
      "policy.names.ip.allow[0]",
      "policy.names.ip.allow[1]",
      "policy.names.uri.allow[0]",
      "policy.names.uri.allow[1]",
    ]);
  });

  it("rejects rules that name spiffe://hemlig/", () => {
    expect(
      codes(errorsFor((p) => (p.names.uri.allow = ["spiffe://hemlig/**"]))),
    ).toContain("reserved_name");
    expect(
      codes(errorsFor((p) => (p.names.uri.deny = ["SPIFFE://hemlig/x"]))),
    ).toContain("reserved_name");
    expect(
      codes(
        errorsFor(
          (p) => (p.names.uri.allow = ["spiffe://hemlig.example.com/**"]),
        ),
      ),
    ).not.toContain("reserved_name");
  });

  it("rejects forced SANs that are invalid or reserved", () => {
    expect(
      codes(errorsFor((p) => (p.forced.sans = { dns: ["bad_name"] }))),
    ).toContain("invalid_forced_san");
    expect(
      codes(errorsFor((p) => (p.forced.sans = { dns: ["*.example.com"] }))),
    ).toContain("invalid_forced_san");
    expect(
      codes(errorsFor((p) => (p.forced.sans = { ip: ["300.1.1.1"] }))),
    ).toContain("invalid_forced_san");
    expect(
      codes(errorsFor((p) => (p.forced.sans = { uri: ["spiffe://hemlig/x"] }))),
    ).toContain("reserved_name");
  });

  it("rejects invalid forced subject values and policy OIDs", () => {
    expect(
      codes(errorsFor((p) => (p.forced.subject = { country: "usa" }))),
    ).toContain("invalid_value");
    expect(
      codes(
        errorsFor((p) => (p.forced.subject = { organization: " padded " })),
      ),
    ).toContain("invalid_value");
    expect(
      codes(errorsFor((p) => (p.forced.certificatePolicies = ["not.an.oid"]))),
    ).toContain("invalid_oid");
    expect(
      codes(errorsFor((p) => (p.forced.certificatePolicies = ["3.1.2"]))),
    ).toContain("invalid_oid");
  });
});

describe("limits", () => {
  it("allows 200 name rules and rejects 201", () => {
    const rules = (n: number) =>
      Array.from({ length: n }, (_, i) => `h${i}.example.com`);
    const policy = validPolicy();
    policy.names.dns = { allow: rules(200) };
    policy.names.ip = undefined;
    policy.names.uri = undefined;
    delete policy.names.ip;
    delete policy.names.uri;
    expect(validateGrantPolicy(policy).ok).toBe(true);
    policy.names.dns = { allow: rules(200), deny: ["x.example.com"] };
    expect(codes(validateGrantPolicy(policy).errors)).toContain(
      "too_many_rules",
    );
  });

  it("allows 10 forced SANs and 10 policy OIDs, and rejects 11", () => {
    const policy = validPolicy();
    policy.forced = {
      sans: { dns: Array.from({ length: 10 }, (_, i) => `f${i}.example.com`) },
      certificatePolicies: Array.from({ length: 10 }, (_, i) => `1.2.3.${i}`),
    };
    expect(validateGrantPolicy(policy).ok).toBe(true);
    policy.forced.sans.dns.push("f10.example.com");
    policy.forced.certificatePolicies.push("1.2.3.10");
    const found = codes(validateGrantPolicy(policy).errors);
    expect(found).toContain("too_many_forced_sans");
    expect(found).toContain("too_many_policy_oids");
  });

  it("counts forced SANs against maxSans", () => {
    const policy = validPolicy();
    policy.names.maxSans = 2;
    policy.forced.sans = {
      dns: ["a.example.com", "b.example.com", "c.example.com"],
    };
    expect(codes(validateGrantPolicy(policy).errors)).toContain(
      "forced_sans_exceed_max_sans",
    );
    policy.forced.sans = { dns: ["a.example.com", "A.example.com."] }; // duplicates collapse
    expect(validateGrantPolicy(policy).ok).toBe(true);
  });

  it("measures the canonical JSON against 32 KiB first", () => {
    const policy = validPolicy();
    policy.subject.allow.organization = ["x".repeat(30 * 1024)];
    expect(stableJson(policy).length).toBeLessThan(GRANT_POLICY_MAX_BYTES);
    expect(codes(validateGrantPolicy(policy).errors)).not.toContain(
      "policy_too_large",
    );
    policy.subject.allow.organizationalUnit = ["y".repeat(3 * 1024)];
    const result = validateGrantPolicy(policy);
    expect(result.ok).toBe(false);
    expect(codes(result.errors)).toEqual(["policy_too_large"]);
  });

  it("counts bytes, not characters", () => {
    const policy = validPolicy();
    policy.displayNote = "é".repeat(17 * 1024); // 34 KiB as UTF-8, 17 K characters
    expect(codes(validateGrantPolicy(policy).errors)).toEqual([
      "policy_too_large",
    ]);
  });

  it("rejects a policy that is not serializable", () => {
    const policy = validPolicy();
    policy.self = policy;
    expect(validateGrantPolicy(policy).ok).toBe(false);
  });
});

describe("lifetime, algorithms and EKUs against the CA", () => {
  const errorsFor = (
    change: (p: Record<string, any>) => void,
    context: GrantCaContext = ca(),
  ) => {
    const policy = validPolicy();
    change(policy);
    return validateGrantPolicy(policy, { ca: context }).errors;
  };

  it("enforces 300 <= min <= default <= max <= CA max <= 397 days", () => {
    expect(codes(errorsFor((p) => (p.lifetime.minSeconds = 299)))).toContain(
      "lifetime_invalid",
    );
    expect(
      codes(
        errorsFor(
          (p) =>
            (p.lifetime = {
              defaultSeconds: 1000,
              maxSeconds: 5000,
              minSeconds: 2000,
            }),
        ),
      ),
    ).toContain("lifetime_invalid");
    expect(
      codes(
        errorsFor(
          (p) => (p.lifetime = { defaultSeconds: 5000, maxSeconds: 4000 }),
        ),
      ),
    ).toContain("lifetime_invalid");
    expect(
      codes(
        errorsFor(
          (p) =>
            (p.lifetime = { defaultSeconds: 398 * DAY, maxSeconds: 398 * DAY }),
        ),
      ),
    ).toContain("lifetime_invalid");
    expect(
      codes(
        errorsFor(
          (p) =>
            (p.lifetime = { defaultSeconds: 7776000, maxSeconds: 7776000 }),
          ca({ maxLeafLifetimeSeconds: 30 * DAY }),
        ),
      ),
    ).toContain("lifetime_exceeds_ca_policy");
    expect(
      errorsFor(
        (p) =>
          (p.lifetime = {
            defaultSeconds: 300,
            maxSeconds: 397 * DAY,
            minSeconds: 300,
          }),
      ),
    ).toEqual([]);
  });

  it("defaults minSeconds to 1 hour for the ordering check", () => {
    expect(
      codes(
        errorsFor(
          (p) => (p.lifetime = { defaultSeconds: 600, maxSeconds: 900 }),
        ),
      ),
    ).toContain("lifetime_invalid");
  });

  it("requires key algorithms to be a subset of the CA leaf policy", () => {
    expect(
      codes(errorsFor((p) => (p.keyAlgorithms = ["ECDSA_P521"]))),
    ).toContain("key_algorithm_not_in_ca_policy");
    expect(codes(errorsFor((p) => (p.keyAlgorithms = ["ED25519"])))).toContain(
      "key_algorithm_not_in_ca_policy",
    );
    expect(
      errorsFor(
        (p) => (p.keyAlgorithms = ["ED25519"]),
        ca({ leafKeyAlgorithms: ["ED25519"] }),
      ),
    ).toEqual([]);
  });

  it("requires a non-empty EKU default inside allow, and allow inside any CA EKU constraint", () => {
    expect(
      codes(errorsFor((p) => (p.extendedKeyUsages.default = []))),
    ).toContain("eku_default_required");
    expect(
      codes(
        errorsFor(
          (p) =>
            (p.extendedKeyUsages = {
              allow: ["serverAuth"],
              default: ["clientAuth"],
            }),
        ),
      ),
    ).toContain("eku_default_not_allowed");
    expect(
      codes(
        errorsFor(() => undefined, ca({ extendedKeyUsages: ["serverAuth"] })),
      ),
    ).toContain("eku_outside_ca_constraints");
    expect(
      errorsFor(
        () => undefined,
        ca({ extendedKeyUsages: ["serverAuth", "clientAuth"] }),
      ),
    ).toEqual([]);
    expect(
      errorsFor(
        () => undefined,
        ca({ extendedKeyUsages: ["anyExtendedKeyUsage"] }),
      ),
    ).toEqual([]);
  });
});

describe("overlap with CA NameConstraints", () => {
  const nameConstraints = {
    permitted: {
      dns: ["example.com", "svc.cluster.local"],
      ip: ["10.0.0.0/8"],
      uri: ["prod.example.com"],
    },
  };

  const validate = (change: (p: Record<string, any>) => void) => {
    const policy = validPolicy();
    change(policy);
    return validateGrantPolicy(policy, { ca: ca({ nameConstraints }) });
  };

  it("accepts the plan example, whose rules sit inside the constraints", () => {
    const result = validate(() => undefined);
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("errors on an allow rule entirely outside", () => {
    const result = validate((p) => {
      p.names.dns.allow = ["api.other.org"];
      p.names.ip.allow = ["192.168.0.0/16"];
      p.names.uri.allow = ["spiffe://other.org/**"];
      p.forced.sans = {};
    });
    expect(
      result.errors
        .filter((e) => e.code === "rule_outside_ca_constraints")
        .map((e) => e.path),
    ).toEqual([
      "policy.names.dns.allow[0]",
      "policy.names.ip.allow[0]",
      "policy.names.uri.allow[0]",
    ]);
  });

  it("warns on a partial overlap", () => {
    const result = validate((p) => {
      p.names.dns.allow = ["**.cluster.local"];
      p.names.ip.allow = ["0.0.0.0/1"];
      p.forced.sans = {};
    });
    expect(result.errors).toEqual([]);
    expect(result.warnings.map((w) => w.path)).toEqual([
      "policy.names.dns.allow[0]",
      "policy.names.ip.allow[0]",
    ]);
    expect(result.ok).toBe(true);
  });

  it("ignores deny rules for overlap", () => {
    const result = validate((p) => (p.names.dns.deny = ["elsewhere.org"]));
    expect(result.errors).toEqual([]);
    expect(result.warnings).toEqual([]);
  });

  it("errors on forced SANs that violate the CA constraints", () => {
    expect(
      codes(validate((p) => (p.forced.sans = { dns: ["x.other.org"] })).errors),
    ).toContain("forced_san_violates_ca_constraints");
    expect(
      codes(validate((p) => (p.forced.sans = { ip: ["192.168.1.1"] })).errors),
    ).toContain("forced_san_violates_ca_constraints");
    expect(
      validate(
        (p) => (p.forced.sans = { dns: ["x.example.com"], ip: ["10.1.1.1"] }),
      ).errors,
    ).toEqual([]);
  });

  it("skips CA-dependent checks when no CA is given", () => {
    const policy = validPolicy();
    policy.names.dns.allow = ["api.other.org"];
    expect(validateGrantPolicy(policy).ok).toBe(true);
  });
});

describe("policyDigest and compileGrantPolicy", () => {
  it("is stable across key order and changes with content", () => {
    const a = validPolicy();
    const reordered = JSON.parse(
      JSON.stringify({
        quotas: a.quotas,
        lifetime: a.lifetime,
        names: a.names,
      }),
    ) as Record<string, unknown>;
    const b = { ...a, ...reordered };
    expect(policyDigest(a)).toBe(policyDigest(b));
    expect(policyDigest(a)).toMatch(/^[0-9a-f]{64}$/);
    b.quotas = { perHour: 1 };
    expect(policyDigest(a)).not.toBe(policyDigest(b));
  });

  it("compiles a stored policy and throws on a corrupt one", () => {
    const result = validateGrantPolicy(validPolicy());
    expect(result.policy).toBeDefined();
    const compiled = compileGrantPolicy(result.policy!);
    expect(compiled.maxSans).toBe(50);
    expect(compiled.minSeconds).toBe(3600);
    const corrupt = JSON.parse(JSON.stringify(result.policy));
    corrupt.names.dns.allow = ["**.com"];
    expect(() => compileGrantPolicy(corrupt)).toThrow("invalid");
  });
});

describe("review regressions", () => {
  it("rejects an oversized or reserved forced URI SAN", () => {
    const policy = validPolicy();
    policy.forced.sans = {
      uri: [`spiffe://hemlig/consumer/${'"'.repeat(340)}`],
    };
    const result = validateGrantPolicy(policy);
    expect(result.ok).toBe(false);
    expect(codes(result.errors)).toContain("invalid_forced_san");
  });

  it("rejects a non-numeric CA maximum lifetime", () => {
    const result = validateGrantPolicy(validPolicy(), {
      ca: ca({ maxLeafLifetimeSeconds: NaN }),
    });
    expect(codes(result.errors)).toContain("ca_policy_invalid");
  });
});

describe("external review regressions", () => {
  it("rejects policy OIDs DER cannot encode", () => {
    for (const oid of ["1.40.7", "0.40", "3.1"]) {
      const policy = validPolicy();
      policy.forced.certificatePolicies = [oid];
      expect(codes(validateGrantPolicy(policy).errors)).toContain(
        "invalid_oid",
      );
    }
    const ok = validPolicy();
    ok.forced.certificatePolicies = ["1.39.7", "2.999.1"];
    expect(validateGrantPolicy(ok).ok).toBe(true);
  });

  it("resolves omitted keyAlgorithms against the CA leaf policy", () => {
    const policy = validPolicy();
    delete policy.keyAlgorithms;
    const result = validateGrantPolicy(policy, {
      ca: ca({ leafKeyAlgorithms: ["ECDSA_P256"] }),
    });
    expect(result.ok).toBe(true);
    expect(result.compiled?.keyAlgorithms).toEqual(["ECDSA_P256"]);
  });

  it("rejects a grant whose resolved keyAlgorithms is empty", () => {
    const policy = validPolicy();
    delete policy.keyAlgorithms;
    const result = validateGrantPolicy(policy, {
      ca: ca({ leafKeyAlgorithms: ["ED25519"] }),
    });
    expect(result.ok).toBe(false);
  });

  it("uses attribute-specific subject length limits", () => {
    const policy = validPolicy();
    policy.forced.subject = {
      locality: "l".repeat(128),
      state: "s".repeat(128),
    };
    expect(validateGrantPolicy(policy).ok).toBe(true);
    policy.forced.subject = { locality: "l".repeat(129) };
    expect(validateGrantPolicy(policy).ok).toBe(false);
    policy.forced.subject = { organization: "o".repeat(65) };
    expect(validateGrantPolicy(policy).ok).toBe(false);
    const pattern = validPolicy();
    pattern.subject = { allow: { locality: ["l".repeat(100)] } };
    expect(validateGrantPolicy(pattern).ok).toBe(true);
    pattern.subject = { allow: { organization: ["o".repeat(100)] } };
    expect(validateGrantPolicy(pattern).ok).toBe(false);
  });
});
