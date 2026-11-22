import { globMatches } from "./grant-policy";
import {
  type DnsRule,
  type DnsRuleSet,
  checkNameConstraints,
  classifyCidr,
  classifyDnsRule,
  cidrContainsIp,
  cidrSubset,
  evaluateDnsName,
  evaluateIp,
  evaluateUri,
  ipToString,
  isReservedName,
  normalizeDnsName,
  normalizeIp,
  normalizeUri,
  parseCidr,
  parseDnsRule,
  parseUriRule,
} from "./names";

const dnsOk = (input: string, allowWildcard = false): string => {
  const result = normalizeDnsName(input, { allowWildcard });
  if (!result.ok) {
    throw new Error(`expected ${input} to normalize: ${result.reason}`);
  }
  return result.value;
};

const rule = (text: string): DnsRule => {
  const result = parseDnsRule(text);
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return result.value;
};

const dnsSet = (
  allow: string[],
  deny: string[] = [],
  allowWildcardNames = false,
): DnsRuleSet => ({
  allow: allow.map(rule),
  deny: deny.map(rule),
  allowWildcardNames,
});

describe("normalizeDnsName", () => {
  it.each([
    ["API.Example.COM", "api.example.com"],
    ["api.example.com.", "api.example.com"],
    ["localhost", "localhost"],
    ["a-b.example.com", "a-b.example.com"],
    ["xn--bcher-kva.example.com", "xn--bcher-kva.example.com"],
    ["1.example.com", "1.example.com"],
  ])("accepts %s", (input, expected) => {
    expect(dnsOk(input)).toBe(expected);
  });

  it.each([
    ["empty", ""],
    ["only a dot", "."],
    ["double trailing dot", "a.example.com.."],
    ["empty label", "a..example.com"],
    ["leading dot", ".example.com"],
    ["underscore", "_dmarc.example.com"],
    ["U-label", "bücher.example.com"],
    ["leading hyphen", "-a.example.com"],
    ["trailing hyphen", "a-.example.com"],
    ["space", "a b.example.com"],
    ["label too long", `${"a".repeat(64)}.example.com`],
    ["name too long", `${"a".repeat(60)}.`.repeat(5) + "com"],
    ["bad A-label (invalid punycode)", "xn--abc.example.com"],
    ["bare xn--", "xn--.example.com"],
    ["A-label with invalid punycode digits", "xn--a.example.com"],
    ["wildcard without opting in", "*.example.com"],
  ])("rejects %s", (_name, input) => {
    expect(normalizeDnsName(input).ok).toBe(false);
  });

  it("accepts exactly 63-byte labels and a 253-byte name", () => {
    const label = "a".repeat(63);
    expect(normalizeDnsName(`${label}.example.com`).ok).toBe(true);
    const name = [label, label, label, "a".repeat(253 - 63 * 3 - 3)].join(".");
    expect(name).toHaveLength(253);
    expect(normalizeDnsName(name).ok).toBe(true);
    expect(normalizeDnsName(`${name}a`).ok).toBe(false);
  });

  it("allows * only as the whole leftmost label", () => {
    expect(dnsOk("*.Example.com", true)).toBe("*.example.com");
    for (const bad of [
      "a.*.example.com",
      "*a.example.com",
      "a*.example.com",
      "**.example.com",
      "*",
      "*.",
    ]) {
      expect(normalizeDnsName(bad, { allowWildcard: true }).ok).toBe(false);
    }
  });
});

describe("parseDnsRule", () => {
  it("parses the three rule forms", () => {
    expect(rule("api.example.com")).toEqual({
      kind: "exact",
      base: "api.example.com",
    });
    expect(rule("*.Example.com")).toEqual({
      kind: "single",
      base: "example.com",
    });
    expect(rule("**.example.com")).toEqual({
      kind: "deep",
      base: "example.com",
    });
  });

  it("allows exact single-label names only", () => {
    expect(rule("localhost")).toEqual({ kind: "exact", base: "localhost" });
    for (const bad of ["**.com", "*.com", "*.localhost", "**.localhost"]) {
      expect(parseDnsRule(bad).ok).toBe(false);
    }
  });

  it.each([
    "*",
    "**",
    "a.*.example.com",
    "*a.example.com",
    "***.example.com",
    "**example.com",
    "",
    "a_b.example.com",
  ])("rejects malformed rule %p", (text) => {
    expect(parseDnsRule(text).ok).toBe(false);
  });
});

describe('DNS rule grammar table (plan "Names")', () => {
  const allowed = (rules: string[], name: string, wildcards = false) =>
    evaluateDnsName(name, dnsSet(rules, [], wildcards)).allowed;

  it.each([
    ["api.example.com", "api.example.com", true],
    ["api.example.com", "x.api.example.com", false],
    ["*.example.com", "a.example.com", true],
    ["*.example.com", "example.com", false],
    ["*.example.com", "a.b.example.com", false],
    ["**.example.com", "a.example.com", true],
    ["**.example.com", "a.b.example.com", true],
    ["**.example.com", "example.com", false],
    ["**.example.com", "notexample.com", false],
    ["*.example.com", "aexample.com", false],
  ])("rule %s permits %s: %s", (ruleText, name, expected) => {
    expect(allowed([ruleText], name)).toBe(expected);
  });

  it("requested wildcard needs allowWildcardNames", () => {
    const decision = evaluateDnsName(
      "*.x.example.com",
      dnsSet(["**.example.com"]),
    );
    expect(decision).toMatchObject({
      allowed: false,
      reason: "wildcard_not_permitted",
    });
  });

  it.each([
    // [allow rules, requested wildcard, permitted]
    [["**.example.com"], "*.x.example.com", true],
    [["**.example.com"], "*.example.com", true],
    [["*.x.example.com"], "*.x.example.com", true],
    [["*.example.com"], "*.x.example.com", false], // two labels deep
    [["x.example.com"], "*.x.example.com", false],
    [["a.x.example.com", "b.x.example.com"], "*.x.example.com", false],
    [["**.x.example.com"], "*.example.com", false],
  ] as const)(
    "wildcard coverage %j requesting %s: %s",
    (rules, requested, expected) => {
      expect(
        evaluateDnsName(requested, dnsSet([...rules], [], true)).allowed,
      ).toBe(expected);
    },
  );
});

describe("deny precedence", () => {
  it("denies a name that matches both allow and deny", () => {
    const set = dnsSet(["**.example.com"], ["internal.example.com"]);
    expect(evaluateDnsName("internal.example.com", set)).toMatchObject({
      allowed: false,
      reason: "name_not_permitted",
    });
    expect(evaluateDnsName("public.example.com", set).allowed).toBe(true);
  });

  it("applies wildcard deny rules to deeper names", () => {
    const set = dnsSet(["**.example.com"], ["**.secret.example.com"]);
    expect(evaluateDnsName("a.b.secret.example.com", set).allowed).toBe(false);
    expect(evaluateDnsName("secret.example.com", set).allowed).toBe(true);
  });

  it("denies a requested wildcard when any covered name matches a deny rule", () => {
    const allow = ["**.example.com"];
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["a.x.example.com"], true),
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["*.x.example.com"], true),
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["**.example.com"], true),
      ).allowed,
    ).toBe(false);
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["**.x.example.com"], true),
      ).allowed,
    ).toBe(false);
    // A deny deeper than the wildcard's single label does not intersect it.
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["a.b.x.example.com"], true),
      ).allowed,
    ).toBe(true);
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["**.a.x.example.com"], true),
      ).allowed,
    ).toBe(true);
    expect(
      evaluateDnsName(
        "*.x.example.com",
        dnsSet(allow, ["*.y.example.com"], true),
      ).allowed,
    ).toBe(true);
  });

  it("an empty allow list permits nothing", () => {
    expect(evaluateDnsName("a.example.com", dnsSet([])).allowed).toBe(false);
  });
});

describe("property: rule matching agrees with brute-force expansion", () => {
  // mulberry32: a tiny deterministic generator, so failures reproduce.
  const prng = (seed: number) => () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const ALPHABET = ["a", "b", "c"];
  const FRESH = "z"; // a label that appears in no rule
  const LABELS = [...ALPHABET, FRESH];
  const MAX_DEPTH = 5;

  const universe: string[] = [];
  const build = (prefix: string[]) => {
    if (prefix.length > 0) {
      universe.push(prefix.join("."));
    }
    if (prefix.length < MAX_DEPTH) {
      for (const label of LABELS) {
        build([label, ...prefix]);
      }
    }
  };
  build([]);

  const expand = (text: string): Set<string> => {
    if (text.startsWith("**.")) {
      const base = text.slice(3);
      return new Set(universe.filter((n) => n.endsWith(`.${base}`)));
    }
    if (text.startsWith("*.")) {
      const base = text.slice(2);
      return new Set(LABELS.map((l) => `${l}.${base}`));
    }
    return new Set([text]);
  };

  it("matches for concrete names and requested wildcards", () => {
    const next = prng(0xc0ffee);
    const pick = <T>(list: readonly T[]): T =>
      list[Math.floor(next() * list.length)] as T;
    const labels = (min: number, max: number): string =>
      Array.from({ length: min + Math.floor(next() * (max - min + 1)) }, () =>
        pick(ALPHABET),
      ).join(".");
    const randomRule = (): string => {
      const roll = next();
      if (roll < 0.3) {
        return labels(1, 4);
      }
      return `${roll < 0.65 ? "*" : "**"}.${labels(2, 3)}`;
    };

    for (let iteration = 0; iteration < 150; iteration += 1) {
      const allow = Array.from(
        { length: 1 + Math.floor(next() * 4) },
        randomRule,
      );
      const deny = Array.from({ length: Math.floor(next() * 3) }, randomRule);
      const set = dnsSet(allow, deny, true);
      const allowed = new Set(allow.flatMap((r) => [...expand(r)]));
      const denied = new Set(deny.flatMap((r) => [...expand(r)]));
      const permitted = (name: string) =>
        allowed.has(name) && !denied.has(name);

      for (const name of universe) {
        expect({
          allow,
          deny,
          name,
          got: evaluateDnsName(name, set).allowed,
        }).toEqual({
          allow,
          deny,
          name,
          got: permitted(name),
        });
      }
      for (let i = 0; i < 12; i += 1) {
        const base = labels(1, MAX_DEPTH - 1);
        const requested = `*.${base}`;
        const covered = LABELS.map((l) => `${l}.${base}`);
        expect({
          allow,
          deny,
          requested,
          got: evaluateDnsName(requested, set).allowed,
        }).toEqual({
          allow,
          deny,
          requested,
          got: covered.every(permitted),
        });
      }
    }
  });
});

describe("IP", () => {
  it.each([
    ["10.0.0.1", "10.0.0.1"],
    ["::1", "::1"],
    ["2001:DB8::1", "2001:db8::1"],
    ["2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"],
    ["::ffff:10.0.0.1", "10.0.0.1"],
    ["::FFFF:0a00:0001", "10.0.0.1"],
    ["0:0:0:0:0:ffff:1.2.3.4", "1.2.3.4"],
    ["2001:db8:0:1:0:0:0:1", "2001:db8:0:1::1"],
    ["1:0:0:2:0:0:0:3", "1:0:0:2::3"],
    ["::", "::"],
    ["fd00::", "fd00::"],
    ["1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8"],
    ["::1.2.3.4", "::102:304"],
  ])("normalizes %s to %s", (input, expected) => {
    const result = normalizeIp(input);
    expect(result.ok && result.value.text).toBe(expected);
  });

  it.each([
    "",
    "256.0.0.1",
    "01.2.3.4",
    "1.2.3",
    "1.2.3.4.5",
    "1:2:3:4:5:6:7",
    "1::2::3",
    "fe80::1%eth0",
    ":::",
    "12345::1",
    "g::1",
    "1.2.3.4/8",
    " 1.2.3.4",
  ])("rejects %p", (input) => {
    expect(normalizeIp(input).ok).toBe(false);
  });

  it("produces the same bytes for an IPv4-mapped IPv6 address and the IPv4 form", () => {
    const mapped = normalizeIp("::ffff:192.0.2.1");
    const plain = normalizeIp("192.0.2.1");
    expect(mapped.ok && plain.ok && mapped.value.family).toBe(4);
    expect(
      mapped.ok &&
        plain.ok &&
        Buffer.from(mapped.value.bytes).equals(Buffer.from(plain.value.bytes)),
    ).toBe(true);
  });

  it("formats the longest zero run and ties go to the first", () => {
    expect(
      ipToString({
        family: 6,
        bytes: Uint8Array.from([
          0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 4,
        ]),
      }),
    ).toBe("1::2:0:0:3:4");
  });
});

describe("CIDR", () => {
  const cidr = (text: string) => {
    const result = parseCidr(text);
    if (!result.ok) {
      throw new Error(result.reason);
    }
    return result.value;
  };
  const ip = (text: string) => {
    const result = normalizeIp(text);
    if (!result.ok) {
      throw new Error(result.reason);
    }
    return result.value;
  };

  it("contains addresses by prefix", () => {
    expect(cidrContainsIp(cidr("10.20.0.0/16"), ip("10.20.255.255"))).toBe(
      true,
    );
    expect(cidrContainsIp(cidr("10.20.0.0/16"), ip("10.21.0.0"))).toBe(false);
    expect(cidrContainsIp(cidr("10.20.4.0/23"), ip("10.20.5.1"))).toBe(true);
    expect(cidrContainsIp(cidr("10.20.4.0/23"), ip("10.20.6.1"))).toBe(false);
    expect(cidrContainsIp(cidr("fd00::/8"), ip("fd12:3456::1"))).toBe(true);
    expect(cidrContainsIp(cidr("fd00::/8"), ip("fe00::1"))).toBe(false);
    expect(cidrContainsIp(cidr("2001:db8::/33"), ip("2001:db8:8000::1"))).toBe(
      false,
    );
  });

  it("never matches across families", () => {
    expect(cidrContainsIp(cidr("10.0.0.0/8"), ip("::1"))).toBe(false);
    expect(cidrContainsIp(cidr("::/1"), ip("10.0.0.1"))).toBe(false);
  });

  it("matches an IPv4-mapped IPv6 address against an IPv4 rule", () => {
    expect(cidrContainsIp(cidr("10.0.0.0/8"), ip("::ffff:10.1.2.3"))).toBe(
      true,
    );
  });

  it("converts an IPv4-mapped IPv6 network to IPv4 and needs prefix >= 96", () => {
    const mapped = cidr("::ffff:10.0.0.0/104");
    expect(mapped).toMatchObject({ family: 4, prefix: 8 });
    expect(parseCidr("::ffff:10.0.0.0/64").ok).toBe(false);
    expect(parseCidr("::ffff:0:0/95").ok).toBe(false);
  });

  it("treats a bare address as a single host", () => {
    expect(cidr("10.0.0.5")).toMatchObject({ family: 4, prefix: 32 });
    expect(cidr("::1")).toMatchObject({ family: 6, prefix: 128 });
  });

  it.each([
    "10.0.0.1/24",
    "10.0.0.0/33",
    "fd00::/129",
    "10.0.0.0/",
    "10.0.0.0/08",
    "10.0.0.0/-1",
    "10.0.0.0/0",
    "::/0",
    "x/8",
  ])("rejects rule %p", (text) => {
    expect(parseCidr(text).ok).toBe(false);
  });

  it("is lenient for CA constraints (masks host bits, allows /0)", () => {
    expect(parseCidr("10.0.0.1/8", { strict: false })).toMatchObject({
      ok: true,
      value: { prefix: 8 },
    });
    expect(parseCidr("0.0.0.0/0", { strict: false }).ok).toBe(true);
  });

  it("evaluates allow and deny, deny first", () => {
    const rules = {
      allow: [cidr("10.20.0.0/16")],
      deny: [cidr("10.20.1.0/24")],
    };
    expect(evaluateIp(ip("10.20.2.1"), rules).allowed).toBe(true);
    expect(evaluateIp(ip("10.20.1.1"), rules).allowed).toBe(false);
    expect(evaluateIp(ip("10.30.0.1"), rules).allowed).toBe(false);
  });

  it("computes subsets", () => {
    expect(cidrSubset(cidr("10.1.0.0/16"), cidr("10.0.0.0/8"))).toBe(true);
    expect(cidrSubset(cidr("10.0.0.0/8"), cidr("10.1.0.0/16"))).toBe(false);
  });
});

describe("URI", () => {
  const uri = (text: string) => {
    const result = normalizeUri(text);
    if (!result.ok) {
      throw new Error(`${text}: ${result.reason}`);
    }
    return result.value;
  };
  const uriRule = (text: string) => {
    const result = parseUriRule(text);
    if (!result.ok) {
      throw new Error(result.reason);
    }
    return result.value;
  };
  const permits = (ruleText: string, request: string) =>
    evaluateUri(uri(request), { allow: [uriRule(ruleText)], deny: [] }).allowed;

  it("normalizes scheme, host and path", () => {
    expect(uri("SPIFFE://Prod.Example.COM/ns/payments/sa/web").value).toBe(
      "spiffe://prod.example.com/ns/payments/sa/web",
    );
    expect(uri("spiffe://x/a/./b/../c").path).toBe("/a/c");
    expect(uri("spiffe://x/a/%2e%2e/b").path).toBe("/b"); // dot segments resolve, never reach the matcher
    expect(uri("spiffe://x/%7Ea%41/%2f").path).toBe("/~aA/%2F");
    expect(uri("https://x.example.com:443/p").value).toBe(
      "https://x.example.com/p",
    );
    expect(uri("spiffe://x").path).toBe("");
    expect(uri("spiffe://x.example.com/a?b=1").query).toBe("?b=1");
  });

  it.each([
    ["userinfo", "https://user:pw@example.com/"],
    ["userinfo without password", "https://user@example.com/"],
    ["fragment", "https://example.com/#f"],
    ["no authority", "urn:isbn:123"],
    ["no scheme", "//example.com/x"],
    ["empty host", "spiffe:///path"],
    ["IPv6 host", "https://[::1]/x"],
    ["U-label host", "https://bücher.example/x"],
    ["underscore host", "spiffe://a_b.example/x"],
    ["whitespace", "spiffe://x/a b"],
    ["newline smuggling", "spiffe://x/a\nb"],
    ["non-ASCII path", "spiffe://x/é"],
    ["bad percent escape", "spiffe://x/%zz"],
    ["encoded NUL", "spiffe://x/%00"],
    ["port out of range", "spiffe://x:99999/"],
    ["too long", `spiffe://x/${"a".repeat(1030)}`],
  ])("rejects %s", (_name, text) => {
    expect(normalizeUri(text).ok).toBe(false);
  });

  it("matches exact scheme, host and path segments", () => {
    const ruleText = "spiffe://prod.example.com/ns/payments/**";
    expect(
      permits(ruleText, "spiffe://prod.example.com/ns/payments/sa/web"),
    ).toBe(true);
    expect(permits(ruleText, "SPIFFE://PROD.example.com/ns/payments/sa")).toBe(
      true,
    );
    expect(permits(ruleText, "spiffe://prod.example.com/ns/payments")).toBe(
      false,
    );
    expect(permits(ruleText, "spiffe://prod.example.com/ns/payments/")).toBe(
      false,
    );
    expect(permits(ruleText, "spiffe://prod.example.com/ns/other/sa")).toBe(
      false,
    );
    expect(permits(ruleText, "spiffe://other.example.com/ns/payments/sa")).toBe(
      false,
    );
    expect(permits(ruleText, "https://prod.example.com/ns/payments/sa")).toBe(
      false,
    );
  });

  it("* matches exactly one segment", () => {
    const ruleText = "spiffe://prod.example.com/ns/*/sa/web";
    expect(
      permits(ruleText, "spiffe://prod.example.com/ns/payments/sa/web"),
    ).toBe(true);
    expect(permits(ruleText, "spiffe://prod.example.com/ns/a/b/sa/web")).toBe(
      false,
    );
    expect(permits(ruleText, "spiffe://prod.example.com/ns//sa/web")).toBe(
      false,
    );
    expect(
      permits(
        "spiffe://prod.example.com/ns/*",
        "spiffe://prod.example.com/ns/a/b",
      ),
    ).toBe(false);
  });

  it("does not let dot segments or encoding escape the prefix", () => {
    expect(
      permits("spiffe://x.example.com/a/**", "spiffe://x.example.com/a/../b"),
    ).toBe(false);
    expect(
      permits("spiffe://x.example.com/a/b", "spiffe://x.example.com/a/%62"),
    ).toBe(true);
  });

  it("does not permit ports or query strings", () => {
    expect(
      permits("https://x.example.com/**", "https://x.example.com:8443/a"),
    ).toBe(false);
    expect(
      permits("https://x.example.com/a", "https://x.example.com/a?q=1"),
    ).toBe(false);
    expect(permits("https://x.example.com/a", "https://x.example.com/a")).toBe(
      true,
    );
  });

  it("allows DNS rule syntax in the host", () => {
    expect(
      permits("spiffe://*.example.com/x", "spiffe://a.example.com/x"),
    ).toBe(true);
    expect(
      permits("spiffe://*.example.com/x", "spiffe://a.b.example.com/x"),
    ).toBe(false);
    expect(
      permits("spiffe://**.example.com/x", "spiffe://a.b.example.com/x"),
    ).toBe(true);
  });

  it("applies deny rules first", () => {
    const rules = {
      allow: [uriRule("spiffe://x.example.com/**")],
      deny: [uriRule("spiffe://x.example.com/admin/**")],
    };
    expect(
      evaluateUri(uri("spiffe://x.example.com/admin/root"), rules).allowed,
    ).toBe(false);
    expect(evaluateUri(uri("spiffe://x.example.com/app"), rules).allowed).toBe(
      true,
    );
  });

  it.each([
    ["port in rule", "spiffe://x.example.com:8080/a"],
    ["query in rule", "spiffe://x.example.com/a?b"],
    ["fragment in rule", "spiffe://x.example.com/a#b"],
    ["userinfo in rule", "spiffe://u@x.example.com/a"],
    ["** not final", "spiffe://x.example.com/**/a"],
    ["partial segment wildcard", "spiffe://x.example.com/a*"],
    ["no scheme", "x.example.com/a"],
    ["wildcard base too short", "spiffe://**.com/a"],
    ["IPv6 host", "spiffe://[::1]/a"],
    ["dot segment", "spiffe://x.example.com/a/../b"],
  ])("rejects rule with %s", (_name, text) => {
    expect(parseUriRule(text).ok).toBe(false);
  });

  it("treats spiffe://hemlig/ as reserved", () => {
    expect(isReservedName("uri", "spiffe://hemlig/consumer/abc")).toBe(true);
    expect(isReservedName("uri", "SPIFFE://Hemlig")).toBe(true);
    expect(isReservedName("uri", "spiffe://hemlig.example.com/x")).toBe(false);
    expect(isReservedName("dns", "hemlig")).toBe(false);
  });
});

describe("CA name constraints", () => {
  const dnsConstraints = { permitted: { dns: ["example.com"] } };

  it("applies RFC 5280 DNS semantics", () => {
    expect(checkNameConstraints("dns", "example.com", dnsConstraints).ok).toBe(
      true,
    );
    expect(
      checkNameConstraints("dns", "a.b.example.com", dnsConstraints).ok,
    ).toBe(true);
    expect(
      checkNameConstraints("dns", "notexample.com", dnsConstraints).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("dns", "example.com", {
        permitted: { dns: [".example.com"] },
      }).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("dns", "a.example.com", {
        permitted: { dns: [".example.com"] },
      }).ok,
    ).toBe(true);
  });

  it("checks every name a wildcard can cover", () => {
    expect(
      checkNameConstraints("dns", "*.x.example.com", dnsConstraints).ok,
    ).toBe(true);
    expect(checkNameConstraints("dns", "*.com", dnsConstraints).ok).toBe(false);
    expect(
      checkNameConstraints("dns", "*.x.example.com", {
        ...dnsConstraints,
        excluded: { dns: ["a.x.example.com"] },
      }).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("dns", "*.x.example.com", {
        ...dnsConstraints,
        excluded: { dns: ["internal.example.com"] },
      }).ok,
    ).toBe(true);
    expect(
      checkNameConstraints("dns", "*.x.example.com", {
        ...dnsConstraints,
        excluded: { dns: ["x.example.com"] },
      }).ok,
    ).toBe(false);
  });

  it("leaves unconstrained name types unrestricted", () => {
    expect(checkNameConstraints("ip", "10.0.0.1", dnsConstraints).ok).toBe(
      true,
    );
    expect(
      checkNameConstraints("uri", "spiffe://anything/x", dnsConstraints).ok,
    ).toBe(true);
    expect(checkNameConstraints("dns", "anything.test", undefined).ok).toBe(
      true,
    );
  });

  it("checks IP and URI host constraints", () => {
    const nc = {
      permitted: { ip: ["10.0.0.0/8"], uri: ["svc.example.com"] },
      excluded: { ip: ["10.9.0.0/16"] },
    };
    expect(checkNameConstraints("ip", "10.1.2.3", nc).ok).toBe(true);
    expect(checkNameConstraints("ip", "10.9.2.3", nc).ok).toBe(false);
    expect(checkNameConstraints("ip", "192.168.0.1", nc).ok).toBe(false);
    expect(
      checkNameConstraints("uri", "spiffe://svc.example.com/a", nc).ok,
    ).toBe(true);
    expect(
      checkNameConstraints("uri", "spiffe://a.svc.example.com/a", nc).ok,
    ).toBe(false); // URI constraints are host-exact
    expect(
      checkNameConstraints("uri", "spiffe://a.svc.example.com/a", {
        permitted: { uri: [".svc.example.com"] },
      }).ok,
    ).toBe(true);
  });

  it("classifies rules as inside, partial or outside", () => {
    const nc = {
      permitted: { dns: ["svc.cluster.local", "example.com"] },
      excluded: { dns: ["internal.example.com"] },
    };
    expect(classifyDnsRule(rule("**.payments.svc.cluster.local"), nc)).toBe(
      "inside",
    );
    expect(classifyDnsRule(rule("api.example.com"), nc)).toBe("inside");
    expect(classifyDnsRule(rule("other.org"), nc)).toBe("outside");
    expect(classifyDnsRule(rule("**.other.org"), nc)).toBe("outside");
    expect(classifyDnsRule(rule("internal.example.com"), nc)).toBe("outside");
    expect(classifyDnsRule(rule("**.example.com"), nc)).toBe("partial"); // may hit internal.example.com
    expect(classifyDnsRule(rule("**.cluster.local"), nc)).toBe("partial"); // wider than the permitted subtree
    expect(classifyDnsRule(rule("*.cluster.local"), nc)).toBe("partial"); // svc.cluster.local itself fits
    expect(classifyDnsRule(rule("anything.org"), undefined)).toBe("inside");
  });

  it("classifies CIDR rules", () => {
    const nc = {
      permitted: { ip: ["10.0.0.0/8"] },
      excluded: { ip: ["10.9.0.0/16"] },
    };
    const c = cidrOf;
    expect(classifyCidr(c("10.20.0.0/16"), nc)).toBe("inside");
    expect(classifyCidr(c("192.168.0.0/16"), nc)).toBe("outside");
    expect(classifyCidr(c("10.9.1.0/24"), nc)).toBe("outside");
    expect(classifyCidr(c("10.0.0.0/8"), nc)).toBe("partial");
    expect(classifyCidr(c("0.0.0.0/1"), nc)).toBe("partial");
  });
});

const cidrOf = (text: string) => {
  const result = parseCidr(text);
  if (!result.ok) {
    throw new Error(result.reason);
  }
  return result.value;
};

describe("review regressions: URI length, constraints, globs", () => {
  it("enforces the 1,024-byte limit on the normalized URI (percent-encoding grows it)", () => {
    const raw = `spiffe://prod.example.com/ns/other-team/sa/admin?${"a".repeat(974)}"`;
    expect(Buffer.byteLength(raw)).toBeLessThanOrEqual(1024);
    expect(normalizeUri(raw).ok).toBe(false);
    expect(normalizeUri(`spiffe://hemlig/consumer/${'"'.repeat(340)}`).ok).toBe(
      false,
    );
    expect(normalizeUri(`spiffe://x.example.com/${"a".repeat(1000)}`).ok).toBe(
      true,
    );
  });

  it("fails closed on unparsable values, with or without constraints", () => {
    expect(
      checkNameConstraints(
        "uri",
        `spiffe://hemlig/${'"'.repeat(400)}`,
        undefined,
      ).ok,
    ).toBe(false);
    expect(checkNameConstraints("ip", "nope", undefined).ok).toBe(false);
    expect(isReservedName("uri", `spiffe://hemlig/${'"'.repeat(400)}`)).toBe(
      true,
    );
  });

  it("keeps IP constraints restrictive when an entry does not parse", () => {
    expect(
      checkNameConstraints("ip", "10.1.1.1", { permitted: { ip: ["garbage"] } })
        .ok,
    ).toBe(false);
    expect(
      checkNameConstraints("ip", "10.1.1.1", {
        permitted: { ip: ["garbage", "10.0.0.0/8"] },
      }).ok,
    ).toBe(true);
    expect(
      checkNameConstraints("ip", "10.1.1.1", { excluded: { ip: ["garbage"] } })
        .ok,
    ).toBe(false);
  });

  it("does not let a mapped-form constraint permit 4-byte addresses", () => {
    const nc = { permitted: { ip: ["::ffff:10.0.0.0/104"] } };
    expect(checkNameConstraints("ip", "10.1.1.1", nc).ok).toBe(false);
    expect(checkNameConstraints("ip", "::ffff:10.1.1.1", nc).ok).toBe(false); // normalizes to 4 bytes
  });

  it("denies IP-literal URI hosts when the CA has URI constraints", () => {
    expect(
      checkNameConstraints("uri", "spiffe://10.0.0.1/x", {
        permitted: { uri: [".example.com"] },
      }).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("uri", "spiffe://10.0.0.1/x", {
        excluded: { uri: ["bad.example.com"] },
      }).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("uri", "spiffe://10.0.0.1/x", {
        permitted: { dns: ["example.com"] },
      }).ok,
    ).toBe(true);
  });

  it("treats an undotted excluded URI subtree as the host and its subdomains", () => {
    const nc = { excluded: { uri: ["bad.example.com"] } };
    expect(
      checkNameConstraints("uri", "spiffe://bad.example.com/x", nc).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("uri", "spiffe://a.bad.example.com/x", nc).ok,
    ).toBe(false);
    expect(
      checkNameConstraints("uri", "spiffe://good.example.com/x", nc).ok,
    ).toBe(true);
  });

  it("matches globs in linear time", () => {
    const started = Date.now();
    expect(globMatches("*a".repeat(7), `${"a".repeat(63)}b`)).toBe(false);
    expect(Date.now() - started).toBeLessThan(200);
    expect(globMatches("payments-*", "payments-eu")).toBe(true);
    expect(globMatches("*-eu", "payments-eu")).toBe(true);
    expect(globMatches("a*b*c", "axxbxxc")).toBe(true);
    expect(globMatches("a*b*c", "axxbxx")).toBe(false);
    expect(globMatches("", "")).toBe(true);
    expect(globMatches("a.b", "axb")).toBe(false);
  });
});
