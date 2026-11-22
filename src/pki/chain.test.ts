import { ApiError } from "../domain/errors";
import {
  days,
  hours,
  makeCert,
  makeIntermediate,
  makeRoot,
  newKey,
  rootExtensions,
  skiExtension,
  subjectDer,
  type TestCert,
  type TestKey,
} from "./__fixtures__/testkit";
import { oid, seq, smallInteger, tlv } from "./asn1/der";
import {
  authorityKeyIdentifierValue,
  basicConstraintsValue,
  EKU,
  EXT,
  extension,
  keyUsageValue,
} from "./asn1/extensions";
import { encodeName } from "./asn1/names";
import {
  computeLeafValidity,
  earliestNotAfter,
  extendedKeyUsageWithin,
  nameConstraintsWithin,
  verifyActivationChain,
  type ActivationInput,
} from "./chain";
import { buildCaSubject, identityRootSubjectKey } from "./subject";
import type { NameConstraintSet } from "./types";

const nc = (
  permitted: string[] = [],
  excluded: string[] = [],
): NameConstraintSet => {
  const entry = (value: string) =>
    value.includes("/")
      ? ({ type: "ip", value } as const)
      : value.startsWith("uri:")
        ? ({ type: "uri", value: value.slice(4) } as const)
        : ({ type: "dns", value } as const);
  return { permitted: permitted.map(entry), excluded: excluded.map(entry) };
};

const subject = { O: "Test Corp", CN: "Test Issuing CA 1" };

interface Setup {
  root: TestCert;
  key: TestKey;
  intermediate: TestCert;
  input: ActivationInput;
}

const setup = async (
  options: {
    requested?: ActivationInput["requested"];
    certificate?: Parameters<typeof makeIntermediate>[1];
    accept?: boolean;
  } = {},
): Promise<Setup> => {
  const root = await makeRoot();
  const key = await newKey();
  const intermediate = await makeIntermediate(root, {
    key,
    subject,
    ...options.certificate,
  });
  return {
    root,
    key,
    intermediate,
    input: {
      certificatePem: intermediate.pem,
      chainPem: root.pem,
      now: new Date(),
      caSpkiDer: key.spkiDer,
      requestedSubjectKey: buildCaSubject(subject).key,
      requested: options.requested ?? { pathLen: 0 },
      acceptBroaderConstraints: options.accept,
      deploymentName: "test",
    },
  };
};

const reasonOf = (action: () => unknown): string | undefined => {
  try {
    action();
  } catch (error) {
    if (error instanceof ApiError) {
      expect(error.code).toBe("chain_invalid");
      expect(error.statusCode).toBe(400);
      return error.safeReason;
    }
    throw error;
  }
  return undefined;
};

/** A CA certificate with the standard extensions, customizable per test. */
const customCa = (
  root: TestCert,
  key: TestKey,
  options: {
    extensions?: Buffer[];
    replace?: string[];
    subject?: Buffer;
    notBefore?: Date;
    notAfter?: Date;
    signedBy?: TestKey;
    issuer?: TestCert;
  } = {},
): TestCert => {
  const standard = [
    extension(EXT.basicConstraints, true, basicConstraintsValue(true, 0)),
    extension(EXT.keyUsage, true, keyUsageValue(["keyCertSign", "cRLSign"])),
    skiExtension(key),
    extension(
      EXT.authorityKeyIdentifier,
      false,
      authorityKeyIdentifierValue(
        root.cert.subjectKeyIdentifier ?? Buffer.alloc(0),
      ),
    ),
  ];
  const replaced = options.replace ?? [];
  return makeCert({
    issuer: options.issuer ?? root,
    key,
    subject: options.subject ?? subjectDer(subject),
    extensions: [
      ...standard.filter(
        (_, index) =>
          !replaced.includes(
            [
              EXT.basicConstraints,
              EXT.keyUsage,
              EXT.subjectKeyIdentifier,
              EXT.authorityKeyIdentifier,
            ][index] as string,
          ),
      ),
      ...(options.extensions ?? []),
    ],
    notBefore: options.notBefore,
    notAfter: options.notAfter,
    signedBy: options.signedBy,
  });
};

describe("nameConstraintsWithin", () => {
  it.each<[string, string[], string[], string[], string[], boolean]>([
    ["equal permitted", ["example.com"], [], ["example.com"], [], true],
    ["narrower permitted", ["api.example.com"], [], ["example.com"], [], true],
    ["unrelated permitted", ["example.org"], [], ["example.com"], [], false],
    [
      "sibling with shared suffix",
      ["badexample.com"],
      [],
      ["example.com"],
      [],
      false,
    ],
    ["broader parent", ["com"], [], ["example.com"], [], false],
    [
      "certificate with no permitted when requested",
      [],
      [],
      ["example.com"],
      [],
      false,
    ],
    [
      "subset of several",
      ["a.example.com", "b.example.net"],
      [],
      ["example.com", "example.net"],
      [],
      true,
    ],
    [
      "one entry outside",
      ["a.example.com", "example.org"],
      [],
      ["example.com", "example.net"],
      [],
      false,
    ],
    ["narrower cidr", ["10.1.0.0/16"], [], ["10.0.0.0/8"], [], true],
    ["equal cidr", ["10.0.0.0/8"], [], ["10.0.0.0/8"], [], true],
    ["broader cidr", ["10.0.0.0/7"], [], ["10.0.0.0/8"], [], false],
    ["disjoint cidr", ["11.0.0.0/8"], [], ["10.0.0.0/8"], [], false],
    ["ipv6 cidr", ["fd00:1::/32"], [], ["fd00::/8"], [], true],
    ["ipv4 vs ipv6", ["10.0.0.0/8"], [], ["fd00::/8"], [], false],
    // URI bases: no leading dot means exactly that host; a leading dot means strictly subordinate hosts.
    ["uri exact host", ["uri:example.com"], [], ["uri:example.com"], [], true],
    [
      "uri subdomain is not covered by a bare host",
      ["uri:prod.example.com"],
      [],
      ["uri:example.com"],
      [],
      false,
    ],
    [
      "uri dotted base inside bare is not covered",
      ["uri:.example.com"],
      [],
      ["uri:example.com"],
      [],
      false,
    ],
    [
      "uri host inside a dotted base",
      ["uri:prod.example.com"],
      [],
      ["uri:.example.com"],
      [],
      true,
    ],
    [
      "uri the dotted base host itself is not subordinate",
      ["uri:example.com"],
      [],
      ["uri:.example.com"],
      [],
      false,
    ],
    [
      "uri dotted inside dotted",
      ["uri:.a.example.com"],
      [],
      ["uri:.example.com"],
      [],
      true,
    ],
    [
      "uri sibling suffix",
      ["uri:.badexample.com"],
      [],
      ["uri:.example.com"],
      [],
      false,
    ],
    [
      "uri excluded exact host does not cover subdomains",
      ["uri:.example.com"],
      ["uri:example.com"],
      ["uri:.example.com"],
      ["uri:a.example.com"],
      false,
    ],
    [
      "uri excluded dotted base covers subdomains",
      ["uri:.example.com"],
      ["uri:.example.com"],
      ["uri:.example.com"],
      ["uri:a.example.com"],
      true,
    ],
    [
      "uri vs dns do not cover each other",
      ["uri:example.com"],
      [],
      ["example.com"],
      [],
      false,
    ],
    [
      "dotted constraint inside bare",
      [".example.com"],
      [],
      ["example.com"],
      [],
      true,
    ],
    [
      "bare is broader than dotted",
      ["example.com"],
      [],
      [".example.com"],
      [],
      false,
    ],
    [
      "requested excluded is present",
      ["example.com"],
      ["bad.example.com"],
      ["example.com"],
      ["bad.example.com"],
      true,
    ],
    [
      "excluded superset",
      ["example.com"],
      ["example.net"],
      ["example.com"],
      ["a.example.net"],
      true,
    ],
    [
      "requested excluded is missing",
      ["example.com"],
      [],
      ["example.com"],
      ["bad.example.com"],
      false,
    ],
    [
      "excluded too narrow",
      ["example.com"],
      ["x.bad.example.com"],
      ["example.com"],
      ["bad.example.com"],
      false,
    ],
    [
      "types the request does not permit are unconstrained",
      ["example.com", "10.0.0.0/8"],
      [],
      ["example.com"],
      [],
      true,
    ],
  ])(
    "%s",
    (_, permitted, excluded, wantedPermitted, wantedExcluded, expected) => {
      expect(
        nameConstraintsWithin(
          nc(permitted, excluded),
          nc(wantedPermitted, wantedExcluded),
        ),
      ).toBe(expected);
    },
  );

  it("treats an absent request as unconstrained", () => {
    expect(nameConstraintsWithin(undefined, undefined)).toBe(true);
    expect(nameConstraintsWithin(nc(["example.com"]), undefined)).toBe(true);
    expect(nameConstraintsWithin(undefined, nc(["example.com"]))).toBe(false);
  });
});

describe("extendedKeyUsageWithin", () => {
  it("nests EKU sets", () => {
    expect(extendedKeyUsageWithin([EKU.serverAuth], [EKU.serverAuth])).toBe(
      true,
    );
    expect(
      extendedKeyUsageWithin(
        [EKU.serverAuth],
        [EKU.serverAuth, EKU.clientAuth],
      ),
    ).toBe(true);
    expect(
      extendedKeyUsageWithin(
        [EKU.serverAuth, EKU.clientAuth],
        [EKU.serverAuth],
      ),
    ).toBe(false);
    expect(extendedKeyUsageWithin(undefined, [EKU.serverAuth])).toBe(false);
    expect(extendedKeyUsageWithin([EKU.any], undefined)).toBe(true);
    expect(extendedKeyUsageWithin(undefined, undefined)).toBe(true);
    expect(extendedKeyUsageWithin([EKU.any], [EKU.serverAuth])).toBe(false);
    expect(extendedKeyUsageWithin(["1.2.3"], [EKU.any])).toBe(true);
  });
});

describe("verifyActivationChain", () => {
  it("accepts a conforming chain and reports the effective constraints", async () => {
    const requested = {
      pathLen: 0 as const,
      nameConstraints: nc(["example.com"], []),
      extendedKeyUsages: [EKU.serverAuth],
    };
    const { input, root, intermediate } = await setup({
      requested,
      certificate: {
        nameConstraints: nc(["example.com"]),
        extendedKeyUsage: [EKU.serverAuth],
      },
    });
    const result = verifyActivationChain(input);
    expect(result.broaderThanRequested).toBe(false);
    expect(result.effective).toEqual({
      nameConstraints: nc(["example.com"]),
      extendedKeyUsages: [EKU.serverAuth],
    });
    expect(result.certificate.fingerprint).toBe(intermediate.cert.fingerprint);
    expect(result.root.fingerprint).toBe(root.cert.fingerprint);
    expect(result.certificateSubject.key).toBe(buildCaSubject(subject).key);
  });

  it("accepts a certificate narrower than requested, and one with no constraints when none were requested", async () => {
    const narrow = await setup({
      requested: { pathLen: 0, nameConstraints: nc(["example.com"]) },
      certificate: { nameConstraints: nc(["api.example.com"]) },
    });
    expect(verifyActivationChain(narrow.input).broaderThanRequested).toBe(
      false,
    );
    const none = await setup();
    expect(verifyActivationChain(none.input).effective).toEqual({});
  });

  describe("constraints broader than requested", () => {
    it.each<
      [
        string,
        ActivationInput["requested"],
        Parameters<typeof makeIntermediate>[1],
      ]
    >([
      [
        "permitted subtree outside the request",
        { pathLen: 0, nameConstraints: nc(["example.com"]) },
        { nameConstraints: nc(["example.org"]) },
      ],
      [
        "no name constraints when requested",
        { pathLen: 0, nameConstraints: nc(["example.com"]) },
        {},
      ],
      [
        "missing excluded subtree",
        {
          pathLen: 0,
          nameConstraints: nc(["example.com"], ["bad.example.com"]),
        },
        { nameConstraints: nc(["example.com"]) },
      ],
      ["pathLen above the request", { pathLen: 0 }, { pathLen: 1 }],
      [
        "EKU wider than the request",
        { pathLen: 0, extendedKeyUsages: [EKU.serverAuth] },
        { extendedKeyUsage: [EKU.serverAuth, EKU.clientAuth] },
      ],
      [
        "no EKU when one was requested",
        { pathLen: 0, extendedKeyUsages: [EKU.serverAuth] },
        {},
      ],
    ])("%s", async (_, requested, certificate) => {
      const { input } = await setup({ requested, certificate });
      expect(reasonOf(() => verifyActivationChain(input))).toBe(
        "constraints_broader",
      );
      const accepted = verifyActivationChain({
        ...input,
        acceptBroaderConstraints: true,
      });
      expect(accepted.broaderThanRequested).toBe(true);
    });

    it("treats a missing pathLen as broader", async () => {
      const root = await makeRoot();
      const key = await newKey();
      const ca = customCa(root, key, {
        replace: [EXT.basicConstraints],
        extensions: [
          extension(EXT.basicConstraints, true, basicConstraintsValue(true)),
        ],
      });
      const input: ActivationInput = {
        certificatePem: ca.pem,
        chainPem: root.pem,
        now: new Date(),
        caSpkiDer: key.spkiDer,
        requestedSubjectKey: buildCaSubject(subject).key,
        requested: { pathLen: 0 },
        deploymentName: "test",
      };
      expect(reasonOf(() => verifyActivationChain(input))).toBe(
        "constraints_broader",
      );
    });
  });

  describe("root checks", () => {
    it("requires exactly one certificate", async () => {
      const { input, root } = await setup();
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: root.pem + root.pem }),
        ),
      ).toBe("chain_multiple_blocks");
      expect(
        reasonOf(() => verifyActivationChain({ ...input, chainPem: "" })),
      ).toBe("chain_malformed");
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...input,
            certificatePem: input.certificatePem + root.pem,
          }),
        ),
      ).toBe("certificate_multiple_blocks");
    });

    it("requires a self-signed root", async () => {
      const { input, intermediate } = await setup();
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: intermediate.pem }),
        ),
      ).toBe("root_not_self_signed");
      const key = await newKey();
      const forged = makeCert({
        key,
        subject: subjectDer({ CN: "Forged Root" }),
        extensions: rootExtensions(key),
        signedBy: await newKey(),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: forged.pem }),
        ),
      ).toBe("root_signature_invalid");
    });

    it("requires a valid root with CA basics", async () => {
      const { input } = await setup();
      const expired = await makeRoot({
        notBefore: new Date(Date.now() - days(400)),
        notAfter: new Date(Date.now() - days(1)),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: expired.pem }),
        ),
      ).toBe("root_not_valid");
      const notCa = await makeRoot({
        extensions: (key) => [
          extension(EXT.basicConstraints, true, basicConstraintsValue(false)),
          skiExtension(key),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: notCa.pem }),
        ),
      ).toBe("root_not_ca");
      const noCrlSign = await makeRoot({
        extensions: (key) => [
          extension(EXT.basicConstraints, true, basicConstraintsValue(true)),
          extension(EXT.keyUsage, true, keyUsageValue(["keyCertSign"])),
          skiExtension(key),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: noCrlSign.pem }),
        ),
      ).toBe("root_key_usage");
      const noSki = await makeRoot({
        extensions: () => [
          extension(EXT.basicConstraints, true, basicConstraintsValue(true)),
          extension(
            EXT.keyUsage,
            true,
            keyUsageValue(["keyCertSign", "cRLSign"]),
          ),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: noSki.pem }),
        ),
      ).toBe("root_missing_ski");
    });

    it("refuses a root whose subject is outside the restricted form", async () => {
      const { input } = await setup();
      const accented = await makeRoot({ subject: { CN: "Placeholder" } });
      // Rebuild with a non-ASCII subject, which Hemlig's own builder refuses.
      const key = await newKey();
      const nonAscii = makeCert({
        key,
        subject: encodeName([{ oid: "2.5.4.3", value: "Rót", kind: "utf8" }]),
        extensions: rootExtensions(key),
      });
      expect(accented.pem).toBeDefined();
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: nonAscii.pem }),
        ),
      ).toBe("issuer_name_unsupported");
      const multi = makeCert({
        key,
        subject: seq(
          tlv(
            0x31,
            seq(oid("2.5.4.10"), tlv(0x0c, Buffer.from("A"))),
            seq(oid("2.5.4.3"), tlv(0x0c, Buffer.from("B"))),
          ),
        ),
        extensions: rootExtensions(key),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: multi.pem }),
        ),
      ).toBe("issuer_name_unsupported");
    });

    it("refuses name constraints on the root", async () => {
      const { input } = await setup();
      const constrained = await makeRoot({
        extensions: (key) => [
          ...rootExtensions(key),
          extension(
            EXT.nameConstraints,
            true,
            tlv(
              0x30,
              tlv(
                0xa0,
                tlv(0x30, tlv(0x30, tlv(0x82, Buffer.from("example.com")))),
              ),
            ),
          ),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...input, chainPem: constrained.pem }),
        ),
      ).toBe("root_name_constraints_unsupported");
    });
  });

  describe("CA certificate checks", () => {
    it("requires the root to have signed it, with a matching issuer and AKI", async () => {
      const s = await setup();
      const other = await makeRoot({ subject: { CN: "Other Root" } });
      const wrongSigner = customCa(s.root, s.key, {
        signedBy: await newKey("ECDSA_P384"),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            certificatePem: wrongSigner.pem,
          }),
        ),
      ).toBe("signature_invalid");
      // Issued by a different root, presented with this root as the chain.
      const fromOther = customCa(other, s.key, {});
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: fromOther.pem }),
        ),
      ).toBe("issuer_mismatch");
      const wrongAki = customCa(s.root, s.key, {
        replace: [EXT.authorityKeyIdentifier],
        extensions: [
          extension(
            EXT.authorityKeyIdentifier,
            false,
            authorityKeyIdentifierValue(Buffer.alloc(20, 7)),
          ),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: wrongAki.pem }),
        ),
      ).toBe("aki_mismatch");
      const noAki = customCa(s.root, s.key, {
        replace: [EXT.authorityKeyIdentifier],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: noAki.pem }),
        ),
      ).toBe("missing_aki");
    });

    it("requires BasicConstraints to be critical", async () => {
      const s = await setup();
      const ca = customCa(s.root, s.key, {
        replace: [EXT.basicConstraints],
        extensions: [
          extension(
            EXT.basicConstraints,
            false,
            basicConstraintsValue(true, 0),
          ),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: ca.pem }),
        ),
      ).toBe("basic_constraints_not_critical");
    });

    it("refuses a root whose pathLen leaves no room for an intermediate", async () => {
      const s = await setup();
      const zero = await makeRoot({
        extensions: (key) => [
          extension(EXT.basicConstraints, true, basicConstraintsValue(true, 0)),
          extension(
            EXT.keyUsage,
            true,
            keyUsageValue(["keyCertSign", "cRLSign"]),
          ),
          skiExtension(key),
        ],
      });
      const ca = await makeIntermediate(zero, { key: s.key, subject });
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            chainPem: zero.pem,
            certificatePem: ca.pem,
          }),
        ),
      ).toBe("root_path_len");
      const one = await makeRoot({
        extensions: (key) => [
          extension(EXT.basicConstraints, true, basicConstraintsValue(true, 1)),
          extension(
            EXT.keyUsage,
            true,
            keyUsageValue(["keyCertSign", "cRLSign"]),
          ),
          skiExtension(key),
        ],
      });
      const ok = await makeIntermediate(one, { key: s.key, subject });
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            chainPem: one.pem,
            certificatePem: ok.pem,
          }),
        ),
      ).toBeUndefined();
    });

    it("refuses a negative pathLen", async () => {
      const s = await setup();
      // BasicConstraints { cA TRUE, pathLenConstraint -1 }
      expect(() =>
        customCa(s.root, s.key, {
          replace: [EXT.basicConstraints],
          extensions: [
            extension(
              EXT.basicConstraints,
              true,
              Buffer.from("30060101ff0201ff", "hex"),
            ),
          ],
        }),
      ).toThrow();
    });

    it("requires the SPKI to be the CA key and an SKI", async () => {
      const s = await setup();
      const otherKey = await newKey();
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, caSpkiDer: otherKey.spkiDer }),
        ),
      ).toBe("spki_mismatch");
      const noSki = customCa(s.root, s.key, {
        replace: [EXT.subjectKeyIdentifier],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: noSki.pem }),
        ),
      ).toBe("missing_ski");
    });

    it("requires cA=true, keyCertSign and cRLSign, and 30 days of validity", async () => {
      const s = await setup();
      const notCa = customCa(s.root, s.key, {
        replace: [EXT.basicConstraints],
        extensions: [
          extension(EXT.basicConstraints, true, basicConstraintsValue(false)),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: notCa.pem }),
        ),
      ).toBe("not_ca");
      const noCrlSign = customCa(s.root, s.key, {
        replace: [EXT.keyUsage],
        extensions: [
          extension(EXT.keyUsage, true, keyUsageValue(["keyCertSign"])),
        ],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: noCrlSign.pem }),
        ),
      ).toBe("key_usage");
      const short = customCa(s.root, s.key, {
        notAfter: new Date(Date.now() + days(29)),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: short.pem }),
        ),
      ).toBe("validity_too_short");
      const early = customCa(s.root, s.key, {
        notBefore: new Date(Date.now() + hours(1)),
        notAfter: new Date(Date.now() + days(400)),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: early.pem }),
        ),
      ).toBe("not_yet_valid");
      const enough = customCa(s.root, s.key, {
        notAfter: new Date(Date.now() + days(31)),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: enough.pem }),
        ),
      ).toBeUndefined();
    });

    it("requires a restricted subject that matches the request", async () => {
      const s = await setup();
      const other = customCa(s.root, s.key, {
        subject: subjectDer({ O: "Test Corp", CN: "Another CA" }),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: other.pem }),
        ),
      ).toBe("subject_mismatch");
      const nonAscii = customCa(s.root, s.key, {
        subject: encodeName([
          { oid: "2.5.4.3", value: "Café CA", kind: "utf8" },
        ]),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: nonAscii.pem }),
        ),
      ).toBe("ca_subject_unsupported");
      const spaced = customCa(s.root, s.key, {
        subject: encodeName([
          { oid: "2.5.4.3", value: "Test  CA", kind: "utf8" },
        ]),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: spaced.pem }),
        ),
      ).toBe("ca_subject_unsupported");
      // PrintableString spelling and case differences canonicalize to the requested subject.
      const respelled = customCa(s.root, s.key, {
        subject: encodeName([
          { oid: "2.5.4.10", value: "TEST CORP", kind: "printable" },
          { oid: "2.5.4.3", value: "test issuing ca 1", kind: "printable" },
        ]),
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: respelled.pem }),
        ),
      ).toBeUndefined();
    });
  });

  describe("policy extensions and unknown critical extensions", () => {
    const policyOids = [
      EXT.policyConstraints,
      EXT.inhibitAnyPolicy,
      EXT.policyMappings,
    ];

    it.each(policyOids)(
      "rejects %s on the CA certificate, critical or not",
      async (policyOid) => {
        const s = await setup();
        for (const critical of [false, true]) {
          const ca = customCa(s.root, s.key, {
            extensions: [extension(policyOid, critical, seq())],
          });
          expect(
            reasonOf(() =>
              verifyActivationChain({ ...s.input, certificatePem: ca.pem }),
            ),
          ).toBe("policy_extension_present");
        }
      },
    );

    it("rejects policy extensions on the root", async () => {
      const s = await setup();
      const root = await makeRoot({
        extensions: (key) => [
          ...rootExtensions(key),
          extension(EXT.inhibitAnyPolicy, false, smallInteger(0)),
        ],
      });
      const ca = await makeIntermediate(root, { key: s.key, subject });
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            chainPem: root.pem,
            certificatePem: ca.pem,
          }),
        ),
      ).toBe("policy_extension_present");
    });

    it("rejects unrecognized critical extensions but tolerates non-critical ones", async () => {
      const s = await setup();
      const critical = customCa(s.root, s.key, {
        extensions: [extension("1.2.3.4.5", true, seq())],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: critical.pem }),
        ),
      ).toBe("unrecognized_critical_extension");
      const benign = customCa(s.root, s.key, {
        extensions: [extension("1.2.3.4.5", false, seq())],
      });
      expect(
        reasonOf(() =>
          verifyActivationChain({ ...s.input, certificatePem: benign.pem }),
        ),
      ).toBeUndefined();
    });
  });

  describe("identity root (layer 6)", () => {
    it("refuses a root or CA with the identity root subject, SPKI or fingerprint", async () => {
      const impostor = await makeRoot({
        subject: { CN: "Hemlig test Issuing Root" },
      });
      const key = await newKey();
      const ca = await makeIntermediate(impostor, { key, subject });
      const input: ActivationInput = {
        certificatePem: ca.pem,
        chainPem: impostor.pem,
        now: new Date(),
        caSpkiDer: key.spkiDer,
        requestedSubjectKey: buildCaSubject(subject).key,
        requested: { pathLen: 0 },
        deploymentName: "test",
      };
      expect(reasonOf(() => verifyActivationChain(input))).toBe(
        "identity_root_reserved",
      );
      expect(identityRootSubjectKey("test")).toBe(
        buildCaSubject({ CN: "Hemlig test Issuing Root" }).key,
      );

      const s = await setup();
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            identity: { spkiSha256: s.root.cert.spkiSha256 },
          }),
        ),
      ).toBe("identity_root_reserved");
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            identity: { fingerprint: s.intermediate.cert.fingerprint },
          }),
        ),
      ).toBe("identity_root_reserved");
      expect(
        reasonOf(() =>
          verifyActivationChain({
            ...s.input,
            identity: { spkiSha256: "other" },
          }),
        ),
      ).toBeUndefined();
    });
  });
});

describe("leaf lifetime clamping", () => {
  const now = new Date("2026-11-22T12:00:00.750Z");
  const base = {
    now,
    requestedSeconds: 90 * 86_400,
    ceilingsSeconds: [397 * 86_400],
    caNotBefore: new Date("2026-10-01T00:00:00Z"),
    chainNotAfters: [
      new Date("2028-10-01T00:00:00Z"),
      new Date("2040-01-01T00:00:00Z"),
    ],
  };

  it("starts 60 seconds ago and does not clamp when everything fits", () => {
    const validity = computeLeafValidity(base);
    expect(validity.notBefore.toISOString()).toBe("2026-11-22T11:59:00.000Z");
    expect(validity.notAfter.toISOString()).toBe("2027-02-20T11:59:00.000Z");
    expect(validity.durationSeconds).toBe(90 * 86_400);
    expect(validity).toMatchObject({ clamped: false, limitedByChain: false });
  });

  it("clamps to the lowest ceiling", () => {
    const validity = computeLeafValidity({
      ...base,
      ceilingsSeconds: [397 * 86_400, 30 * 86_400, 60 * 86_400],
    });
    expect(validity.durationSeconds).toBe(30 * 86_400);
    expect(validity).toMatchObject({ clamped: true, limitedByChain: false });
  });

  it("never outlives the chain", () => {
    const validity = computeLeafValidity({
      ...base,
      chainNotAfters: [
        new Date("2026-12-01T00:00:00Z"),
        new Date("2040-01-01T00:00:00Z"),
      ],
    });
    expect(validity.notAfter.toISOString()).toBe("2026-12-01T00:00:00.000Z");
    expect(validity).toMatchObject({ clamped: true, limitedByChain: true });
    expect(validity.durationSeconds).toBe(
      Math.floor(
        (Date.parse("2026-12-01T00:00:00Z") -
          Date.parse("2026-11-22T11:59:00Z")) /
          1000,
      ),
    );
  });

  it("does not report a chain limit when a ceiling is lower anyway", () => {
    const validity = computeLeafValidity({
      ...base,
      ceilingsSeconds: [5 * 86_400],
      chainNotAfters: [new Date("2026-12-01T00:00:00Z")],
    });
    expect(validity).toMatchObject({
      clamped: true,
      limitedByChain: false,
      durationSeconds: 5 * 86_400,
    });
  });

  it("starts no earlier than the CA certificate", () => {
    const validity = computeLeafValidity({
      ...base,
      caNotBefore: new Date("2026-11-22T11:59:50Z"),
    });
    expect(validity.notBefore.toISOString()).toBe("2026-11-22T11:59:50.000Z");
    expect(validity.notAfter.getTime() - validity.notBefore.getTime()).toBe(
      90 * 86_400_000,
    );
  });

  it("reports a non-positive duration when the chain has expired, leaving the denial to the policy", () => {
    const validity = computeLeafValidity({
      ...base,
      chainNotAfters: [new Date("2026-11-01T00:00:00Z")],
    });
    expect(validity.durationSeconds).toBeLessThanOrEqual(0);
    expect(validity.limitedByChain).toBe(true);
  });

  it("finds the earliest notAfter", () => {
    expect(
      earliestNotAfter([
        { notAfter: new Date(5000) },
        { notAfter: new Date(1000) },
        { notAfter: new Date(9000) },
      ]).getTime(),
    ).toBe(1000);
  });
});
