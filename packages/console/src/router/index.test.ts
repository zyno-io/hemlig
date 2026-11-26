import { describe, expect, it } from "vitest";
import { createAppRouter } from "./index";

describe("secret routes", () => {
  it("preserves every slash-separated secret ID segment before a subpage", () => {
    const router = createAppRouter();
    const route = router.resolve(
      "/e/dev/secrets/payments/stripe/api-key/payload",
    );

    expect(route.name).toBe("secret-payload");
    expect(route.params).toMatchObject({
      env: "dev",
      secretId: "payments/stripe/api-key",
    });
  });

  it("registers /cli-login as an ordinary route that App.vue gates behind sign-in", () => {
    const route = createAppRouter().resolve("/cli-login?port=40000&state=x");

    expect(route.name).toBe("cli-login");
    expect(route.query).toMatchObject({ port: "40000", state: "x" });
  });
});

const propsFor = (path: string): Record<string, unknown> => {
  const route = createAppRouter().resolve(path);
  const record = route.matched[route.matched.length - 1];
  const raw = record?.props.default;
  if (typeof raw === "function") {
    return (raw as (r: unknown) => unknown)(route) as Record<string, unknown>;
  }
  return route.params;
};

describe("PKI routes", () => {
  const nameOf = (path: string): unknown => createAppRouter().resolve(path).name;

  it("resolves the overview", () => {
    expect(nameOf("/e/prod/pki")).toBe("pki");
    expect(propsFor("/e/prod/pki")).toMatchObject({ env: "prod" });
    expect(propsFor("/e/prod/pki").tab).toBeUndefined();
  });

  it("resolves cas/new to the create route, not a CA called new", () => {
    expect(nameOf("/e/prod/pki/cas/new")).toBe("pki-ca-new");
    expect(nameOf("/e/prod/pki/cas/ca-abc")).toBe("pki-ca");
  });

  it("passes the PKI page tab only when it is cas or certificates", () => {
    expect(propsFor("/e/prod/pki?tab=certificates")).toMatchObject({
      env: "prod",
      tab: "certificates",
    });
    expect(propsFor("/e/prod/pki?tab=cas").tab).toBe("cas");
    expect(propsFor("/e/prod/pki?tab=grants").tab).toBeUndefined();
    expect(propsFor("/e/prod/pki?tab=certificates&tab=cas").tab).toBeUndefined();
  });

  it("passes the CA tab only when it is one of the three", () => {
    expect(propsFor("/e/prod/pki/cas/ca-abc?tab=grants")).toMatchObject({
      env: "prod",
      caId: "ca-abc",
      tab: "grants",
    });
    expect(propsFor("/e/prod/pki/cas/ca-abc?tab=nope").tab).toBeUndefined();
    expect(propsFor("/e/prod/pki/cas/ca-abc").tab).toBeUndefined();
  });

  it("resolves the certificate route parameters", () => {
    const route = createAppRouter().resolve("/e/prod/pki/cas/ca-abc/certificates/0a1b");
    expect(route.name).toBe("pki-certificate");
    expect(route.params).toMatchObject({ env: "prod", caId: "ca-abc", serial: "0a1b" });
    expect(propsFor("/e/prod/pki/cas/ca-abc/certificates/0a1b")).toMatchObject({
      serial: "0a1b",
    });
  });

  it("accepts a rolloverFrom that starts with ca- and drops any other", () => {
    expect(propsFor("/e/prod/pki/cas/new?rolloverFrom=ca-abc")).toMatchObject({
      rolloverFrom: "ca-abc",
    });
    expect(propsFor("/e/prod/pki/cas/new?rolloverFrom=abc").rolloverFrom).toBeUndefined();
    expect(propsFor("/e/prod/pki/cas/new?rolloverFrom=").rolloverFrom).toBeUndefined();
  });

  it("accepts only the three CA kinds", () => {
    expect(propsFor("/e/prod/pki/cas/new?kind=ROOT").kind).toBe("ROOT");
    expect(propsFor("/e/prod/pki/cas/new?kind=EXTERNAL_INTERMEDIATE").kind).toBe(
      "EXTERNAL_INTERMEDIATE",
    );
    expect(propsFor("/e/prod/pki/cas/new?kind=LEAF").kind).toBeUndefined();
  });

  it("keeps a grant named new reachable", () => {
    const route = createAppRouter().resolve("/e/prod/consumers/c1/issuance-grants/new");
    expect(route.name).toBe("consumer-pki-grant");
    expect(route.params).toMatchObject({ consumerId: "c1", name: "new" });
  });

  it("resolves the create path and takes caId from the query", () => {
    const path = "/e/prod/consumers/c1/new-issuance-grant?caId=ca-abc";
    expect(nameOf(path)).toBe("consumer-pki-grant-new");
    expect(propsFor(path)).toMatchObject({ env: "prod", consumerId: "c1", caId: "ca-abc" });
  });

  it("passes the consumer tab from the query", () => {
    expect(propsFor("/e/prod/consumers/c1?tab=certificate-grants")).toMatchObject({
      env: "prod",
      consumerId: "c1",
      tab: "certificate-grants",
    });
    expect(propsFor("/e/prod/consumers/c1?tab=x").tab).toBeUndefined();
    expect(nameOf("/e/prod/consumers/c1")).toBe("consumer");
  });
});
