import {
  caKeyUnavailable,
  chainInvalid,
  crlInvalid,
  csrInvalid,
  deniedNameFields,
  issuanceDenied,
} from "./errors";

describe("PKI errors", () => {
  it.each([
    ["chainInvalid", chainInvalid],
    ["crlInvalid", crlInvalid],
    ["issuanceDenied", issuanceDenied],
    ["csrInvalid", csrInvalid],
  ])("%s carries its reason as details and safeReason", (_name, factory) => {
    const error = factory("some_reason");
    expect(error.safeReason).toBe("some_reason");
    expect(error.details).toEqual({ reason: "some_reason" });
  });

  it("caKeyUnavailable is a 409", () => {
    const error = caKeyUnavailable();
    expect(error.statusCode).toBe(409);
    expect(error.code).toBe("ca_key_unavailable");
    expect(error.safeReason).toBe("ca_key_unavailable");
  });

  describe("denied URI names", () => {
    it("strips userinfo, query and fragment", () => {
      expect(
        deniedNameFields({
          type: "uri",
          value: "https://user:pw@service.example:8443/path/a?access_token=abc#frag",
        }),
      ).toEqual({
        deniedNameType: "uri",
        deniedName: "https://service.example:8443/path/a",
      });
      const error = issuanceDenied("name_not_permitted", undefined, {
        type: "uri",
        value: "https://service.example/p?access_token=secret",
      });
      expect(JSON.stringify(error.details)).not.toContain("secret");
      expect(error.details?.deniedName).toBe("https://service.example/p");
    });

    it("omits a URI that does not parse", () => {
      expect(
        deniedNameFields({ type: "uri", value: "https://exa mple.com/?token=s" }),
      ).toEqual({});
      expect(deniedNameFields({ type: "uri", value: "not a uri?token=s" })).toEqual({});
    });

    it("leaves other names unchanged", () => {
      expect(deniedNameFields({ type: "dns", value: "a.example.com" })).toEqual({
        deniedNameType: "dns",
        deniedName: "a.example.com",
      });
    });
  });
});
