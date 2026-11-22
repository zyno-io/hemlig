import {
  caKeyUnavailable,
  chainInvalid,
  crlInvalid,
  csrInvalid,
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
});
