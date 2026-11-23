import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import { ApiError } from "../api/errors";
import ErrorNotice from "./ErrorNotice.vue";

const render = (error: ApiError) => mount(ErrorNotice, { props: { error } }).text();

describe("ErrorNotice PKI headlines", () => {
  it("explains a claimed subject name", () => {
    const text = render(
      new ApiError(409, "ca_subject_in_use", "taken", "c", undefined, {
        reason: "subject_in_use",
      }),
    );
    expect(text).toContain("Subject names are never reused");
    expect(text).toContain("Reason: subject_in_use");
  });

  it("does not blame the idempotency key for name_in_use", () => {
    const text = render(
      new ApiError(409, "conflict", "name taken", "c", undefined, { reason: "name_in_use" }),
    );
    expect(text).toContain("CA name is already taken");
    expect(text.toLowerCase()).not.toContain("idempotency");
  });

  it("keeps the idempotency headline for a bare conflict", () => {
    expect(render(new ApiError(409, "conflict", "x", "c"))).toContain(
      "idempotency key was already used",
    );
    expect(
      render(
        new ApiError(409, "conflict", "x", "c", undefined, {
          reason: "idempotency_key_reused",
        }),
      ),
    ).toContain("idempotency key was already used");
  });

  it("gives other conflicts a generic state headline", () => {
    const text = render(
      new ApiError(409, "conflict", "x", "c", undefined, { reason: "something_else" }),
    );
    expect(text).toContain("conflicts with the current state");
    expect(text.toLowerCase()).not.toContain("idempotency");
  });

  it("names the missing PKI role and omits the gateway guidance", () => {
    const text = render(
      new ApiError(403, "forbidden", "no", "c", undefined, {
        reason: "pki_role_required",
        role: "ca-administrator",
      }),
    );
    expect(text).toContain("lacks the PKI ca-administrator role");
    expect(text).not.toContain("API Gateway authorizer");
    expect(text).not.toContain("rejected a token the gateway accepted");
  });

  it("keeps the gateway guidance for a plain forbidden", () => {
    expect(render(new ApiError(403, "forbidden", "no", "c"))).toContain(
      "API Gateway authorizer",
    );
  });

  it("shows the retry delay", () => {
    const text = render(
      new ApiError(429, "issuance_rate_limited", "slow", "c", undefined, undefined, 30),
    );
    expect(text).toContain("Issuance is rate limited");
    expect(text).toContain("Retry after 30 seconds");
  });

  it("puts the reason in the CA and chain headlines", () => {
    expect(
      render(new ApiError(409, "ca_not_active", "x", "c", undefined, { reason: "retired" })),
    ).toContain("The CA is not active (retired)");
    expect(
      render(
        new ApiError(400, "chain_invalid", "x", "c", undefined, {
          reason: "constraints_broader",
        }),
      ),
    ).toContain("refused (constraints_broader)");
  });

  it("renders the path and denied name but no other detail", () => {
    const text = render(
      new ApiError(403, "issuance_denied", "denied", "c", undefined, {
        reason: "name_not_permitted",
        path: "dnsNames[0]",
        deniedName: "evil.example.com",
        secretish: "hunter2",
      }),
    );
    expect(text).toContain("dnsNames[0]");
    expect(text).toContain("evil.example.com");
    expect(text).not.toContain("hunter2");
  });
});
