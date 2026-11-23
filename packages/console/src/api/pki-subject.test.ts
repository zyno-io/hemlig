import { describe, expect, it } from "vitest";
import {
  canonicalSubject,
  incrementTrailingInteger,
  restrictedValueProblem,
  rolloverSuggestion,
  subjectProblems,
} from "./pki-subject";

describe("canonicalSubject", () => {
  it("ignores case and collapses whitespace", () => {
    expect(canonicalSubject({ commonName: "Prod  Issuing CA 1", organization: "Acme" })).toBe(
      canonicalSubject({ commonName: "prod issuing ca 1", organization: "ACME" }),
    );
  });

  it("uses a fixed attribute order and skips blanks", () => {
    expect(canonicalSubject({ commonName: "x", country: "US", organization: "" })).toBe(
      canonicalSubject({ country: "us", commonName: "X" }),
    );
    expect(canonicalSubject({ commonName: "a" })).not.toBe(canonicalSubject({ commonName: "b" }));
  });
});

describe("incrementTrailingInteger", () => {
  it("increments and keeps padding", () => {
    expect(incrementTrailingInteger("prod-issuing-1")).toBe("prod-issuing-2");
    expect(incrementTrailingInteger("ca-09")).toBe("ca-10");
    expect(incrementTrailingInteger("ca-99")).toBe("ca-100");
    expect(incrementTrailingInteger("x")).toBeUndefined();
  });
});

describe("rolloverSuggestion", () => {
  it("increments both and falls back to -2 and ' 2'", () => {
    expect(rolloverSuggestion({ name: "ca-1", subject: { commonName: "CA 1" } })).toEqual({
      name: "ca-2",
      commonName: "CA 2",
    });
    expect(rolloverSuggestion({ name: "ca", subject: { commonName: "CA" } })).toEqual({
      name: "ca-2",
      commonName: "CA 2",
    });
  });
});

describe("restricted form", () => {
  it("flags the restricted-form violations", () => {
    expect(restrictedValueProblem("")).toBeDefined();
    expect(restrictedValueProblem("café")).toBeDefined();
    expect(restrictedValueProblem(" lead")).toBeDefined();
    expect(restrictedValueProblem("trail ")).toBeDefined();
    expect(restrictedValueProblem("do  uble")).toBeDefined();
    expect(restrictedValueProblem("fine value")).toBeUndefined();
  });

  it("requires a common name and a two-letter country for a ROOT", () => {
    expect(subjectProblems({}, "ROOT").commonName).toBeDefined();
    expect(subjectProblems({ commonName: "r", country: "USA" }, "ROOT").country).toBeDefined();
    expect(subjectProblems({ commonName: "r", country: "USA" }, "EXTERNAL_INTERMEDIATE").country).toBeUndefined();
    expect(subjectProblems({ commonName: "r", country: "us" }, "INTERMEDIATE")).toEqual({});
  });
});
