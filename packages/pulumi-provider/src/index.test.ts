import assert from "node:assert/strict";
import test from "node:test";
import { Provider } from "./index";

test("exports a Pulumi component provider", () => {
  assert.equal(typeof Provider, "function");
});
