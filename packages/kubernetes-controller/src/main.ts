#!/usr/bin/env node
import {
  HemligV1BetaController,
  v1BetaControllerConfigFromEnvironment,
} from "./v1beta";

const controller = HemligV1BetaController.fromDefaultConfig(
  v1BetaControllerConfigFromEnvironment(),
);
const abort = new AbortController();
process.once("SIGTERM", () => abort.abort());
process.once("SIGINT", () => abort.abort());

void controller.run(abort.signal).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
