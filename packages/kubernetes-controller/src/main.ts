#!/usr/bin/env node
import { HemligKubernetesController, controllerConfigFromEnvironment } from "./index";

const controller = HemligKubernetesController.fromDefaultConfig(
  controllerConfigFromEnvironment(),
);
const abort = new AbortController();
process.once("SIGTERM", () => abort.abort());
process.once("SIGINT", () => abort.abort());

void controller.run(abort.signal).catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.stack : String(error)}\n`);
  process.exitCode = 1;
});
