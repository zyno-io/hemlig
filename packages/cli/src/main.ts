#!/usr/bin/env node
import { runCli } from "./index";
import type { Writable } from "node:stream";

function writer(stream: Writable): (text: string) => Promise<void> {
  // Node emits an error event as well as invoking the write callback on a broken pipe.
  stream.on("error", () => {});
  return (text) =>
    new Promise<void>((resolve, reject) => {
      stream.write(text, (error) => (error ? reject(error) : resolve()));
    });
}

async function main(): Promise<void> {
  const exitCode = await runCli(process.argv.slice(2), {
    stdout: writer(process.stdout),
    stderr: writer(process.stderr),
  });
  process.exitCode = exitCode;
}

void main();
