import assert from "node:assert/strict";
import * as net from "node:net";
import test from "node:test";
import forge from "node-forge";
import { agentClient } from "../v1beta";

const selfSigned = (): { cert: Buffer; key: Buffer } => {
  const pair = forge.pki.rsa.generateKeyPair({ bits: 1024, e: 0x10001 });
  const cert = forge.pki.createCertificate();
  cert.publicKey = pair.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 3_600_000);
  const subject = [{ name: "commonName", value: "test" }];
  cert.setSubject(subject);
  cert.setIssuer(subject);
  cert.sign(pair.privateKey, forge.md.sha256.create());
  return {
    cert: Buffer.from(forge.pki.certificateToPem(cert)),
    key: Buffer.from(forge.pki.privateKeyToPem(pair.privateKey)),
  };
};

test("a stalled PKI call is aborted at the transport, closing its socket", async () => {
  let markClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    markClosed = resolve;
  });
  // Accepts the connection and never answers.
  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    // Read, so that the peer's close is observed.
    socket.resume();
    socket.on("close", markClosed);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address() as net.AddressInfo;
    const { cert, key } = selfSigned();
    const client = agentClient(`https://127.0.0.1:${port}`, cert, key, 100);
    await assert.rejects(client.getCaBundle("ca-aaa"));
    await closed;
  } finally {
    server.close();
  }
});
