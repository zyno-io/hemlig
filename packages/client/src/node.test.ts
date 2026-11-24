import assert from "node:assert/strict";
import * as net from "node:net";
import test from "node:test";
import { NodeHttpsTransport } from "./node";

// A TCP peer that accepts the connection and never answers: the TLS handshake cannot finish.
const silentServer = async (): Promise<{
  readonly port: number;
  readonly closed: Promise<void>;
  readonly stop: () => void;
}> => {
  let markClosed: () => void = () => {};
  const closed = new Promise<void>((resolve) => {
    markClosed = resolve;
  });
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    // Read, so that the peer's close is observed.
    socket.resume();
    socket.on("close", markClosed);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    port: (server.address() as net.AddressInfo).port,
    closed,
    stop: () => {
      server.close();
      for (const socket of sockets) socket.destroy();
    },
  };
};

test("timeoutMs destroys a stalled request and rejects with a transport error", { timeout: 30_000 }, async () => {
  const peer = await silentServer();
  try {
    const transport = new NodeHttpsTransport({ timeoutMs: 100 });
    const started = Date.now();
    await assert.rejects(
      transport.request({
        method: "GET",
        url: new URL(`https://127.0.0.1:${peer.port}/v1/ping`),
      }),
      (error: NodeJS.ErrnoException) => {
        assert.equal(error.code, "ETIMEDOUT");
        return true;
      },
    );
    assert.ok(Date.now() - started < 5_000);
    // The socket is closed, not left open behind the rejection.
    await peer.closed;
  } finally {
    peer.stop();
  }
});

test("without timeoutMs the options still reach https.request", () => {
  assert.doesNotThrow(() => new NodeHttpsTransport({ rejectUnauthorized: false }));
  assert.doesNotThrow(() => new NodeHttpsTransport());
});
