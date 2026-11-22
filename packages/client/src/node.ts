import * as https from "node:https";
import {
  decodeTransportBody,
  type HemligTransport,
  type TransportRequest,
  type TransportResponse,
} from "./index";

/** Node-only mTLS transport. Import from `@zyno-io/hemlig-client/node`. */
export class NodeHttpsTransport implements HemligTransport {
  public constructor(private readonly options: https.AgentOptions = {}) {}

  public async request(request: TransportRequest): Promise<TransportResponse> {
    const body =
      request.body === undefined ? undefined : JSON.stringify(request.body);
    const headers: Record<string, string> = {
      accept:
        request.responseType === "binary"
          ? "application/pkix-crl, application/json"
          : "application/json",
      ...request.headers,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      headers["content-length"] = String(Buffer.byteLength(body));
    }
    return new Promise((resolve, reject) => {
      const response = https.request(
        request.url,
        { method: request.method, headers, ...this.options },
        (incoming) => {
          const chunks: Buffer[] = [];
          incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
          incoming.on("error", reject);
          incoming.on("end", () => {
            const responseHeaders: Record<string, string | undefined> = {};
            for (const [name, value] of Object.entries(incoming.headers)) {
              responseHeaders[name] = Array.isArray(value)
                ? value.join(",")
                : value;
            }
            const status = incoming.statusCode ?? 500;
            const decoded = decodeTransportBody(
              status,
              responseHeaders,
              Buffer.concat(chunks),
              request.responseType,
            );
            resolve({ status, headers: responseHeaders, ...decoded });
          });
        },
      );
      response.on("error", reject);
      if (body !== undefined) {
        response.write(body);
      }
      response.end();
    });
  }
}
