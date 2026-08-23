import * as https from "node:https";
import type {
  HemligTransport,
  TransportRequest,
  TransportResponse,
} from "./index";

/** Node-only mTLS transport. Import from `@hemlig/client/node`. */
export class NodeHttpsTransport implements HemligTransport {
  public constructor(private readonly options: https.AgentOptions = {}) {}

  public async request(request: TransportRequest): Promise<TransportResponse> {
    const body = request.body === undefined ? undefined : JSON.stringify(request.body);
    const headers: Record<string, string> = {
      accept: "application/json",
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
            const text = Buffer.concat(chunks).toString("utf8");
            let parsed: unknown;
            try {
              parsed = text.length === 0 ? undefined : JSON.parse(text);
            } catch {
              parsed = undefined;
            }
            const responseHeaders: Record<string, string | undefined> = {};
            for (const [name, value] of Object.entries(incoming.headers)) {
              responseHeaders[name] = Array.isArray(value) ? value.join(",") : value;
            }
            resolve({ status: incoming.statusCode ?? 500, headers: responseHeaders, body: parsed });
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
