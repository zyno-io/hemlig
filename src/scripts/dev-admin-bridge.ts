import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { handler as auditQueryHandler } from "../handlers/audit-query";
import { handler as adminHandler } from "../handlers/admin";

const port = Number.parseInt(process.env.DEV_BRIDGE_PORT ?? "5274", 10);
const origin = process.env.DEV_BRIDGE_ORIGIN ?? "http://127.0.0.1:5273";
const endpoint = process.env.AWS_ENDPOINT_URL;

/**
 * Local development only. MiniStack provides DynamoDB, S3, and KMS but no API
 * Gateway and no identity provider, so the console cannot obtain a real token
 * or reach a deployed route. This bridge maps an HTTP request onto the payload
 * format 2.0 event the admin handler expects and invokes it in process,
 * against whatever AWS endpoint the environment points at.
 *
 * It fabricates the JWT authorizer claims that API Gateway would normally have
 * validated. That is exactly the control this bypasses, which is why it binds
 * to loopback, refuses to start against a non-local AWS endpoint, and is never
 * bundled into a Lambda or the published construct.
 */
const readBody = async (request: IncomingMessage): Promise<string> => {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
};

const corsHeaders = (): Record<string, string> => ({
  "access-control-allow-origin": origin,
  "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
  "access-control-allow-headers":
    "authorization,content-type,idempotency-key,if-match,x-hemlig-dev-subject",
  "access-control-expose-headers": "etag",
  "access-control-max-age": "600",
  vary: "origin",
});

const buildServer = () =>
  createServer((request: IncomingMessage, response: ServerResponse) => {
    void (async () => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      const method = request.method ?? "GET";

      // Mirrors the deployed unauthenticated preflight route.
      if (method === "OPTIONS") {
        response.writeHead(204, corsHeaders());
        response.end();
        return;
      }

      const subject =
        (request.headers["x-hemlig-dev-subject"] as string | undefined) ??
        "local-administrator";
      const headers: Record<string, string> = {};
      for (const [name, value] of Object.entries(request.headers)) {
        if (typeof value === "string") {
          headers[name.toLowerCase()] = value;
        }
      }
      const body = await readBody(request);

      const event = {
        version: "2.0",
        routeKey: "$default",
        rawPath: url.pathname,
        rawQueryString: url.search.replace(/^\?/, ""),
        headers,
        queryStringParameters: Object.fromEntries(url.searchParams.entries()),
        requestContext: {
          accountId: "000000000000",
          apiId: "dev-bridge",
          domainName: "localhost",
          domainPrefix: "localhost",
          http: {
            method,
            path: url.pathname,
            protocol: "HTTP/1.1",
            sourceIp: request.socket.remoteAddress ?? "127.0.0.1",
            userAgent: headers["user-agent"] ?? "dev-bridge",
          },
          requestId: crypto.randomUUID(),
          routeKey: "$default",
          stage: "$default",
          time: new Date().toISOString(),
          timeEpoch: Date.now(),
          // Claims API Gateway would have validated. The handler re-checks them
          // against its own configuration, so these must match the environment.
          authorizer: {
            jwt: {
              claims: {
                iss: process.env.ADMIN_JWT_ISSUER ?? "",
                aud: process.env.ADMIN_JWT_AUDIENCE ?? "",
                sub: subject,
                ...(process.env.ADMIN_JWT_SCOPE === undefined
                  ? {}
                  : { scope: process.env.ADMIN_JWT_SCOPE }),
              },
              scopes: null,
            },
          },
        },
        body: body.length === 0 ? undefined : body,
        isBase64Encoded: false,
      } as unknown as APIGatewayProxyEventV2;

      try {
        // The deployed HTTP API routes this exact path to a distinct
        // archive-read Lambda. Keep the local bridge faithful so the console's
        // Audit page can be exercised against MiniStack too.
        const result =
          url.pathname === "/v1/admin/audit"
            ? await auditQueryHandler(event)
            : await adminHandler(event);
        const status = result.statusCode ?? 200;
        response.writeHead(status, {
          ...corsHeaders(),
          ...(result.headers as Record<string, string> | undefined),
        });
        response.end(result.body ?? "");
        process.stdout.write(`${method} ${url.pathname} -> ${status}\n`);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        response.writeHead(500, {
          ...corsHeaders(),
          "content-type": "application/json",
        });
        response.end(
          JSON.stringify({
            error: {
              code: "internal_error",
              message,
              correlationId: "dev-bridge",
            },
          }),
        );
        process.stdout.write(`${method} ${url.pathname} -> 500 ${message}\n`);
      }
    })();
  });

export const startBridge = (): void => {
  if (
    endpoint === undefined ||
    !/^https?:\/\/(127\.0\.0\.1|localhost|\[::1\])/.test(endpoint)
  ) {
    throw new Error(
      "AWS_ENDPOINT_URL must point at a local MiniStack. Refusing to bridge unauthenticated administrator requests to a remote account.",
    );
  }
  buildServer().listen(port, "127.0.0.1", () => {
    process.stdout.write(
      `Hemlig dev admin bridge on http://127.0.0.1:${port} (console origin ${origin})\n` +
        "Authentication is bypassed. Local MiniStack use only.\n",
    );
  });
};
