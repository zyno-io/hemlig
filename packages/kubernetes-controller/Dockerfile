ARG NODE_IMAGE=node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

FROM ${NODE_IMAGE} AS build
WORKDIR /workspace
COPY . .
# Build the controller and its workspace dependencies, then bundle it into one
# file so the runtime image needs no node_modules. Third-party license and
# notice files from the production dependency closure ship alongside it.
RUN corepack enable \
  && yarn install --immutable \
  && yarn workspaces foreach -R --topological \
    --from @zyno-io/hemlig-kubernetes-controller run build \
  && mkdir -p /out \
  && yarn esbuild packages/kubernetes-controller/dist/main.js \
    --bundle --platform=node --target=node24 --format=cjs \
    --minify-syntax --minify-whitespace --legal-comments=eof \
    --outfile=/out/main.js \
  && rm -rf node_modules packages/*/node_modules \
  && yarn workspaces focus --production @zyno-io/hemlig-kubernetes-controller \
  && find -L node_modules -mindepth 1 -type f \
    \( -iname 'licen[cs]e*' -o -iname 'notice*' -o -iname 'copying*' \) \
    -exec sh -c 'for f; do mkdir -p "/out/third-party/$(dirname "${f#node_modules/}")" && cp "$f" "/out/third-party/${f#node_modules/}"; done' sh {} + \
  && cp packages/kubernetes-controller/LICENSE /out/LICENSE

# The runtime is Alpine plus the Node binary and the two C++ runtime libraries
# it links against, all taken from the same pinned Node image. Leaving out npm,
# yarn and corepack keeps the image small and drops tooling the controller
# never runs.
FROM ${NODE_IMAGE} AS node

FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
COPY --from=node /usr/lib/libstdc++.so.6 /usr/lib/libgcc_s.so.1 /usr/lib/
COPY --from=node /usr/local/bin/node /usr/local/bin/node
# The Helm chart enforces runAsNonRoot. Use a numeric UID so Kubernetes can
# verify that constraint from image metadata before it starts the container.
RUN addgroup -g 1000 node && adduser -D -H -u 1000 -G node node
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /out/ ./
USER 1000
CMD ["node", "main.js"]
