FROM node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS build
WORKDIR /workspace
COPY . .
RUN corepack enable && yarn install --immutable && yarn workspaces foreach -A --topological run build

FROM node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53
WORKDIR /workspace
ENV NODE_ENV=production
COPY --from=build /workspace/node_modules ./node_modules
COPY --from=build /workspace/packages/client/package.json ./packages/client/package.json
COPY --from=build /workspace/packages/client/LICENSE ./packages/client/LICENSE
COPY --from=build /workspace/packages/client/dist ./packages/client/dist
COPY --from=build /workspace/packages/kubernetes-controller/package.json ./packages/kubernetes-controller/package.json
COPY --from=build /workspace/packages/kubernetes-controller/LICENSE ./packages/kubernetes-controller/LICENSE
COPY --from=build /workspace/packages/kubernetes-controller/LICENSE ./LICENSE
COPY --from=build /workspace/packages/kubernetes-controller/dist ./packages/kubernetes-controller/dist
# The Helm chart enforces runAsNonRoot.  Use the unprivileged account supplied
# by the official Node image. Its numeric UID lets Kubernetes verify that
# constraint from image metadata before it starts the container.
USER 1000
CMD ["node", "packages/kubernetes-controller/dist/main.js"]
