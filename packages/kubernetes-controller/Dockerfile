FROM node:22-alpine AS build
WORKDIR /workspace
COPY . .
RUN corepack enable && yarn install --immutable && yarn workspaces foreach -A --topological run build

FROM node:22-alpine
WORKDIR /workspace
ENV NODE_ENV=production
COPY --from=build /workspace/node_modules ./node_modules
COPY --from=build /workspace/packages/client/package.json ./packages/client/package.json
COPY --from=build /workspace/packages/client/dist ./packages/client/dist
COPY --from=build /workspace/packages/kubernetes-controller/package.json ./packages/kubernetes-controller/package.json
COPY --from=build /workspace/packages/kubernetes-controller/dist ./packages/kubernetes-controller/dist
CMD ["node", "packages/kubernetes-controller/dist/main.js"]
