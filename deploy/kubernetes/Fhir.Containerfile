FROM docker.io/library/node:26.10.0-bookworm-slim@sha256:662933cf47f013bc8e4beb31a6116448427a82057ba7c42c97e4c5ba766504c2 AS build
WORKDIR /bridge
COPY mcp-spiffe-bridge/package.json mcp-spiffe-bridge/pnpm-lock.yaml mcp-spiffe-bridge/pnpm-workspace.yaml ./
RUN npm install --global pnpm@12.10.1 && pnpm install --frozen-lockfile
COPY mcp-spiffe-bridge/src src
COPY mcp-spiffe-bridge/tsconfig.json mcp-spiffe-bridge/tsup.config.ts ./
RUN pnpm build && pnpm prune --prod
WORKDIR /fhir
COPY hipaa-fhir-mcp/package.json hipaa-fhir-mcp/pnpm-lock.yaml ./
RUN npm install --global pnpm@10.33.2 && pnpm install --frozen-lockfile
COPY hipaa-fhir-mcp/src src
COPY hipaa-fhir-mcp/tsconfig.json ./
RUN pnpm build && pnpm prune --prod

FROM docker.io/library/node:26.10.0-bookworm-slim@sha256:662933cf47f013bc8e4beb31a6116448427a82057ba7c42c97e4c5ba766504c2
COPY --from=build /bridge /bridge
COPY --from=build /fhir /fhir
COPY hipaa-fhir-mcp/deploy/kubernetes/fhir-gateway.mjs /lab/fhir-gateway.mjs
COPY mcp-svid-auth/deploy/kubernetes/token-verifier.mjs /lab/token-verifier.mjs
USER 1000:1000
ENTRYPOINT ["node", "/lab/fhir-gateway.mjs"]
