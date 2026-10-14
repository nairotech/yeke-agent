# The YEKE agent image.
#
# The installation manifest produced by the YEKE control plane points at this
# image; the image name can be overridden with `YEKE_AGENT_IMAGE`. If the
# manifest is to be genuinely applicable, the image has to be genuinely
# buildable — this file closes that gap.
#
# From the repository root:
#   docker build -t yeke-agent:0.1.0 .
#
# To load it into a local k3s (without a registry):
#   docker save yeke-agent:0.1.0 -o /tmp/agent.tar
#   docker cp /tmp/agent.tar <k3s-container>:/tmp/agent.tar
#   docker exec <k3s-container> ctr -n k8s.io images import /tmp/agent.tar

FROM node:24-alpine AS build
WORKDIR /app
RUN corepack enable

# The build context is this repository's root, and the manifest is copied on its
# own first so that the dependency layer is only rebuilt when the manifest or the
# lockfile changes.
#
# Until 2026-08-09 this block copied workspace fragments out of the product
# monorepo (`packages/tunnel/…` next to `apps/agent/…`) and the install was run
# with a `--filter`. Those lines are gone: the wire contract now arrives from the
# public registry as `@nairotech/yeke-tunnel`, pinned to an exact version. The
# day one of them reappears is the day this repository stopped being standalone —
# `src/boundary.test.ts` measures the same thing on the source side.
COPY package.json pnpm-lock.yaml ./

# `--frozen-lockfile`: let the content of the image be determined by
# `pnpm-lock.yaml`; if the lockfile and `package.json` have diverged, stop the
# build HERE. The flag matters most precisely here: the agent is the component
# installed into the customer's cluster, and the contract between it and the
# control plane is the tunnel protocol. An image silently produced with a
# different `ws` or `@kubernetes/client-node` would create exactly the class of
# error the protocol version gate (rejecting a mismatch with 1008) is there to
# prevent.
RUN pnpm install --frozen-lockfile --ignore-scripts

# The `COPY` lines are at file/subdirectory level, not whole-directory. A plain
# `COPY . .` would carry the host's `node_modules/` (pnpm symlinks whose targets
# do not exist in the image, i.e. broken) and `dist/` into the image.
# `.dockerignore` compensates for that today, but compensation is not the rule
# itself: the day a line falls out of the ignore list, the image would quietly
# start carrying host output.
COPY tsconfig.json ./
COPY src ./src
RUN pnpm build

# Drop devDependencies from the tree that gets copied into the runtime image.
# The build needs `typescript`/`tsx`; the running agent needs neither.
RUN pnpm prune --prod

# ─── Runtime stage ────────────────────────────────────────────────────────────
#
# The stage name `runtime` is a target, not a label: the product's release
# script rebuilds this stage without cache on every release
# (`--no-cache-filter runtime`, together with `--pull`) so that the image
# carries the Alpine patches of release day, while the build stage above keeps
# its cache. BuildKit silently ignores a `--no-cache-filter` naming a stage that
# does not exist (measured 2026-10-14), so the release script checks that the
# last `FROM` here is `AS runtime` and refuses to build otherwise.
FROM node:24-alpine AS runtime

# ─── Alpine patches up, package managers out (2026-10-14) ────────────────────
#
# Measured on the pre-release image scan (Trivy 0.76.0, 2026-10-14):
#
# - `apk upgrade --no-cache`: the image carried libssl3/libcrypto3 3.5.7-r0
#   (HIGH, fixed in 3.5.8-r0) because the cached `node:24-alpine` base was
#   built on 2026-09-09. Even the current Docker Hub tag is frozen at its own
#   build date, while the Alpine 3.24 repository already offered newer
#   libssl3/zlib on 2026-10-14. Pulling the base closes part of that gap;
#   upgrading here closes the rest. `node` itself is not an apk package in
#   the official image (it is `/usr/local/bin/node`), so this does not touch it.
# - npm, npx, corepack and yarn are removed: 8 HIGH findings sat under
#   `/usr/local/lib/node_modules/npm/node_modules/` (one of them,
#   http-cache-semantics, with no fixed version). That is the npm CLI bundled
#   by the base image; the agent never runs it — the entrypoint is
#   `node dist/index.js` and nothing at runtime spawns npm/npx/corepack/yarn.
#   The bytes stay in the base layer (layers only add); what goes away is the
#   files in the container's filesystem and the ability to run them. The
#   base's `YARN_VERSION` env var remains as a harmless leftover.
#
# The step stops loudly if `node` resolves into one of the deleted paths, then
# checks that no package manager is left on PATH and that `node --version`
# still works.
RUN set -eu; \
    apk upgrade --no-cache; \
    node_bin="$(readlink -f "$(command -v node)")"; \
    case "$node_bin" in \
      /usr/local/lib/node_modules/* | /opt/yarn-v*) \
        echo "node ($node_bin) lives under a path about to be deleted; refusing" >&2; exit 1 ;; \
    esac; \
    rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack /opt/yarn-v* \
      /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /usr/local/bin/yarn /usr/local/bin/yarnpkg; \
    for b in npm npx corepack yarn yarnpkg; do \
      if command -v "$b" >/dev/null 2>&1; then echo "$b is still on PATH: $(command -v "$b")" >&2; exit 1; fi; \
    done; \
    node --version

WORKDIR /app
COPY --from=build /app/package.json ./package.json
COPY --from=build /app/dist ./dist
COPY --from=build /app/node_modules ./node_modules

# ─── The release version enters the image HERE ───────────────────────────────
#
# The agent reports its own version to the control plane, and the user interface
# shows it on the cluster card. Until 2026-08-04 that value was a constant
# hand-written inside `tunnel-client.ts` (`"0.1.0"`) with no link at all to the
# release tag — an agent running 0.4.25 was introducing itself as 0.1.0.
#
# The only truth about the version is the image tag; that is why the value enters
# as a build argument and stays in the image's own environment. Without it the
# agent reports `"unknown"` (see `tunnel-client.ts`) — better than an invented
# number.
#
# Release command (passing the SAME value as the tag is mandatory; see "Lockstep"
# in README.md — the tag must equal the control plane's version):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --build-arg YEKE_VERSION=<version> \
#     -t nairotech/yeke-agent:<version> --push .
ARG YEKE_VERSION=""
ENV YEKE_VERSION=$YEKE_VERSION

# The manifest runs the pod with `runAsNonRoot: true` + `runAsUser: 65532`; the
# image default is the same so that it does not run as root when started outside
# the manifest either.
USER 65532:65532
ENTRYPOINT ["node", "dist/index.js"]
