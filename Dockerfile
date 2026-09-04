ARG DOCKER_REGISTRY=docker.prod.nuke.benjamin-borbe.de:443
FROM ${DOCKER_REGISTRY}/golang:1.27.1 AS build
ARG BUILD_GIT_VERSION=dev
ARG BUILD_GIT_COMMIT=none
ARG BUILD_DATE=unknown
WORKDIR /workspace
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    --mount=type=bind,target=. \
    GOCACHE=/root/.cache/go-build \
    GOMODCACHE=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w" \
    -installsuffix cgo \
    -o /main
CMD ["/bin/bash"]

FROM ${DOCKER_REGISTRY}/golang:1.27.1 AS toolchain
# Go toolchain snapshot for the runtime: the watcher runs each repo's own
# `make vulncheck` + `make check`, whose scanners/linters mostly run via
# `go run tool@version` — the runtime needs a full Go toolchain.

FROM ${DOCKER_REGISTRY}/alpine:3.24 AS runtime
# Runtime toolchain: the watcher clones each consenting repo (git) and runs
# its own vuln gates (`make vulncheck` + `make check`). Most scanners/linters
# run via `go run tool@version` from the repo's Makefile — only trivy must be
# a system binary (the metrics lesson: trivy's dep-level scan catches
# indirect-dep vulns govulncheck misses). gcc + musl-dev: repo gates run
# `go test -race`, which requires cgo. gh + jq: repo gates shell out to them.
# No Claude CLI / npm / X11 headers: this service emits tasks, it does not
# create PRs or compile GUI libs — leaner than the github-update-go-agent image.
RUN apk --no-cache add ca-certificates curl bash git make gcc musl-dev github-cli jq \
 && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin v0.74.0 \
 && trivy --version
COPY --from=toolchain /usr/local/go /usr/local/go
ENV ZONEINFO=/zoneinfo.zip
COPY --from=toolchain /usr/local/go/lib/time/zoneinfo.zip /
ENV PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin

FROM runtime
ARG BUILD_GIT_VERSION=dev
ARG BUILD_GIT_COMMIT=none
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="github-vuln-watcher"
LABEL org.opencontainers.image.description="Go vuln-drift detection watcher: clones consenting repos, runs their vuln gates, emits github-update-go tasks"
LABEL org.opencontainers.image.vendor="Benjamin Borbe"
LABEL org.opencontainers.image.licenses="BSD-2-Clause"
LABEL org.opencontainers.image.source="https://github.com/bborbe/github-vuln-watcher"
LABEL org.opencontainers.image.documentation="https://github.com/bborbe/github-vuln-watcher"
LABEL org.opencontainers.image.version="${BUILD_GIT_VERSION}"
LABEL org.opencontainers.image.created="${BUILD_DATE}"
LABEL org.opencontainers.image.revision="${BUILD_GIT_COMMIT}"

COPY --from=build /main /main
ENV BUILD_GIT_VERSION=${BUILD_GIT_VERSION}
ENV BUILD_GIT_COMMIT=${BUILD_GIT_COMMIT}
ENV BUILD_DATE=${BUILD_DATE}
# Non-root: the runtime executes arbitrary gate scripts from cloned repos, so a
# compromised gate must not run as root. USER nobody (uid 65534) matches the k8s
# runAsUser/runAsNonRoot the Helm chart enforces. HOME points at /tmp because
# the k8s manifest mounts readOnlyRootFilesystem with only /tmp (emptyDir) and
# /data (PVC) writable — git and the go toolchain (GOCACHE/GOPATH) need a
# writable HOME.
ENV HOME=/tmp
USER nobody
ENTRYPOINT ["/main"]
