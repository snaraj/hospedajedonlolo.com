# The build stages run natively on the build platform and cross-compile for
# each target; only the compile and the final stage are per-architecture.
# Nothing in this file reads build arguments other than the target platform,
# so the image is a pure function of the source tree.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.10-trixie@sha256:a050dcceee6eb9bf110151662dfac7662f3bec40927c7dee48731e3d92083d42 AS backend-source
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY site/ site/

# TESTS NEVER TOUCH WHAT SHIPS. The battery runs in a stage of its own. The
# stage that compiles the binary starts again from the source stage and
# copies only the battery's empty pass mark, so it still waits for every test
# to pass, while nothing a test does (a file it writes, a build-cache entry)
# can reach the binary. That is what lets the release classifier treat Go
# test files as no-artifact (scripts/ci/release_contract.py). The battery
# names no target, so both architectures share one run of it.
FROM backend-source AS backend-test
RUN go test ./... && touch /backend-tested

FROM backend-source AS backend
COPY --from=backend-test /backend-tested /backend-tested
ARG TARGETOS
ARG TARGETARCH
RUN GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w -buildid=" -o /out/hospedajedonlolo-com ./cmd/server

# Shell-less, package-manager-less, non-root. The photographs and film are a
# read-only volume mounted at run time and never part of this image.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329
COPY --from=backend --chown=65532:65532 /out/hospedajedonlolo-com /hospedajedonlolo-com
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/hospedajedonlolo-com"]
