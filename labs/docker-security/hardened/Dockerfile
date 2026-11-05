# HARDENED counterpart for labs/docker-security.
#
# Build stage: pinned toolchain image (tag + digest). The digest is the index
# digest observed locally via `docker images --digests` when this lab was built.
FROM golang:1.27-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS build
# GOTOOLCHAIN=local forbids silent toolchain downloads during the build.
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS="-trimpath -buildvcs=false"
WORKDIR /src
COPY go.mod main.go ./
RUN go build -ldflags="-s -w" -o /out/posture .

# Runtime stage: static, no shell, no package manager, non-root variant.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build --chmod=0555 /out/posture /app/posture
USER 65532:65532
EXPOSE 8080
# The image has no shell or curl, so the probe is the binary itself. Defined here
# (not only in Compose) so the check travels with the image.
HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=3 \
  CMD ["/app/posture", "healthcheck"]
# Exec form: the app is PID 1 and receives SIGTERM directly.
ENTRYPOINT ["/app/posture"]
CMD ["serve"]
