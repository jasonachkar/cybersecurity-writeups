# INSECURE BASELINE for labs/docker-security. Deliberately bad; do not reuse.
#
# Every choice below is a finding that tests/policy-check.js must report and that
# the runtime probe observes. See README.md "Control decisions" for the hardened
# counterpart of each line.

# Mutable tag, no digest: the base can change under an unchanged Dockerfile.
FROM golang:1.27-alpine

# Build toolchain, shell and package manager stay in the runtime image.
WORKDIR /src
COPY . .
RUN go build -o /usr/local/bin/posture . && chmod -R 777 /src

# Secret-shaped build-time config baked into image metadata (placeholder only).
ENV API_TOKEN=<placeholder-not-a-real-secret>

# No USER instruction: the process runs as uid 0.
# No HEALTHCHECK: orchestration cannot tell "running" from "serving".
EXPOSE 8080
# Shell form: PID 1 is /bin/sh -c, which does not forward SIGTERM to the app.
CMD posture serve
