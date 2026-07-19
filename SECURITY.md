# Security Policy

## Supported state

This repository is under migration review and is not release-ready.

## Security boundaries

- The Docker socket, exec, console, logs, and host statistics endpoints expose privileged host capabilities.
- Docker socket tokens require the exact `dockersocket` scope. Statistics tokens are bound to one `resourceId` or an explicit `containerIds` set; a token issued for another endpoint or resource fails closed.
- API credentials, JWT keys, proxy tokens, container metadata, and log data must never be written to public fixtures.
- Public keys generated for tests are ephemeral; real keys and certificates must not be committed.
- The vendored module graph is checksum-locked. Every package includes an exact module inventory and collected dependency legal files.
- Control-platform schema and collection URLs must remain on the configured origin. Redirects across origins, unbounded response bodies, URL credentials, and unsupported proxy schemes are rejected.
- Debug logging records sizes and identifiers, not proxied headers, bodies, credentials, or query tokens.
- `Dockerfile.dapper` is a local build-and-test image, not a runtime image. Its privileged root process is limited to starting a disposable inner Docker daemon; the harness does not mount the host Docker socket. Never publish or deploy this image as a service.
- Source and release artifacts must have no secret or High/Critical vulnerability findings. The build-only image must also have no secrets, no fixable High/Critical findings, and no unfixed High/Critical findings outside Ubuntu's `linux-libc-dev` package. Unfixed `linux-libc-dev` findings remain visible in the evidence because kernel headers are required for compilation but are not included in the release artifact; the gate fails as soon as Trivy reports a fixed version so the snapshot must be upgraded.
- The security gate records full race-test coverage and enforces minimum total and security-function coverage before an artifact can pass review.

## Reporting

Report suspected vulnerabilities through this repository's private security advisory channel. Do not include live credentials, keys, or production node data in a public issue.
