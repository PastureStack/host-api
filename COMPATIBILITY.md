# Compatibility Contract

Host API preserves established `/v1` and `/v2-beta` node endpoint paths, proxy-token requests, container event payloads, Docker labels, and generated client schemas.

Preferred settings use `platform-*` names. Historical `cattle-*` flags, legacy Docker labels, and established node data paths remain only as API or data contracts. They are not PastureStack branding. The archived generated control-platform client, archived event lock, archived Docker Engine API, and archived global configuration parser are no longer compiled or vendored.

Operator lifecycle messages support `en-US` and `zh-TW`. HTTP response bodies, log streams, statistics payloads, Docker output, identifiers, and protocol errors are not translated.

The current candidate is `0.38.4`, built with Go 1.26.5 on a digest-pinned Ubuntu 26.04 image and an exact Ubuntu package snapshot. Server packaging consumes `host-api-0.38.4.tar.gz`; its filename, executable layout, architecture, legacy SHA-1 compatibility files, and SHA-256 integrity files are release contracts. Product versions must remain pure numeric `MAJOR.MINOR.PATCH` values without branding or maintenance suffixes.

Before release, validate token acquisition, event forwarding, logs, stats, exec, console, Docker socket proxy, container proxy, disabled-proxy behavior, key parsing, and restart behavior.

The control-platform server must begin issuing the `dockersocket` scope and resource-bound statistics claims before this candidate is deployed. Allow previously issued short-lived tokens to expire, then deploy Host API enforcement. Reversing that order makes existing Docker socket and legacy statistics requests fail closed by design.
