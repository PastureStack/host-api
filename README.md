# PastureStack Host API

Host API exposes node-local log, statistics, exec, console, Docker socket, container proxy, and event-forwarding endpoints used by compatible control-platform components.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

## Capabilities

The source package version is `0.38.5`. Target-bound API Key tickets require matching Engine introspection at handshake and during logs, exec, and statistics streams. Revocation or expiry closes the stream; it does not stop its container or kill an already started exec process. Legacy and full-without-expiry tokens retain their authentication contract.

The authenticated backend connection declares the exact `key-audit-v1,key-delegation-v1` capabilities. A compatible Proxy requires that declaration for every verified API Key stream, including full keys, so an older embedded backend cannot bypass terminal audit. Ordinary non-Key streams retain their existing backend compatibility.

Terminal evidence is sent with the host agent's credential. A private persistent spool reserves a PENDING record before execution for every verified API Key trace, preserves the first terminal result, and retries only evidence after outages or process restarts. Interrupted PENDING streams become `CANCELLED`, never a fabricated success. Original API Key and agent secrets are not persisted. Full keys retain their permission payload and expiry contract, but do not bypass audit durability; unavailable admission closes with retryable `AuditUnavailable` (503 semantics), not a permission denial. Ordinary non-Key tokens have no new audit-admission requirement.

## Configuration

Preferred flags are `--platform-url`, `--platform-access-key`, and `--platform-secret-key`. Existing `--cattle-*` flags remain compatibility aliases. Set `PASTURESTACK_HOME` for the state root and `PASTURESTACK_LOCALE=en-US` or `zh-TW` for operator messages. `host-api --version` reports the pure numeric `MAJOR.MINOR.PATCH` build version.

Set `--completion-spool-dir` or `HOST_API_COMPLETION_SPOOL_DIR` to an absolute dedicated directory ending in `completion-spool` on the agent's persistent state mount, for example `/var/lib/rancher/state/host-api/completion-spool`. Without an override, the root is selected from `PASTURESTACK_STATE_DIR`, `CATTLE_STATE_DIR`, `PASTURESTACK_HOME`, `CATTLE_HOME`, then `/var/lib/pasturestack`. The directory is 0700 and ticket files are 0600; symlink paths, unsafe writable ancestors, other-owner Linux files, and public ticket files are refused. Capacity is bounded to 256 records and 4 MiB of reserved file space (32 KiB per record), with at most seven days of retention. A full or unavailable spool rejects new verified API Key streams rather than discarding their outcomes. Receiver audit retention may impose a shorter acceptance window.

Use the official versioned host-api package and its inner SHA256 manifests through the control platform's config-content installer. The matching Engine and WebSocket Proxy must support target-bound tickets; replacing only the proxy is insufficient.

## Build and test

From a Docker-capable Linux host:

```sh
make test
make build
make package
```

The test container starts its own disposable Docker daemon and creates minimal test images locally from the bundled static BusyBox binary. It does not mount the host Docker socket or pull mutable test images from a public registry. Packages include the root legal files, an exact Go module inventory, and each dependency's collected license or notice files.

See [COMPATIBILITY.md](COMPATIBILITY.md), [SECURITY.md](SECURITY.md), and [ORIGIN.md](ORIGIN.md).

## License and attribution

The inherited project remains licensed under [Apache License 2.0](LICENSE). Copyright and attribution for inherited work and vendored dependencies remain with their respective authors and contributors. PastureStack contributors claim authorship only for their own changes.
