# PastureStack Host API

Host API exposes node-local log, statistics, exec, console, Docker socket, container proxy, and event-forwarding endpoints used by compatible control-platform components.

PastureStack is an independent community effort to preserve, audit, and modernize the Rancher 1.6 ecosystem. It is not affiliated with or endorsed by Rancher Labs or SUSE.

**Upstream:** [`rancher/host-api`](https://github.com/rancher/host-api). This GitHub fork preserves upstream history, authorship, dates, tags, licenses, and bundled dependency notices; PastureStack maintenance is consolidated into one commit after the preserved upstream boundary.

## Project status

This is a migration proof of concept. The candidate uses a digest-pinned Ubuntu 26.04 build environment, Go 1.27.0, the current Docker client APIs, bounded control-platform responses, strict JWT claim handling, runtime-only test keys, and a reproducible package. Product-owned imports, settings, event-handler identifiers, and operator output use PastureStack naming. A manually dispatched GitHub security gate builds, race-tests, inventories, and scans the candidate; it does not publish or deploy anything.

## Configuration

Preferred flags are `--platform-url`, `--platform-access-key`, and `--platform-secret-key`. Existing `--cattle-*` flags remain compatibility aliases. Set `PASTURESTACK_HOME` for the state root and `PASTURESTACK_LOCALE=en-US` or `zh-TW` for operator messages. `host-api --version` reports the pure numeric `MAJOR.MINOR.PATCH` build version.

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
