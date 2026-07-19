TARGETS := build ci clean package release test validate
DAPPER_IMAGE ?= pasturestack-host-api-dapper:ubuntu26
DAPPER_SOURCE ?= /go/src/github.com/PastureStack/host-api

.dapper-image: Dockerfile.dapper
	docker build \
		--network "$${DOCKER_BUILD_NETWORK:-default}" \
		--build-arg DAPPER_HOST_ARCH=$${DAPPER_HOST_ARCH:-amd64} \
		-t $(DAPPER_IMAGE) \
		-f Dockerfile.dapper .

$(TARGETS): .dapper-image
	docker run --rm \
		--privileged \
		--cgroupns=host \
		-v $(CURDIR):$(DAPPER_SOURCE) \
		-e DAPPER_UID=$$(id -u) \
		-e DAPPER_GID=$$(id -g) \
		-e ARCH=$${ARCH:-amd64} \
		-e DOCKER_BUILD_NETWORK \
		-e VERSION_OVERRIDE \
		$(DAPPER_IMAGE) $@

trash:
	@echo "Dependencies are vendored; no external dependency fetch is required."

trash-keep: trash

deps: trash

.DEFAULT_GOAL := ci

.PHONY: $(TARGETS) deps trash trash-keep
