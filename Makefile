SHELL := /bin/sh

.PHONY: fmt check build test-integration
fmt:
	gofmt -w .
check:
	GOWORK=off go vet ./...
	GOWORK=off go test -race ./...
	$(MAKE) -C dev/tools check
build:
	GOWORK=off go build ./...
	$(MAKE) -C dev/tools build
test-integration:
	GOWORK=off go test -race -tags=integration ./internal/integration/...
	$(MAKE) -C dev/tools test-integration
