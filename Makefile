SHELL := /bin/sh

.PHONY: fmt check test-integration
fmt:
	gofmt -w .
check:
	GOWORK=off go vet ./...
	GOWORK=off go test -race ./...
test-integration:
	GOWORK=off go test -race -tags=integration ./internal/integration/...
