linter:=$(shell which golangci-lint 2>/dev/null || echo $(HOME)/go/bin/golangci-lint)

format:
	@gofmt -l -w ./

check: check-format check-linter

check-format:
	@test -z $(shell gofmt -d -l ./ | tee /dev/stderr) || (echo "[WARN] Fix formatting issues with 'make format'"; exit 1)

check-linter:
	@test -x $(linter) || (echo "Please install linter from https://github.com/golangci/golangci-lint/releases/tag/v1.45.2 to $(HOME)/go/bin")
	$(linter) run

test:
	go test ./... -v
