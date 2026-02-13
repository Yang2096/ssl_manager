.PHONY: all build clean test deps scf cli

# Build variables
BINARY_SCFS=scf
BINARY_CLI=cli
BUILD_DIR=build
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -s -w"

all: deps scf cli

deps:
	go mod tidy
	go mod download

scf: deps
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SCFS) ./cmd/scf
	@echo "Built SCF binary: $(BUILD_DIR)/$(BINARY_SCFS)"

cli: deps
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_CLI) ./cmd/cli
	@echo "Built CLI binary: $(BUILD_DIR)/$(BINARY_CLI)"

scf-windows: deps
	@mkdir -p $(BUILD_DIR)
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_SCFS).exe ./cmd/scf

scf-package: scf
	@mkdir -p $(BUILD_DIR)/scf-package
	cp $(BUILD_DIR)/$(BINARY_SCFS) $(BUILD_DIR)/scf-package/
	@BUILD_TIME=$$(date "+%Y-%m-%d %H:%M:%S") && \
	 GIT_REVISION=$$(git rev-parse --short HEAD 2>/dev/null || echo "unknown") && \
	 sed "s/\$${BUILD_TIME}/$${BUILD_TIME}/g; s/\$${GIT_REVISION}/$${GIT_REVISION}/g" \
	     ./scripts/scf_bootstrap > $(BUILD_DIR)/scf-package/scf_bootstrap
	cd $(BUILD_DIR)/scf-package && zip -r ../scf.zip $(BINARY_SCFS) scf_bootstrap
	@echo "Created SCF package: $(BUILD_DIR)/scf.zip"

test:
	go test -v -race -cover ./...

clean:
	rm -rf $(BUILD_DIR)

run-local:
	go run ./cmd/cli main.go $(ARGS)

# Development
dev:
	air || echo "air not installed. Install with: go install github.com/cosmtrek/air@latest"
