NAME    := mirage-chaff
PKG     := ./cmd/$(NAME)
BIN     := bin/$(NAME)
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build check test vet fmt fmt-check lint clean install

all: build

build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

# Validate the sample config with the built binary (nginx -t style, D-1).
check: build
	$(BIN) check -config configs/$(NAME).conf.sample

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "unformatted:"; echo "$$out"; exit 1; fi

lint: vet fmt-check

clean:
	rm -rf bin dist

# Root-only: run the installer from a checkout.
install:
	sudo ./deploy/install.sh
