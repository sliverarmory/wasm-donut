GO ?= go
GOBIN ?= $(CURDIR)/bin

.PHONY: all wasm install build clean

all: headers install

headers:
	@if ! docker image inspect $(HEADERS_IMAGE) >/dev/null 2>&1; then \
		docker build -f donut/Dockerfile.headers -t $(HEADERS_IMAGE) .; \
	fi
	docker run --rm -v ./donut:/work/donut/ donut-headers all

wasm:
	./donut/wasm/build.sh

install: wasm
	mkdir -p "$(GOBIN)"
	GOBIN="$(GOBIN)" $(GO) install ./cmd/wasm-donut

build: install

clean:
	rm -f "$(GOBIN)/wasm-donut"
