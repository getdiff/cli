.PHONY: build test gateway-test investor-demo sidecar clean

build:
	cargo build --release

sidecar:
	cargo build --release --bin gateway-sidecar

test:
	cargo test

gateway-test: build
	./scripts/integration-test.sh

investor-demo: build
	./scripts/investor-demo.sh

docker-sidecar:
	docker build -f Dockerfile.sidecar -t gateway-sidecar:latest .

clean:
	cargo clean
