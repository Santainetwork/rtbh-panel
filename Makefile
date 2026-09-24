.PHONY: build test integration race vet web-test web-build

build:
	mkdir -p bin
	go build -buildvcs=false -o bin/rtbh-server ./cmd/rtbh-server
	go build -buildvcs=false -o bin/rtbh-agent ./cmd/rtbh-agent

test:
	go test ./...

integration:
	go test -tags=integration ./...

race:
	go test -race ./...

vet:
	go vet ./...

web-test:
	cd web && pnpm test --run

web-build:
	cd web && pnpm build
