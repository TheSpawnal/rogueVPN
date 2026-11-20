VERSION ?= 0.1.0
LDFLAGS := -s -w -X wyrm/internal/version.Version=$(VERSION)

.PHONY: build test race fuzz e2e cross clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/wyrm ./cmd/wyrm

test:
	go vet ./...
	go test ./...

race:
	go test -race -count=1 ./...

fuzz:
	go test -run '^$$' -fuzz '^FuzzDecode$$' -fuzztime 30s ./internal/flow
	go test -run '^$$' -fuzz '^FuzzOpen$$' -fuzztime 30s ./internal/disco
	go test -run '^$$' -fuzz '^FuzzParseResponse$$' -fuzztime 30s ./internal/stun

# Needs root: builds a NAT lab out of network namespaces.
e2e:
	test/mesh.sh

# Compile-only check that the code base stays portable.
cross:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o bin/wyrm.exe ./cmd/wyrm
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o bin/wyrm-arm64 ./cmd/wyrm

clean:
	rm -rf bin
