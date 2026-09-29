BINARY := bin/gas
PKG := ./cmd/gas
VERSION := 1.0.0

.PHONY: build test vet fmt cross all-cross install clean doctor

build:
	go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o $(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w cmd internal

cross:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/gas-linux-amd64 $(PKG)
	GOOS=linux   GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o bin/gas-linux-arm64 $(PKG)
	GOOS=darwin  GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o bin/gas-darwin-arm64 $(PKG)
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o bin/gas-windows-amd64.exe $(PKG)

install: build
	install -m 0755 $(BINARY) /usr/local/bin/gas

doctor: build
	./$(BINARY) doctor

clean:
	rm -rf bin
