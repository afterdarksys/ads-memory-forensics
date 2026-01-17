.PHONY: build clean install test run

BINARY=ads-memory-forensics
VERSION=0.1.0

build:
	CGO_ENABLED=1 go build -ldflags "-X github.com/afterdarksystems/ads-memory-forensics/cmd.Version=$(VERSION)" -o $(BINARY) .

clean:
	rm -f $(BINARY)

install: build
	sudo cp $(BINARY) /usr/local/bin/

test:
	go test -v ./...

run: build
	./$(BINARY)

deps:
	go mod tidy

# Quick commands for testing (requires sudo)
regions: build
	sudo ./$(BINARY) regions --pid 1

scan: build
	sudo ./$(BINARY) scan --pid 1

serve: build
	sudo ./$(BINARY) serve
