.PHONY: build test lint clean

build:
	go build -o bin/enclout ./cmd/enclout

test:
	go test ./... -race -count=1

lint:
	go vet ./...

clean:
	rm -rf bin/
