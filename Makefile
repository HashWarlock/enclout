.PHONY: build test lint clean install

build:
	go build -o bin/enclout ./cmd/enclout

test:
	go test ./... -race -count=1

lint:
	go vet ./...

clean:
	rm -rf bin/

install: build
	cp bin/enclout /usr/local/bin/enclout
