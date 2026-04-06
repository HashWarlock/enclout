.PHONY: build test lint clean install docker-build docker-push docker-publish deploy

DOCKER_IMAGE := hashwarlock/enclout
GIT_SHA      := $(shell git rev-parse --short HEAD)

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

# Build a linux/amd64 image (required for Phala Cloud TDX CVMs).
docker-build:
	docker build --platform linux/amd64 \
		-t $(DOCKER_IMAGE):latest \
		-t $(DOCKER_IMAGE):$(GIT_SHA) \
		.

# Push both :latest and the git-SHA tag.
docker-push:
	docker push $(DOCKER_IMAGE):latest
	docker push $(DOCKER_IMAGE):$(GIT_SHA)

# Build + push in one step.
docker-publish: docker-build docker-push

# Deploy (or update) the Phala Cloud CVM.
# First deploy:  make deploy NAME=enclout
# Re-deploy:     make deploy              (uses CVM_ID from env or phala.toml)
# Pin a SHA:     make deploy TAG=<sha>
CVM_ID ?= 5cbe64ef-b8fb-444e-a90e-593c2e453e6f
deploy:
	IMAGE_TAG=$(or $(TAG),latest) phala deploy \
		$(if $(NAME),-n $(NAME),--cvm-id $(CVM_ID)) \
		-c docker-compose.prod.yml -e .env
