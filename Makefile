# Makefile for backend

# Variables
REGISTRY = ghcr.io
USERNAME = damianjaskolski95
IMAGE = $(REGISTRY)/$(USERNAME)/webapp-backend
TAG ?= v0.0.3

# Build target
build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Build Docker image
docker-build:
	@echo "Building Docker image $(IMAGE):$(TAG)..."
	docker build -t $(IMAGE):$(TAG) .

# Ensure dependencies are up to date
deps:
	go mod tidy

# Push target
.PHONY: push

push:
	@echo "Pushing backend Docker image..."
	docker push $(IMAGE):$(TAG)


# All-in-one target
.PHONY: all

all: docker-build push

# Clean target
.PHONY: clean

clean:
	@echo "Cleaning up..."
	rm -f main