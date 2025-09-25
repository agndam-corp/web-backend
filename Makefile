# Makefile for backend

# Variables
REGISTRY = ghcr.io
USERNAME = agndam-corp
IMAGE = $(REGISTRY)/$(USERNAME)/web-backend
TAG ?= latest

# Build Docker image
build:
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

all: build push

# Clean target
.PHONY: clean

clean:
	@echo "Cleaning up..."
	rm -f main