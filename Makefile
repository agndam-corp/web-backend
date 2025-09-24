# Makefile for backend

# Variables
REGISTRY = ghcr.io
USERNAME = damianjaskolski95
IMAGE = $(REGISTRY)/$(USERNAME)/webapp-backend
TAG ?= v0.0.3

# Build target
.PHONY: build

build:
	@echo "Building backend Docker image..."
	docker build -t $(IMAGE):$(TAG) .

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