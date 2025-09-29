FROM golang:1.25-alpine AS builder
WORKDIR /app
# Copy mod files first to leverage caching
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
    
# Copy source code
COPY . .

# Tidy modules to ensure all dependencies are included
RUN go mod tidy

# Build binary with cached builds
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -o main .

# Final stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates curl bash

WORKDIR /root/

# Install aws-signing-helper from GitHub releases for linux
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then \
      ARCH="amd64"; \
    elif [ "$ARCH" = "aarch64" ]; then \
      ARCH="arm64"; \
    fi && \
    curl -sL https://github.com/aws/aws-signing-helper/releases/latest/download/aws_signing_helper_linux_$ARCH -o aws_signing_helper && \
    chmod +x aws_signing_helper && \
    mv aws_signing_helper /usr/local/bin/

# Create .aws directory
RUN mkdir -p ~/.aws

# Copy the binary from builder
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
