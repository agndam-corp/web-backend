FROM golang:1.25-alpine AS builder\n\nWORKDIR /app\n\n# Copy mod files first to leverage caching\nCOPY go.mod go.sum ./\nRUN --mount=type=cache,target=/go/pkg/mod \\\n    go mod download\n\n# Copy source code\nCOPY . .\n\n# Tidy modules to ensure all dependencies are included\nRUN go mod tidy

# Build binary with cached builds
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o main .

# Final stage
FROM alpine:3.20

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder
COPY --from=builder /app/main .

EXPOSE 8080
CMD ["./main"]
