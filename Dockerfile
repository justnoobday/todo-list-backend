# Stage 1: Build Go binary
FROM golang:1.24-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go.mod dan go.sum dulu biar cache build tetap kepake
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build binary (disable CGO biar portable)
RUN go build -o main .

# Stage 2: Final image
FROM alpine:latest

RUN apk add --no-cache git tzdata

# Set working directory
WORKDIR /root/

# Copy binary dari builder
COPY --from=builder /app/main .

# Expose port (ubah sesuai app lo)
EXPOSE 8001

# Run binary
CMD ["./main"]