# ECPS Robot Controller Docker Image
FROM golang:1.21-alpine AS builder

LABEL maintainer="ECPS Team <team@ecps.org>"
LABEL description="ECPS Robot Controller - Agentic AI Robot Control"
LABEL version="1.0.0"

# Set working directory
WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY robot-controller/go.mod robot-controller/go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY robot-controller/ ./

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o robot-controller .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates curl

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/robot-controller .

# Create directories
RUN mkdir -p /app/config /app/certs /app/logs /app/data

# Set environment variables
ENV ECPS_ENV=production
ENV ECPS_LOG_LEVEL=INFO

# Expose ports
EXPOSE 8081 8001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8081/health || exit 1

# Run the robot controller
CMD ["./robot-controller"]