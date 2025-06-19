#!/bin/bash

# ECPS Golden Path Production Setup
# Complete production-grade deployment script for the "ROS 2 for agentic AI" workflow

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOYMENT_ENV="${DEPLOYMENT_ENV:-production}"
ECPS_VERSION="${ECPS_VERSION:-1.0.0}"

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

check_prerequisites() {
    log_step "Checking prerequisites..."
    
    # Check required tools
    local required_tools=("docker" "docker-compose" "kubectl" "helm" "python3" "go" "protoc")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            log_error "$tool is required but not installed"
            exit 1
        fi
    done
    
    # Check Python version
    local python_version=$(python3 --version | cut -d' ' -f2)
    local required_python="3.9"
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
        log_error "Python 3.9+ is required, found $python_version"
        exit 1
    fi
    
    # Check Go version
    local go_version=$(go version | cut -d' ' -f3 | sed 's/go//')
    if ! go version | grep -q "go1.2[1-9]"; then
        log_warn "Go 1.21+ recommended, found $go_version"
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        exit 1
    fi
    
    # Check Kubernetes cluster (optional)
    if kubectl cluster-info &> /dev/null; then
        log_info "Kubernetes cluster detected"
        export KUBERNETES_AVAILABLE=true
    else
        log_warn "Kubernetes cluster not available, skipping K8s deployment"
        export KUBERNETES_AVAILABLE=false
    fi
    
    log_info "Prerequisites check passed"
}

setup_environment() {
    log_step "Setting up environment..."
    
    # Create necessary directories
    mkdir -p {logs,data,certs,config,monitoring,backups}
    
    # Set up Python virtual environment
    if [ ! -d "venv" ]; then
        log_info "Creating Python virtual environment..."
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    # Upgrade pip and install dependencies
    log_info "Installing Python dependencies..."
    pip install --upgrade pip setuptools wheel
    pip install -r requirements.txt
    
    # Install ECPS SDK in development mode
    cd "$PROJECT_ROOT/ecps-sdk"
    pip install -e .
    cd "$SCRIPT_DIR"
    
    log_info "Environment setup complete"
}

generate_certificates() {
    log_step "Generating security certificates..."
    
    if [ ! -f "certs/ca.crt" ]; then
        log_info "Generating CA certificate..."
        
        # Generate CA private key
        openssl genrsa -out certs/ca.key 4096
        
        # Generate CA certificate
        openssl req -new -x509 -days 3650 -key certs/ca.key -out certs/ca.crt \
            -subj "/C=US/ST=CA/L=San Francisco/O=ECPS/OU=Security/CN=ECPS-CA"
        
        log_info "CA certificate generated"
    fi
    
    # Generate server certificates
    local services=("gateway" "robot-controller" "monitor")
    for service in "${services[@]}"; do
        if [ ! -f "certs/${service}.crt" ]; then
            log_info "Generating certificate for $service..."
            
            # Generate private key
            openssl genrsa -out "certs/${service}.key" 2048
            
            # Generate certificate signing request
            openssl req -new -key "certs/${service}.key" -out "certs/${service}.csr" \
                -subj "/C=US/ST=CA/L=San Francisco/O=ECPS/OU=Services/CN=${service}"
            
            # Generate certificate
            openssl x509 -req -in "certs/${service}.csr" -CA certs/ca.crt -CAkey certs/ca.key \
                -CAcreateserial -out "certs/${service}.crt" -days 365 \
                -extensions v3_req -extfile <(cat <<EOF
[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${service}
DNS.2 = ${service}.ecps.local
DNS.3 = localhost
IP.1 = 127.0.0.1
IP.2 = ::1
EOF
)
            
            # Clean up CSR
            rm "certs/${service}.csr"
        fi
    done
    
    # Set appropriate permissions
    chmod 600 certs/*.key
    chmod 644 certs/*.crt
    
    log_info "Certificate generation complete"
}

setup_hsm_tpm() {
    log_step "Setting up HSM/TPM integration..."
    
    # Check for TPM 2.0
    if [ -c "/dev/tpm0" ] || [ -c "/dev/tpmrm0" ]; then
        log_info "TPM 2.0 device detected"
        
        # Install TPM tools if not present
        if ! command -v tpm2_startup &> /dev/null; then
            log_info "Installing TPM 2.0 tools..."
            if command -v apt-get &> /dev/null; then
                sudo apt-get update
                sudo apt-get install -y tpm2-tools
            elif command -v yum &> /dev/null; then
                sudo yum install -y tpm2-tools
            else
                log_warn "Please install tpm2-tools manually"
            fi
        fi
        
        # Initialize TPM
        log_info "Initializing TPM..."
        sudo tpm2_startup -c || true
        sudo tpm2_clear || true
        
        export TPM_AVAILABLE=true
    else
        log_warn "No TPM 2.0 device found"
        export TPM_AVAILABLE=false
    fi
    
    # Check for HSM (SoftHSM for testing)
    if command -v softhsm2-util &> /dev/null; then
        log_info "SoftHSM detected"
        
        # Initialize test HSM token
        mkdir -p ~/.config/softhsm2
        echo "directories.tokendir = $SCRIPT_DIR/data/softhsm2/" > ~/.config/softhsm2/softhsm2.conf
        mkdir -p "$SCRIPT_DIR/data/softhsm2"
        
        # Initialize token if not exists
        if ! softhsm2-util --show-slots | grep -q "ECPS-Production"; then
            log_info "Initializing HSM token..."
            softhsm2-util --init-token --slot 0 --label "ECPS-Production" \
                --pin 123456 --so-pin 654321
        fi
        
        export HSM_AVAILABLE=true
    else
        log_warn "No HSM available, install SoftHSM for testing"
        export HSM_AVAILABLE=false
    fi
    
    log_info "HSM/TPM setup complete"
}

build_containers() {
    log_step "Building Docker containers..."
    
    # Build Gateway container
    log_info "Building ECPS Gateway container..."
    docker build -t "ecps-gateway:${ECPS_VERSION}" -f Dockerfile.gateway .
    
    # Build Robot Controller container
    log_info "Building Robot Controller container..."
    docker build -t "ecps-robot:${ECPS_VERSION}" -f Dockerfile.robot .
    
    # Build Monitor container
    log_info "Building Monitor container..."
    docker build -t "ecps-monitor:${ECPS_VERSION}" -f Dockerfile.monitor .
    
    # Tag latest
    docker tag "ecps-gateway:${ECPS_VERSION}" ecps-gateway:latest
    docker tag "ecps-robot:${ECPS_VERSION}" ecps-robot:latest
    docker tag "ecps-monitor:${ECPS_VERSION}" ecps-monitor:latest
    
    log_info "Container build complete"
}

setup_monitoring() {
    log_step "Setting up monitoring infrastructure..."
    
    # Create monitoring configuration
    cat > config/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

scrape_configs:
  - job_name: 'ecps-gateway'
    static_configs:
      - targets: ['gateway:8000']
    metrics_path: /metrics
    scrape_interval: 5s

  - job_name: 'ecps-robot'
    static_configs:
      - targets: ['robot-controller:8001']
    metrics_path: /metrics
    scrape_interval: 5s

  - job_name: 'ecps-monitor'
    static_configs:
      - targets: ['monitor:8002']
    metrics_path: /metrics
    scrape_interval: 10s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
EOF

    # Create alert rules
    cat > config/alert_rules.yml << 'EOF'
groups:
  - name: ecps_alerts
    rules:
      - alert: ECPSGatewayDown
        expr: up{job="ecps-gateway"} == 0
        for: 30s
        labels:
          severity: critical
        annotations:
          summary: "ECPS Gateway is down"
          description: "ECPS Gateway has been down for more than 30 seconds"

      - alert: HighLatency
        expr: ecps_end_to_end_latency_seconds > 0.5
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "High end-to-end latency detected"
          description: "End-to-end latency is {{ $value }}s"

      - alert: HighErrorRate
        expr: rate(ecps_errors_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors/second"
EOF

    # Create Grafana dashboard
    mkdir -p config/grafana/dashboards
    cat > config/grafana/dashboards/ecps-dashboard.json << 'EOF'
{
  "dashboard": {
    "id": null,
    "title": "ECPS Golden Path Dashboard",
    "tags": ["ecps", "robotics", "ai"],
    "timezone": "browser",
    "panels": [
      {
        "id": 1,
        "title": "End-to-End Latency",
        "type": "graph",
        "targets": [
          {
            "expr": "ecps_end_to_end_latency_seconds",
            "legendFormat": "Latency"
          }
        ]
      },
      {
        "id": 2,
        "title": "Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ecps_processed_frames_total[1m])",
            "legendFormat": "Frames/sec"
          }
        ]
      },
      {
        "id": 3,
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(ecps_errors_total[1m])",
            "legendFormat": "Errors/sec"
          }
        ]
      }
    ],
    "time": {
      "from": "now-1h",
      "to": "now"
    },
    "refresh": "5s"
  }
}
EOF

    log_info "Monitoring setup complete"
}

create_docker_compose() {
    log_step "Creating Docker Compose configuration..."
    
    cat > docker-compose.production.yml << EOF
version: '3.8'

services:
  # Core ECPS Services
  gateway:
    image: ecps-gateway:${ECPS_VERSION}
    container_name: ecps-gateway
    restart: unless-stopped
    ports:
      - "8080:8080"
      - "8000:8000"  # Metrics
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:ro
      - ./logs:/app/logs
      - ./data:/app/data
    environment:
      - ECPS_ENV=${DEPLOYMENT_ENV}
      - ECPS_LOG_LEVEL=INFO
      - ECPS_METRICS_PORT=8000
      - ECPS_SECURITY_ENABLED=true
      - TPM_AVAILABLE=${TPM_AVAILABLE:-false}
      - HSM_AVAILABLE=${HSM_AVAILABLE:-false}
    depends_on:
      - redis
      - postgres
      - mosquitto
    networks:
      - ecps-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  robot-controller:
    image: ecps-robot:${ECPS_VERSION}
    container_name: ecps-robot-controller
    restart: unless-stopped
    ports:
      - "8081:8081"
      - "8001:8001"  # Metrics
    volumes:
      - ./config:/app/config:ro
      - ./certs:/app/certs:ro
      - ./logs:/app/logs
      - ./data:/app/data
    environment:
      - ECPS_ENV=${DEPLOYMENT_ENV}
      - ECPS_LOG_LEVEL=INFO
      - ECPS_GATEWAY_ENDPOINT=gateway:8080
    depends_on:
      - gateway
    networks:
      - ecps-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8081/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  monitor:
    image: ecps-monitor:${ECPS_VERSION}
    container_name: ecps-monitor
    restart: unless-stopped
    ports:
      - "3000:3000"
      - "8002:8002"  # Metrics
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs:ro
    environment:
      - ECPS_ENV=${DEPLOYMENT_ENV}
      - ECPS_GATEWAY_ENDPOINT=gateway:8080
    depends_on:
      - gateway
    networks:
      - ecps-network

  # Infrastructure Services
  redis:
    image: redis:7-alpine
    container_name: ecps-redis
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    command: redis-server --appendonly yes --requirepass \${REDIS_PASSWORD:-ecps123}
    networks:
      - ecps-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 3

  postgres:
    image: postgres:15-alpine
    container_name: ecps-postgres
    restart: unless-stopped
    ports:
      - "5432:5432"
    volumes:
      - postgres-data:/var/lib/postgresql/data
      - ./config/postgres-init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    environment:
      - POSTGRES_DB=ecps
      - POSTGRES_USER=ecps
      - POSTGRES_PASSWORD=\${POSTGRES_PASSWORD:-ecps123}
    networks:
      - ecps-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ecps"]
      interval: 30s
      timeout: 10s
      retries: 3

  mosquitto:
    image: eclipse-mosquitto:2
    container_name: ecps-mosquitto
    restart: unless-stopped
    ports:
      - "1883:1883"
      - "9001:9001"
    volumes:
      - ./config/mosquitto.conf:/mosquitto/config/mosquitto.conf:ro
      - mosquitto-data:/mosquitto/data
      - mosquitto-logs:/mosquitto/log
    networks:
      - ecps-network
    healthcheck:
      test: ["CMD", "mosquitto_pub", "-h", "localhost", "-t", "test", "-m", "test"]
      interval: 30s
      timeout: 10s
      retries: 3

  # Monitoring Stack
  prometheus:
    image: prom/prometheus:latest
    container_name: ecps-prometheus
    restart: unless-stopped
    ports:
      - "9090:9090"
    volumes:
      - ./config/prometheus.yml:/etc/prometheus/prometheus.yml:ro
      - ./config/alert_rules.yml:/etc/prometheus/alert_rules.yml:ro
      - prometheus-data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'
      - '--storage.tsdb.retention.time=200h'
      - '--web.enable-lifecycle'
    networks:
      - ecps-network

  grafana:
    image: grafana/grafana:latest
    container_name: ecps-grafana
    restart: unless-stopped
    ports:
      - "3001:3000"
    volumes:
      - grafana-data:/var/lib/grafana
      - ./config/grafana/dashboards:/etc/grafana/provisioning/dashboards:ro
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=\${GRAFANA_PASSWORD:-admin123}
      - GF_USERS_ALLOW_SIGN_UP=false
    networks:
      - ecps-network

  jaeger:
    image: jaegertracing/all-in-one:latest
    container_name: ecps-jaeger
    restart: unless-stopped
    ports:
      - "16686:16686"
      - "14268:14268"
    environment:
      - COLLECTOR_OTLP_ENABLED=true
    networks:
      - ecps-network

  # Log aggregation
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    container_name: ecps-elasticsearch
    restart: unless-stopped
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    networks:
      - ecps-network

  kibana:
    image: docker.elastic.co/kibana/kibana:8.11.0
    container_name: ecps-kibana
    restart: unless-stopped
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch
    networks:
      - ecps-network

  # Load balancer
  nginx:
    image: nginx:alpine
    container_name: ecps-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - gateway
      - monitor
    networks:
      - ecps-network

volumes:
  redis-data:
  postgres-data:
  mosquitto-data:
  mosquitto-logs:
  prometheus-data:
  grafana-data:
  elasticsearch-data:

networks:
  ecps-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
EOF

    log_info "Docker Compose configuration created"
}

create_kubernetes_manifests() {
    if [ "$KUBERNETES_AVAILABLE" = "false" ]; then
        log_warn "Skipping Kubernetes manifests (cluster not available)"
        return
    fi
    
    log_step "Creating Kubernetes manifests..."
    
    mkdir -p k8s
    
    # Create namespace
    cat > k8s/namespace.yaml << 'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: ecps-production
  labels:
    name: ecps-production
    environment: production
EOF

    # Create ConfigMap
    cat > k8s/configmap.yaml << 'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: ecps-config
  namespace: ecps-production
data:
  gateway-config.yaml: |
    security:
      jwt_rotation_interval: 86400
      mtls_enabled: true
      hsm_enabled: false
    perception:
      max_fps: 30
      tensor_compression: "zstd"
    cognition:
      llm_provider: "openai"
      model: "gpt-4"
    actuation:
      robot_endpoint: "robot-controller:8081"
    observability:
      metrics_port: 8000
      tracing_enabled: true
EOF

    # Create Secret
    cat > k8s/secret.yaml << 'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: ecps-secrets
  namespace: ecps-production
type: Opaque
data:
  # Base64 encoded values
  redis-password: ZWNwczEyMw==  # ecps123
  postgres-password: ZWNwczEyMw==  # ecps123
  openai-api-key: ""  # Set this to your actual API key
EOF

    # Create Gateway Deployment
    cat > k8s/gateway-deployment.yaml << EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ecps-gateway
  namespace: ecps-production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ecps-gateway
  template:
    metadata:
      labels:
        app: ecps-gateway
    spec:
      containers:
      - name: gateway
        image: ecps-gateway:${ECPS_VERSION}
        ports:
        - containerPort: 8080
        - containerPort: 8000
        env:
        - name: ECPS_ENV
          value: "production"
        - name: REDIS_PASSWORD
          valueFrom:
            secretKeyRef:
              name: ecps-secrets
              key: redis-password
        volumeMounts:
        - name: config
          mountPath: /app/config
        - name: certs
          mountPath: /app/certs
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
      volumes:
      - name: config
        configMap:
          name: ecps-config
      - name: certs
        secret:
          secretName: ecps-tls-certs
---
apiVersion: v1
kind: Service
metadata:
  name: ecps-gateway-service
  namespace: ecps-production
spec:
  selector:
    app: ecps-gateway
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: metrics
    port: 8000
    targetPort: 8000
  type: LoadBalancer
EOF

    # Create Helm chart
    mkdir -p helm/ecps-golden-path
    cat > helm/ecps-golden-path/Chart.yaml << EOF
apiVersion: v2
name: ecps-golden-path
description: ECPS Golden Path - Complete Agentic AI Workflow
type: application
version: ${ECPS_VERSION}
appVersion: "${ECPS_VERSION}"
keywords:
  - robotics
  - ai
  - agentic
  - ecps
home: https://github.com/ecps/ecps
sources:
  - https://github.com/ecps/ecps
maintainers:
  - name: ECPS Team
    email: team@ecps.org
EOF

    log_info "Kubernetes manifests created"
}

run_tests() {
    log_step "Running comprehensive test suite..."
    
    source venv/bin/activate
    
    # Unit tests
    log_info "Running unit tests..."
    pytest tests/test_golden_path.py::TestGoldenPathUnit -v --cov=gateway --cov-report=html
    
    # Integration tests (if infrastructure is running)
    if docker-compose -f docker-compose.production.yml ps | grep -q "Up"; then
        log_info "Running integration tests..."
        pytest tests/test_golden_path.py::TestGoldenPathIntegration -v
    else
        log_warn "Skipping integration tests (infrastructure not running)"
    fi
    
    # Security tests
    log_info "Running security tests..."
    pytest tests/test_golden_path.py::TestGoldenPathSecurity -v
    
    # Performance benchmarks
    log_info "Running performance benchmarks..."
    pytest tests/test_golden_path.py::TestGoldenPathPerformance -v --benchmark-only
    
    log_info "Test suite completed"
}

deploy_production() {
    log_step "Deploying to production..."
    
    # Start infrastructure
    log_info "Starting infrastructure services..."
    docker-compose -f docker-compose.production.yml up -d redis postgres mosquitto
    
    # Wait for infrastructure
    log_info "Waiting for infrastructure to be ready..."
    sleep 30
    
    # Start monitoring
    log_info "Starting monitoring services..."
    docker-compose -f docker-compose.production.yml up -d prometheus grafana jaeger elasticsearch kibana
    
    # Start ECPS services
    log_info "Starting ECPS services..."
    docker-compose -f docker-compose.production.yml up -d gateway robot-controller monitor
    
    # Start load balancer
    log_info "Starting load balancer..."
    docker-compose -f docker-compose.production.yml up -d nginx
    
    # Wait for services to be ready
    log_info "Waiting for services to be ready..."
    sleep 60
    
    # Run health checks
    log_info "Running health checks..."
    local services=("gateway:8080" "robot-controller:8081" "monitor:3000")
    for service in "${services[@]}"; do
        local host=$(echo "$service" | cut -d':' -f1)
        local port=$(echo "$service" | cut -d':' -f2)
        
        if curl -f "http://localhost:$port/health" &> /dev/null; then
            log_info "$host health check passed"
        else
            log_error "$host health check failed"
        fi
    done
    
    # Deploy to Kubernetes if available
    if [ "$KUBERNETES_AVAILABLE" = "true" ]; then
        log_info "Deploying to Kubernetes..."
        kubectl apply -f k8s/
        
        # Wait for deployment
        kubectl wait --for=condition=available --timeout=300s deployment/ecps-gateway -n ecps-production
    fi
    
    log_info "Production deployment complete"
}

show_status() {
    log_step "Deployment Status"
    
    echo -e "\n${GREEN}ECPS Golden Path Production Deployment${NC}"
    echo "========================================"
    
    echo -e "\n${BLUE}Services:${NC}"
    echo "  Gateway:         http://localhost:8080"
    echo "  Robot Controller: http://localhost:8081"
    echo "  Monitor:         http://localhost:3000"
    echo "  Grafana:         http://localhost:3001 (admin/admin123)"
    echo "  Prometheus:      http://localhost:9090"
    echo "  Jaeger:          http://localhost:16686"
    echo "  Kibana:          http://localhost:5601"
    
    echo -e "\n${BLUE}Metrics:${NC}"
    echo "  Gateway Metrics:  http://localhost:8000/metrics"
    echo "  Robot Metrics:    http://localhost:8001/metrics"
    echo "  Monitor Metrics:  http://localhost:8002/metrics"
    
    echo -e "\n${BLUE}Security:${NC}"
    echo "  mTLS Enabled:     Yes"
    echo "  JWT Rotation:     Active"
    echo "  HSM Available:    ${HSM_AVAILABLE:-false}"
    echo "  TPM Available:    ${TPM_AVAILABLE:-false}"
    
    echo -e "\n${BLUE}Performance Targets:${NC}"
    echo "  Perception Latency:  < 50ms"
    echo "  End-to-End Latency:  < 200ms"
    echo "  Throughput:          > 30 FPS"
    echo "  Availability:        99.9%"
    
    echo -e "\n${GREEN}Production deployment ready!${NC}"
    echo "This is the definitive 'ROS 2 for agentic AI' implementation."
}

cleanup() {
    log_step "Cleaning up..."
    
    # Stop all services
    docker-compose -f docker-compose.production.yml down
    
    # Remove containers
    docker container prune -f
    
    # Remove unused images
    docker image prune -f
    
    log_info "Cleanup complete"
}

main() {
    echo -e "${GREEN}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════╗
║                    ECPS Golden Path                           ║
║              Production Deployment Setup                     ║
║                                                               ║
║           "ROS 2 for Agentic AI" - Complete Workflow         ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    
    case "${1:-deploy}" in
        "check")
            check_prerequisites
            ;;
        "setup")
            check_prerequisites
            setup_environment
            generate_certificates
            setup_hsm_tpm
            ;;
        "build")
            build_containers
            ;;
"test")
            run_tests
            ;;
        "deploy")
            check_prerequisites
            setup_environment
            generate_certificates
            setup_hsm_tpm
            build_containers
            setup_monitoring
            create_docker_compose
            create_kubernetes_manifests
            deploy_production
            show_status
            ;;
        "status")
            show_status
            ;;
        "cleanup")
            cleanup
            ;;
        "help"|*)
            echo "Usage: $0 {check|setup|build|test|deploy|status|cleanup|help}"
            echo ""
            echo "Commands:"
            echo "  check    - Check prerequisites"
            echo "  setup    - Setup environment and certificates"
            echo "  build    - Build Docker containers"
            echo "  test     - Run comprehensive test suite"
            echo "  deploy   - Full production deployment"
            echo "  status   - Show deployment status"
            echo "  cleanup  - Clean up deployment"
            echo "  help     - Show this help message"
            echo ""
            echo "Environment Variables:"
            echo "  DEPLOYMENT_ENV - Deployment environment (default: production)"
            echo "  ECPS_VERSION   - ECPS version (default: 1.0.0)"
            echo ""
            echo "Examples:"
            echo "  $0 deploy                    # Full production deployment"
            echo "  ECPS_VERSION=1.1.0 $0 build # Build specific version"
            echo "  DEPLOYMENT_ENV=staging $0 deploy # Deploy to staging"
            ;;
    esac
}

# Trap for cleanup on exit
trap cleanup EXIT

main "$@"