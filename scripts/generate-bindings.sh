#!/bin/bash

# ECPS Protocol Buffer Binding Generator
# This script generates language bindings from the canonical protobuf definitions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PROTO_DIR="$PROJECT_ROOT/spec/proto"
OUTPUT_DIR="$PROJECT_ROOT/generated"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_protoc() {
    if ! command -v protoc &> /dev/null; then
        log_error "protoc compiler not found. Please install Protocol Buffers compiler."
        log_info "Installation instructions: https://grpc.io/docs/protoc-installation/"
        exit 1
    fi
    log_info "Found protoc: $(protoc --version)"
}

sync_proto() {
    log_info "Syncing canonical proto files to spec/proto/"
    mkdir -p "$PROTO_DIR"
    cp "$PROJECT_ROOT/spec/v1.0/ecps.proto" "$PROTO_DIR/ecps.proto"
    log_info "Proto files synced"
}

generate_python() {
    log_info "Generating Python bindings..."
    
    if ! python -c "import grpc_tools" &> /dev/null; then
        log_warn "grpcio-tools not found. Installing..."
        pip install grpcio-tools
    fi
    
    mkdir -p "$OUTPUT_DIR/python/ecps_proto"
    
    python -m grpc_tools.protoc \
        --python_out="$OUTPUT_DIR/python" \
        --grpc_python_out="$OUTPUT_DIR/python" \
        --proto_path="$PROTO_DIR" \
        "$PROTO_DIR/ecps.proto"
    
    # Create __init__.py files
    touch "$OUTPUT_DIR/python/ecps_proto/__init__.py"
    
    # Create setup.py
    cat > "$OUTPUT_DIR/python/setup.py" << 'EOF'
from setuptools import setup, find_packages

setup(
    name="ecps-proto",
    version="1.0.0",
    description="ECPS Protocol Buffer bindings for Python",
    packages=find_packages(),
    install_requires=[
        "protobuf>=4.0.0",
        "grpcio>=1.50.0",
    ],
    python_requires=">=3.8",
)
EOF
    
    log_info "Python bindings generated in $OUTPUT_DIR/python/"
}

generate_go() {
    log_info "Generating Go bindings..."
    
    if ! command -v protoc-gen-go &> /dev/null; then
        log_warn "protoc-gen-go not found. Installing..."
        go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
    fi
    
    if ! command -v protoc-gen-go-grpc &> /dev/null; then
        log_warn "protoc-gen-go-grpc not found. Installing..."
        go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
    fi
    
    mkdir -p "$OUTPUT_DIR/go/ecps"
    
    protoc \
        --go_out="$OUTPUT_DIR/go" \
        --go-grpc_out="$OUTPUT_DIR/go" \
        --proto_path="$PROTO_DIR" \
        "$PROTO_DIR/ecps.proto"
    
    # Create go.mod
    cd "$OUTPUT_DIR/go"
    go mod init github.com/ecps/ecps-proto-go
    go mod tidy
    
    log_info "Go bindings generated in $OUTPUT_DIR/go/"
}

generate_javascript() {
    log_info "Generating JavaScript/TypeScript bindings..."
    
    if ! command -v npm &> /dev/null; then
        log_error "npm not found. Please install Node.js and npm."
        exit 1
    fi
    
    mkdir -p "$OUTPUT_DIR/javascript/src"
    
    # Install grpc-tools locally if not available
    if ! npx grpc_tools_node_protoc --version &> /dev/null; then
        log_warn "grpc-tools not found. Installing locally..."
        cd "$OUTPUT_DIR/javascript"
        npm init -y
        npm install grpc-tools @grpc/grpc-js google-protobuf
        cd - > /dev/null
    fi
    
    npx grpc_tools_node_protoc \
        --js_out=import_style=commonjs,binary:"$OUTPUT_DIR/javascript/src" \
        --grpc_out=grpc_js:"$OUTPUT_DIR/javascript/src" \
        --proto_path="$PROTO_DIR" \
        "$PROTO_DIR/ecps.proto"
    
    # Create package.json if it doesn't exist
    if [ ! -f "$OUTPUT_DIR/javascript/package.json" ]; then
        cat > "$OUTPUT_DIR/javascript/package.json" << 'EOF'
{
  "name": "@ecps/proto",
  "version": "1.0.0",
  "description": "ECPS Protocol Buffer bindings for JavaScript/TypeScript",
  "main": "src/ecps_pb.js",
  "dependencies": {
    "@grpc/grpc-js": "^1.8.0",
    "google-protobuf": "^3.21.0"
  }
}
EOF
    fi
    
    log_info "JavaScript bindings generated in $OUTPUT_DIR/javascript/"
}

generate_cpp() {
    log_info "Generating C++ bindings..."
    
    if ! command -v grpc_cpp_plugin &> /dev/null; then
        log_error "grpc_cpp_plugin not found. Please install gRPC C++ development packages."
        log_info "Ubuntu/Debian: sudo apt-get install libgrpc++-dev"
        log_info "macOS: brew install grpc"
        exit 1
    fi
    
    mkdir -p "$OUTPUT_DIR/cpp/include/ecps" "$OUTPUT_DIR/cpp/src"
    
    protoc \
        --cpp_out="$OUTPUT_DIR/cpp/src" \
        --grpc_out="$OUTPUT_DIR/cpp/src" \
        --plugin=protoc-gen-grpc="$(which grpc_cpp_plugin)" \
        --proto_path="$PROTO_DIR" \
        "$PROTO_DIR/ecps.proto"
    
    # Move headers to include directory
    mv "$OUTPUT_DIR/cpp/src"/*.h "$OUTPUT_DIR/cpp/include/ecps/"
    
    # Create CMakeLists.txt
    cat > "$OUTPUT_DIR/cpp/CMakeLists.txt" << 'EOF'
cmake_minimum_required(VERSION 3.16)
project(ecps-proto VERSION 1.0.0)

find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

add_library(ecps-proto
    src/ecps.pb.cc
    src/ecps.grpc.pb.cc
)

target_include_directories(ecps-proto PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(ecps-proto
    protobuf::libprotobuf
    gRPC::grpc++
)
EOF
    
    log_info "C++ bindings generated in $OUTPUT_DIR/cpp/"
}

generate_java() {
    log_info "Generating Java bindings..."
    
    if ! command -v java &> /dev/null; then
        log_error "Java not found. Please install JDK 11 or later."
        exit 1
    fi
    
    # Download protoc-gen-grpc-java if not available
    if ! command -v protoc-gen-grpc-java &> /dev/null; then
        log_warn "protoc-gen-grpc-java not found. Downloading..."
        GRPC_JAVA_VERSION="1.53.0"
        GRPC_JAVA_URL="https://repo1.maven.org/maven2/io/grpc/protoc-gen-grpc-java/${GRPC_JAVA_VERSION}/protoc-gen-grpc-java-${GRPC_JAVA_VERSION}-linux-x86_64.exe"
        
        if [[ "$OSTYPE" == "darwin"* ]]; then
            GRPC_JAVA_URL="https://repo1.maven.org/maven2/io/grpc/protoc-gen-grpc-java/${GRPC_JAVA_VERSION}/protoc-gen-grpc-java-${GRPC_JAVA_VERSION}-osx-x86_64.exe"
        fi
        
        wget -O /tmp/protoc-gen-grpc-java "$GRPC_JAVA_URL"
        chmod +x /tmp/protoc-gen-grpc-java
        export PATH="/tmp:$PATH"
    fi
    
    mkdir -p "$OUTPUT_DIR/java/src/main/java"
    
    protoc \
        --java_out="$OUTPUT_DIR/java/src/main/java" \
        --grpc-java_out="$OUTPUT_DIR/java/src/main/java" \
        --proto_path="$PROTO_DIR" \
        "$PROTO_DIR/ecps.proto"
    
    # Create Maven POM
    cat > "$OUTPUT_DIR/java/pom.xml" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    
    <groupId>org.ecps</groupId>
    <artifactId>ecps-proto</artifactId>
    <version>1.0.0</version>
    <packaging>jar</packaging>
    
    <name>ECPS Protocol Buffers</name>
    <description>ECPS Protocol Buffer bindings for Java</description>
    
    <properties>
        <maven.compiler.source>11</maven.compiler.source>
        <maven.compiler.target>11</maven.compiler.target>
        <grpc.version>1.53.0</grpc.version>
        <protobuf.version>3.22.0</protobuf.version>
    </properties>
    
    <dependencies>
        <dependency>
            <groupId>io.grpc</groupId>
            <artifactId>grpc-stub</artifactId>
            <version>${grpc.version}</version>
        </dependency>
        <dependency>
            <groupId>io.grpc</groupId>
            <artifactId>grpc-protobuf</artifactId>
            <version>${grpc.version}</version>
        </dependency>
        <dependency>
            <groupId>com.google.protobuf</groupId>
            <artifactId>protobuf-java</artifactId>
            <version>${protobuf.version}</version>
        </dependency>
    </dependencies>
</project>
EOF
    
    log_info "Java bindings generated in $OUTPUT_DIR/java/"
}

show_usage() {
    echo "Usage: $0 [LANGUAGE...]"
    echo ""
    echo "Generate ECPS protocol buffer bindings for specified languages."
    echo ""
    echo "Languages:"
    echo "  python      Generate Python bindings"
    echo "  go          Generate Go bindings"
    echo "  javascript  Generate JavaScript/TypeScript bindings"
    echo "  cpp         Generate C++ bindings"
    echo "  java        Generate Java bindings"
    echo "  all         Generate bindings for all languages"
    echo ""
    echo "Examples:"
    echo "  $0 python go           # Generate Python and Go bindings"
    echo "  $0 all                 # Generate bindings for all languages"
    echo "  $0                     # Show this help message"
}

main() {
    if [ $# -eq 0 ]; then
        show_usage
        exit 0
    fi
    
    check_protoc
    sync_proto
    
    # Clean output directory
    rm -rf "$OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    
    for lang in "$@"; do
        case $lang in
            python)
                generate_python
                ;;
            go)
                generate_go
                ;;
            javascript|js|ts)
                generate_javascript
                ;;
            cpp|c++)
                generate_cpp
                ;;
            java)
                generate_java
                ;;
            all)
                generate_python
                generate_go
                generate_javascript
                generate_cpp
                generate_java
                ;;
            *)
                log_error "Unknown language: $lang"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log_info "Binding generation complete!"
    log_info "Generated bindings are available in: $OUTPUT_DIR"
}

main "$@"