# ECPS Protocol Specifications

This directory contains the canonical specifications, schema files, and conformance testing framework for the Embodied Cognition Protocol Stack (ECPS).

## Directory Structure

```
spec/
├── README.md                    # This file
├── proto/                       # Protocol Buffer schema files
│   ├── README.md               # Proto-specific documentation
│   └── ecps.proto              # Canonical ECPS protocol definitions
├── openapi/                     # OpenAPI/REST specifications
│   └── ecps-api.yaml           # REST API specification
└── v1.0/                       # Version 1.0 specification
    ├── README.md               # Version-specific documentation
    ├── ecps.proto              # Canonical protobuf (source of truth)
    ├── IMPLEMENTATION_GUIDE.md # Implementation guidelines
    ├── docs/                   # Detailed documentation
    │   └── protocol-specification.md
    └── conformance/            # Conformance testing framework
        ├── README.md
        ├── test-runner/        # Test execution framework
        ├── test-vectors/       # Test case definitions
        └── schemas/            # Test interface schemas
```

## Schema Files for Third-Party Implementations

### Protocol Buffer Definitions

The canonical Protocol Buffer definitions in [`proto/ecps.proto`](proto/ecps.proto) enable third-party developers to generate language bindings for any Protocol Buffer-supported language.

**Supported Languages:**
- Python
- Go
- JavaScript/TypeScript
- C++
- Java
- C#
- Ruby
- PHP
- Dart
- Kotlin
- Swift
- Rust

**Usage:**
```bash
# Generate Python bindings
protoc --python_out=./generated --grpc_python_out=./generated spec/proto/ecps.proto

# Generate Go bindings
protoc --go_out=./generated --go-grpc_out=./generated spec/proto/ecps.proto

# Generate JavaScript bindings
protoc --js_out=import_style=commonjs:./generated --grpc-web_out=import_style=commonjs,mode=grpcwebtext:./generated spec/proto/ecps.proto
```

### OpenAPI/REST Specification

The OpenAPI specification in [`openapi/ecps-api.yaml`](openapi/ecps-api.yaml) provides REST API definitions for HTTP-based integrations.

**Usage:**
```bash
# Generate client libraries using OpenAPI Generator
openapi-generator-cli generate -i spec/openapi/ecps-api.yaml -g python -o ./python-client
openapi-generator-cli generate -i spec/openapi/ecps-api.yaml -g typescript-fetch -o ./ts-client
openapi-generator-cli generate -i spec/openapi/ecps-api.yaml -g java -o ./java-client
```

## Automated Language Binding Generation

### CI/CD Pipeline

The GitHub Actions workflow in [`.github/workflows/generate-bindings.yml`](../.github/workflows/generate-bindings.yml) automatically:

1. **Syncs** canonical proto files from `v1.0/` to `proto/`
2. **Generates** language bindings for Python, Go, JavaScript, C++, and Java
3. **Publishes** packages to language-specific repositories
4. **Creates** release artifacts for manual distribution

### Local Generation

Use the provided script for local development:

```bash
# Generate bindings for specific languages
./scripts/generate-bindings.sh python go

# Generate bindings for all supported languages
./scripts/generate-bindings.sh all

# Show available options
./scripts/generate-bindings.sh
```

## Published Packages

### Python
```bash
pip install ecps-proto
```

### Go
```bash
go get github.com/ecps/ecps-proto-go
```

### JavaScript/TypeScript
```bash
npm install @ecps/proto
```

### Java
```xml
<dependency>
    <groupId>org.ecps</groupId>
    <artifactId>ecps-proto</artifactId>
    <version>1.0.0</version>
</dependency>
```

### C++
Available via vcpkg, Conan, or direct download from GitHub releases.

## Third-Party Implementation Guidelines

### 1. Protocol Compliance

Implementations must conform to the ECPS specification:
- **Transport Layer (L2)**: Support for DDS/RTPS, gRPC/HTTP-2, or MQTT 5
- **Serialization (L3)**: Protocol Buffers with CloudEvents envelope
- **Observability (L4)**: OpenTelemetry integration
- **Perception (L5)**: Latent Tensor Protocol (LTP) support
- **Cognition (L6)**: Model Context Protocol (MCP) and Memory Exchange Protocol (MEP)
- **Actuation (L7)**: Embodied Action Protocol (EAP)
- **Trust Layer**: P2 security hardening features

### 2. Security Requirements

Implement P2 security hardening features:
- **JWT Secret Rotation**: Automatic rotation of signing secrets
- **Mutual TLS (mTLS)**: Certificate-based authentication between nodes
- **HSM/TPM Integration**: Hardware security module support
- **Protobuf Fuzzing**: Security testing for message parsers
- **Role-Based Access Control**: Fine-grained permissions

### 3. Conformance Testing

Use the conformance test suite in [`v1.0/conformance/`](v1.0/conformance/) to validate implementation correctness:

```bash
# Run conformance tests against your implementation
cd spec/v1.0/conformance
python test-runner/run-conformance.py --implementation your-implementation --endpoint localhost:8080
```

### 4. Cross-Language Compatibility

Ensure interoperability with existing implementations:
- **Message Format Compatibility**: Use identical protobuf serialization
- **Security Protocol Compatibility**: Support shared certificate formats
- **Transport Compatibility**: Implement compatible transport bindings

## Versioning and Compatibility

### Schema Versioning

Schema files follow semantic versioning:
- **Major version**: Breaking changes to message structure
- **Minor version**: Backward-compatible additions (new fields, messages)
- **Patch version**: Documentation updates, non-breaking clarifications

### Backward Compatibility

- **Protocol Buffer Evolution**: Follow protobuf best practices for field evolution
- **API Versioning**: REST API includes version in URL path (`/v1/`)
- **Migration Support**: Tools provided for upgrading between versions

## Contributing to Specifications

### Updating Schema Files

1. **Modify** the canonical version in [`v1.0/ecps.proto`](v1.0/ecps.proto)
2. **Sync** changes to [`proto/ecps.proto`](proto/ecps.proto)
3. **Update** OpenAPI specification if REST endpoints are affected
4. **Run** conformance tests to ensure backward compatibility
5. **Update** version numbers and documentation
6. **Submit** pull request with changes

### Adding New Features

1. **Design** the feature following ECPS architectural principles
2. **Update** protocol buffer definitions with new messages/fields
3. **Add** conformance test cases for the new feature
4. **Update** implementation guide and documentation
5. **Implement** in reference Python and Go implementations
6. **Validate** cross-language compatibility

## License

All specification files are released under the MIT License to enable broad adoption and third-party implementations.

## Support

For questions about implementing ECPS or using the schema files:

1. **Documentation**: Review the [Implementation Guide](v1.0/IMPLEMENTATION_GUIDE.md)
2. **Conformance Tests**: Use the test suite to validate your implementation
3. **GitHub Issues**: Report bugs or request clarifications
4. **Community**: Join discussions in GitHub Discussions

## Related Resources

- **Main Repository**: [ECPS SDK](../ecps-sdk/)
- **Protocol Specification**: [Detailed Protocol Documentation](v1.0/docs/protocol-specification.md)
- **Conformance Testing**: [Test Framework Documentation](v1.0/conformance/README.md)
- **Security Hardening**: [Security Implementation Guide](../ecps-sdk/SECURITY_HARDENING.md)