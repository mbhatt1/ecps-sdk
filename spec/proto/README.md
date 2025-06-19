# ECPS Protocol Buffer Definitions

This directory contains the canonical Protocol Buffer definitions for the Embodied Cognition Protocol Stack (ECPS). These schema files are the authoritative source for generating language bindings and enabling third-party implementations.

## Files

- [`ecps.proto`](ecps.proto) - Main ECPS protocol definitions including all layers (Transport, Perception, Cognition, Actuation, Trust)

## Language Bindings

Language bindings are automatically generated from these schema files via CI/CD pipelines. The generated bindings are published to language-specific package repositories:

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
Available via vcpkg, Conan, or direct download from releases.

## Building Custom Language Bindings

To generate bindings for other languages or custom builds:

```bash
# Install protoc compiler
# See: https://grpc.io/docs/protoc-installation/

# Generate Python bindings
protoc --python_out=./generated --grpc_python_out=./generated spec/proto/ecps.proto

# Generate Go bindings
protoc --go_out=./generated --go-grpc_out=./generated spec/proto/ecps.proto

# Generate JavaScript bindings
protoc --js_out=import_style=commonjs:./generated --grpc-web_out=import_style=commonjs,mode=grpcwebtext:./generated spec/proto/ecps.proto

# Generate C++ bindings
protoc --cpp_out=./generated --grpc_cpp_out=./generated spec/proto/ecps.proto

# Generate Java bindings
protoc --java_out=./generated --grpc-java_out=./generated spec/proto/ecps.proto
```

## Third-Party Implementations

These schema files enable third-party developers to create ECPS-compatible implementations in any language that supports Protocol Buffers. Key considerations:

1. **Protocol Compliance**: Implementations must conform to the ECPS specification in [`../v1.0/docs/protocol-specification.md`](../v1.0/docs/protocol-specification.md)
2. **Conformance Testing**: Use the conformance test suite in [`../v1.0/conformance/`](../v1.0/conformance/) to validate implementation correctness
3. **Security Requirements**: Implement the P2 security hardening features as documented in the specification

## Versioning

Schema files follow semantic versioning:
- **Major version**: Breaking changes to message structure
- **Minor version**: Backward-compatible additions (new fields, messages)
- **Patch version**: Documentation updates, non-breaking clarifications

Current version: **v1.0.0**

## Contributing

When modifying schema files:

1. Update the canonical version in [`../v1.0/ecps.proto`](../v1.0/ecps.proto)
2. Copy changes to this directory: `cp ../v1.0/ecps.proto ./ecps.proto`
3. Update version numbers and documentation
4. Run conformance tests to ensure backward compatibility
5. Update language bindings via CI/CD pipeline

## License

These schema files are released under the MIT License to enable broad adoption and third-party implementations.