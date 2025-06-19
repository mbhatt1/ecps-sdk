# ECPS v1.0 Implementation Guide

## Overview

This document provides guidance for implementing ECPS v1.0 conformant systems and integrating with the conformance test suite.

## Canonical Protocol Definitions

The canonical protocol definitions are located in [`/spec/v1.0/ecps.proto`](./ecps.proto). All implementations MUST use these definitions as the authoritative source.

### Protocol Versions

- **MCP (Model Context Protocol)**: v1.0
- **LTP (Latent Tensor Protocol)**: v0.9  
- **MEP (Memory Exchange Protocol)**: v1.0
- **EAP (Embodied Action Protocol)**: v0.1

## Implementation Requirements

### 1. Protocol Buffer Integration

Copy or symlink the canonical [`ecps.proto`](./ecps.proto) file into your implementation:

```bash
# For Python implementations
cp spec/v1.0/ecps.proto your-project/proto/

# For Go implementations  
cp spec/v1.0/ecps.proto your-project/proto/
# Add: option go_package = "your-module/proto";

# Generate language bindings
protoc --python_out=. --go_out=. ecps.proto
```

### 2. Conformance Test Integration

Implementations MUST provide a conformance test interface as specified in [`conformance/schemas/conformance-interface.yaml`](./conformance/schemas/conformance-interface.yaml).

#### Required Commands

```bash
# Message validation
your-ecps-impl validate-message --type MCP --input message.bin

# Transport testing
your-ecps-impl transport-test --transport dds --config config.yaml

# Behavioral testing
your-ecps-impl mep-query --query query.bin --expected results.bin
your-ecps-impl eap-replay --actions actions.bin --state-hashes hashes.txt
your-ecps-impl ltp-compression --input tensor.bin --verify-integrity
```

#### Output Format

All commands MUST output JSON in this format:

```json
{
  "status": "PASS|FAIL|ERROR|SKIP",
  "message": "Human-readable status message",
  "details": {
    "execution_time_ms": 123,
    "validation_errors": ["error1", "error2"],
    "transport_metrics": {...},
    "memory_usage": {...}
  }
}
```

### 3. Running Conformance Tests

```bash
# Install test runner dependencies
pip install -r spec/v1.0/conformance/test-runner/requirements.txt

# Generate test vectors
cd spec/v1.0/conformance/test-vectors
python generate-test-vectors.py --output-dir .

# Run conformance tests
cd spec/v1.0/conformance
./test-runner/run-conformance.py --implementation /path/to/your-ecps-impl

# Run specific test category
./test-runner/run-conformance.py --category protocol-messages --implementation /path/to/your-ecps-impl

# Generate JSON report
./test-runner/run-conformance.py --implementation /path/to/your-ecps-impl --report-format json > report.json
```

## Certification Levels

### Level 1: Basic Conformance
- **Requirements**: Message validation for MCP, LTP, EAP
- **Commands**: `validate-message`
- **Pass Rate**: 100%
- **Use Case**: Basic ECPS message handling

### Level 2: Standard Conformance  
- **Requirements**: Multi-transport support, behavioral validation
- **Commands**: `validate-message`, `transport-test`, `mep-query`, `ltp-compression`
- **Transports**: DDS, gRPC
- **Pass Rate**: 95%
- **Use Case**: Production robot systems

### Level 3: Full Conformance
- **Requirements**: Complete ECPS implementation
- **Commands**: All conformance commands
- **Transports**: DDS, gRPC, MQTT
- **Additional**: OTLP observability, TLS security, performance benchmarks
- **Pass Rate**: 90%
- **Use Case**: Enterprise robot fleets

## Migration from Existing Implementations

### Python (ecps_uv)

1. Update protobuf definitions:
   ```bash
   cp spec/v1.0/ecps.proto ecps-sdk/ecps_uv/proto/
   ```

2. Regenerate Python bindings:
   ```bash
   cd ecps-sdk/ecps_uv/proto
   protoc --python_out=. ecps.proto
   ```

3. Implement conformance interface in your main module

### Go (ecps-go)

1. Update protobuf definitions:
   ```bash
   cp spec/v1.0/ecps.proto ecps-sdk/ecps-go/proto/
   # Add go_package option
   ```

2. Regenerate Go bindings:
   ```bash
   cd ecps-sdk/ecps-go/proto
   protoc --go_out=. --go-grpc_out=. ecps.proto
   ```

3. Implement conformance interface as a CLI command

## Key Implementation Notes

### Message Constraints
- **MCP prompts**: ≤ 16 KiB UTF-8
- **LTP frames**: ≤ 1 MiB for DDS compatibility
- **Version strings**: Must be exact (e.g., "mcp/1.0", "ltp/0.9")
- **CloudEvents IDs**: Must be unique and propagate as OTLP trace_id

### Transport Requirements
- **DDS**: Use RELIABLE QoS for critical messages, TRANSIENT_LOCAL durability
- **gRPC**: Support streaming for MEP queries, implement back-pressure
- **MQTT**: Use QoS 1+ for delivery guarantees

### Behavioral Requirements
- **MEP**: Respect k-limiting and similarity thresholds, return results ordered by similarity
- **LTP**: Use zstd compression, verify integrity with checksums
- **EAP**: Ensure deterministic replay with state hashes
- **Observability**: Emit OTLP traces with CloudEvents ID as trace_id

## Troubleshooting

### Common Issues

1. **Protobuf version mismatches**: Ensure all implementations use the canonical spec
2. **Transport configuration**: Verify QoS settings match requirements
3. **Message size limits**: Check MCP prompt and LTP frame size constraints
4. **Compression errors**: Verify zstd compression/decompression implementation
5. **Trace correlation**: Ensure CloudEvents ID propagates correctly

### Debug Mode

Run conformance tests with verbose output:
```bash
./test-runner/run-conformance.py --implementation your-impl --verbose
```

### Test Vector Validation

Validate your test vectors:
```bash
python spec/v1.0/conformance/test-vectors/generate-test-vectors.py --validate
```

## Contributing

To contribute improvements to the specification or conformance tests:

1. Update the canonical protobuf definitions in [`/spec/v1.0/ecps.proto`](./ecps.proto)
2. Add corresponding test cases in [`conformance/test-vectors/test-cases.yaml`](./conformance/test-vectors/test-cases.yaml)
3. Update implementation guides and documentation
4. Run full conformance test suite to verify changes

## Support

For questions about ECPS v1.0 implementation or conformance testing:

- Review the [Protocol Specification](./docs/protocol-specification.md)
- Check the [Conformance Test Documentation](./conformance/README.md)
- Examine existing implementations in [`/ecps-sdk/`](../ecps-sdk/)