# ECPS v1.0 Conformance Test Suite

This directory contains the conformance test suite for ECPS v1.0 implementations. The test suite validates protocol compliance across different languages, transport layers, and deployment scenarios.

## Structure

- [`test-vectors/`](./test-vectors/) - Canonical test messages in binary and JSON formats
- [`test-runner/`](./test-runner/) - Language-agnostic test runner implementation
- [`schemas/`](./schemas/) - JSON schemas for test configuration and results
- [`reports/`](./reports/) - Example test reports and validation results

## Test Categories

### Protocol Message Tests
- **Message Structure**: Validates protobuf message structure and field constraints
- **Size Limits**: Enforces size constraints (MCP prompts ≤ 16 KiB, LTP frames ≤ 1 MiB)
- **Version Strings**: Validates exact version string requirements
- **CloudEvents Integration**: Verifies CloudEvents attribute mirroring

### Transport Layer Tests
- **DDS/RTPS**: QoS profile validation, message delivery, real-time constraints
- **gRPC/HTTP-2**: Streaming behavior, error handling, back-pressure
- **MQTT 5**: QoS levels, topic structure, message persistence

### Behavioral Tests
- **MEP Query Semantics**: Cosine similarity thresholds, result ordering, k-limiting
- **LTP Compression**: zstd compression/decompression, integrity verification
- **EAP Determinism**: State hash verification, replay consistency
- **Observability**: OTLP trace emission, metric collection

### Integration Tests
- **End-to-End**: Complete perception → cognition → actuation flows
- **Multi-Transport**: Cross-transport message routing and conversion
- **Error Handling**: Graceful degradation, timeout behavior, retry logic

## Running Tests

### Prerequisites
- Protocol buffer compiler (`protoc`)
- Language-specific ECPS implementation
- Transport layer dependencies (DDS, gRPC, MQTT broker)

### Basic Usage
```bash
# Run all conformance tests
./test-runner/run-conformance.py --implementation /path/to/ecps-impl

# Run specific test category
./test-runner/run-conformance.py --category protocol-messages --implementation /path/to/ecps-impl

# Generate test report
./test-runner/run-conformance.py --implementation /path/to/ecps-impl --report-format json > report.json
```

### Implementation Requirements

Your ECPS implementation must provide a conformance test interface:

```bash
# Message validation
ecps-conformance validate-message --type MCP --input message.bin
ecps-conformance validate-message --type LTP --input tensor.bin

# Transport tests  
ecps-conformance transport-test --transport dds --config dds-config.yaml
ecps-conformance transport-test --transport grpc --config grpc-config.yaml

# Behavioral tests
ecps-conformance mep-query --query query.bin --expected results.bin
ecps-conformance eap-replay --actions actions.bin --state-hashes hashes.txt
```

## Test Vector Format

Test vectors are provided in both binary (protobuf) and JSON formats:

```
test-vectors/
├── mcp/
│   ├── valid/
│   │   ├── basic-prompt.bin
│   │   ├── basic-prompt.json
│   │   ├── with-tools.bin
│   │   └── with-tools.json
│   └── invalid/
│       ├── oversized-prompt.bin
│       └── invalid-spec.bin
├── ltp/
│   ├── valid/
│   │   ├── float32-tensor.bin
│   │   ├── compressed-large.bin
│   │   └── chunked-transmission.bin
│   └── invalid/
│       ├── oversized-frame.bin
│       └── invalid-compression.bin
├── eap/
│   └── valid/
│       ├── robot-pose.bin
│       ├── gripper-op.bin
│       └── navigation.bin
└── mep/
    ├── queries/
    │   ├── basic-query.bin
    │   └── similarity-threshold.bin
    └── responses/
        ├── query-results.bin
        └── empty-results.bin
```

## Certification Levels

### Level 1: Basic Conformance
- Message structure validation
- Size constraint enforcement
- Version string compliance
- Single transport support

### Level 2: Standard Conformance  
- Multiple transport support
- Behavioral test compliance
- Observability integration
- Error handling validation

### Level 3: Full Conformance
- All transport layers supported
- Complete integration test suite
- Performance benchmarks met
- Security requirements validated

## Contributing Test Cases

To add new test cases:

1. Create test vector files in appropriate format
2. Add test case definition to `test-cases.yaml`
3. Update expected results in `expected-results/`
4. Run validation: `./validate-test-case.py new-test-case`

See [`CONTRIBUTING.md`](./CONTRIBUTING.md) for detailed guidelines.