# ECPS Security Hardening Guide

This document describes the security hardening features implemented in ECPS-UV SDK, including JWT secret rotation, mTLS between nodes, HSM/TPM enrollment, and protobuf fuzzing.

## Overview

The ECPS security hardening implementation provides multiple layers of security:

1. **JWT Secret Rotation**: Automatic rotation of JWT signing secrets
2. **Mutual TLS (mTLS)**: Certificate-based authentication between nodes
3. **Hardware Security Modules (HSM/TPM)**: Hardware-backed key storage
4. **Protobuf Fuzzing**: Security testing of message parsers

## JWT Secret Rotation

### Features

- Automatic secret rotation on startup
- Configurable rotation intervals
- Graceful transition with previous secret validation
- Persistent storage with secure permissions
- Callback system for secret updates

### Usage

```python
from ecps_uv.trust.jwt_rotation import initialize_jwt_rotation, start_jwt_rotation

# Initialize JWT rotation on startup
secret = initialize_jwt_rotation(
    rotation_interval_hours=24,
    secret_length=64,
    algorithm="HS256"
)

# Start automatic rotation
await start_jwt_rotation()

# Create and validate tokens
from ecps_uv.trust.jwt_rotation import get_jwt_manager

manager = get_jwt_manager()
token = manager.create_token({"user_id": "robot_001"}, expires_in_hours=1)
payload = manager.validate_token(token)
```

### Configuration

JWT secrets are stored in `~/.ecps/jwt_secrets.json` with 600 permissions:

```json
{
  "current": {
    "secret": "...",
    "created_at": "2025-01-01T00:00:00",
    "expires_at": "2025-01-03T00:00:00",
    "key_id": "abc123",
    "algorithm": "HS256"
  },
  "previous": {
    "secret": "...",
    "created_at": "2024-12-31T00:00:00",
    "expires_at": "2025-01-02T00:00:00",
    "key_id": "def456",
    "algorithm": "HS256"
  }
}
```

## Mutual TLS (mTLS)

### Features

- Automatic certificate generation and management
- CA certificate creation and signing
- Server and client certificate generation
- Support for gRPC, HTTP, and raw TCP connections
- Certificate validation and verification

### Usage

```python
from ecps_uv.trust.mtls import initialize_mtls, NodeIdentity

# Define node identity
node_identity = NodeIdentity(
    node_id="robot_001",
    common_name="robot-001.example.com",
    organization="ECPS Robotics",
    organizational_unit="Production Robots",
    country="US",
    state="California",
    locality="San Francisco",
    dns_names=["robot-001.local", "robot-001.example.com"],
    ip_addresses=["192.168.1.100"]
)

# Initialize mTLS
config = await initialize_mtls(node_identity)

# Use with gRPC
from ecps_uv.trust.mtls import get_mtls_transport

transport = get_mtls_transport()
server_credentials = transport.create_grpc_server_credentials()
channel_credentials = transport.create_grpc_channel_credentials()
```

### Certificate Structure

Certificates are stored in `~/.ecps/certs/`:

```
~/.ecps/certs/
├── ca-cert.pem          # Certificate Authority certificate
├── ca-key.pem           # CA private key (600 permissions)
├── server-cert.pem      # Server certificate
├── server-key.pem       # Server private key (600 permissions)
├── client-cert.pem      # Client certificate
└── client-key.pem       # Client private key (600 permissions)
```

## HSM/TPM Enrollment

### Features

- Automatic detection of HSM and TPM devices
- SoftHSM setup for testing environments
- TPM 2.0 support with persistent key handles
- Key generation and management
- PKCS#11 integration for HSM devices

### Usage

```bash
# Detect available devices
./scripts/hsm-enrollment.sh detect

# Setup SoftHSM for testing
./scripts/hsm-enrollment.sh setup-softhsm

# Setup TPM
./scripts/hsm-enrollment.sh setup-tpm

# Run complete setup
./scripts/hsm-enrollment.sh full-setup

# Test functionality
./scripts/hsm-enrollment.sh test
```

### Configuration

HSM/TPM configuration is stored in `~/.ecps/hardware_security_config.json`:

```json
{
  "hardware_security": {
    "enabled": true,
    "hsm": {
      "enabled": true,
      "config_path": "/home/user/.ecps/hsm/softhsm_config.json",
      "signing_key_id": "01",
      "encryption_key_id": "02"
    },
    "tpm": {
      "enabled": true,
      "config_path": "/home/user/.ecps/tpm/tmp_config.json",
      "signing_handle": "0x81000001",
      "encryption_handle": "0x81000002"
    }
  }
}
```

### SoftHSM Configuration

For testing environments, SoftHSM is configured in `~/.ecps/hsm/softhsm_config.json`:

```json
{
  "token_label": "ecps-token",
  "so_pin": "123456",
  "user_pin": "654321",
  "config_file": "/home/user/.ecps/hsm/softhsm2.conf",
  "pkcs11_library": "/usr/lib/softhsm/libsofthsm2.so"
}
```

### TPM Configuration

TPM setup creates persistent key handles in `~/.ecps/tpm/tpm_config.json`:

```json
{
  "signing_handle": "0x81000001",
  "encryption_handle": "0x81000002",
  "primary_context": "/home/user/.ecps/tpm/primary.ctx",
  "setup_date": "2025-01-01T00:00:00Z"
}
```

## Protobuf Fuzzing

### Features

- Atheris-based fuzzing for Python protobuf parsers
- libFuzzer harness generation for C++ implementations
- Comprehensive test case generation
- Error detection and reporting
- Coverage-guided fuzzing

### Usage

```bash
# Install fuzzing dependencies
pip install atheris

# Run standalone fuzzing
python tests/fuzz_protobuf.py

# Run Atheris fuzzing
python tests/fuzz_protobuf.py --atheris

# Generate libFuzzer harness
python tests/fuzz_protobuf.py --libfuzzer

# Build and run libFuzzer (requires clang)
cd tests
./build_libfuzzer.sh
./ecps_protobuf_fuzzer
```

### Fuzzing Targets

The fuzzer tests all ECPS message types:

- **MCP**: Model Context Protocol messages
- **LTP**: Latent Tensor Protocol messages
- **EAP**: Embodied Action Protocol messages
- **QueryReq**: Memory Exchange Protocol queries
- **Ack**: Acknowledgment messages
- **LTPChunk**: LTP chunk messages
- **LTPAck**: LTP acknowledgment messages

### Test Cases

The fuzzer generates various test cases:

- Empty messages
- Single byte inputs
- Valid protobuf patterns
- Invalid protobuf patterns
- Large messages
- Nested messages
- Random data

## Integration with ECPS

### Startup Sequence

```python
import asyncio
from ecps_uv.trust.jwt_rotation import initialize_jwt_rotation, start_jwt_rotation
from ecps_uv.trust.mtls import initialize_mtls, NodeIdentity

async def secure_startup():
    # 1. Initialize JWT rotation
    jwt_secret = initialize_jwt_rotation(rotation_interval_hours=24)
    
    # 2. Setup mTLS
    node_identity = NodeIdentity(
        node_id="robot_001",
        common_name="robot-001.example.com",
        organization="ECPS Robotics",
        # ... other fields
    )
    mtls_config = await initialize_mtls(node_identity)
    
    # 3. Start automatic JWT rotation
    await start_jwt_rotation()
    
    # 4. Initialize ECPS with security
    # ... ECPS initialization code
    
    return jwt_secret, mtls_config

# Run secure startup
jwt_secret, mtls_config = asyncio.run(secure_startup())
```

### Transport Layer Integration

```python
from ecps_uv.transport.grpc import GRPCTransport
from ecps_uv.trust.mtls import get_mtls_transport

# Create secure gRPC transport
mtls_transport = get_mtls_transport()
server_credentials = mtls_transport.create_grpc_server_credentials()
channel_credentials = mtls_transport.create_grpc_channel_credentials()

grpc_transport = GRPCTransport(
    server_credentials=server_credentials,
    channel_credentials=channel_credentials
)
```

## Security Best Practices

### JWT Security

1. **Rotation**: Rotate secrets every 24 hours minimum
2. **Storage**: Store secrets with 600 permissions
3. **Validation**: Always validate tokens with current and previous secrets
4. **Expiration**: Use short token expiration times (1-4 hours)

### mTLS Security

1. **Certificate Validation**: Always verify peer certificates
2. **Key Protection**: Store private keys with 600 permissions
3. **Certificate Rotation**: Rotate certificates annually
4. **Hostname Verification**: Enable hostname verification for clients

### HSM/TPM Security

1. **Hardware Verification**: Verify HSM/TPM authenticity
2. **Key Isolation**: Use separate keys for signing and encryption
3. **Access Control**: Implement proper PIN/password policies
4. **Backup**: Securely backup key material

### Fuzzing Security

1. **Regular Testing**: Run fuzzing tests in CI/CD pipelines
2. **Coverage**: Ensure high code coverage in fuzzing
3. **Error Handling**: Implement robust error handling
4. **Input Validation**: Validate all protobuf inputs

## Monitoring and Logging

### Security Events

All security operations are logged with appropriate levels:

```python
import logging

# JWT rotation events
logger.info("JWT secret rotated. New key_id: abc123")
logger.warning("JWT token validation failed with all available secrets")

# mTLS events
logger.info("mTLS initialized for node: robot_001")
logger.error("Peer certificate verification failed")

# HSM/TPM events
logger.info("HSM key pair generated")
logger.warning("TPM not detected")
```

### Metrics

Key security metrics to monitor:

- JWT rotation frequency
- Certificate expiration dates
- HSM/TPM availability
- Fuzzing test results
- Authentication failures
- TLS handshake failures

## Troubleshooting

### Common Issues

1. **JWT Validation Failures**
   - Check secret rotation timing
   - Verify token expiration
   - Ensure proper secret storage

2. **mTLS Connection Failures**
   - Verify certificate validity
   - Check hostname verification settings
   - Ensure proper CA trust chain

3. **HSM/TPM Issues**
   - Verify device availability
   - Check permissions and access
   - Validate PKCS#11 library paths

4. **Fuzzing Failures**
   - Install required dependencies
   - Check protobuf message definitions
   - Verify compiler settings for libFuzzer

### Debug Commands

```bash
# Check JWT secrets
cat ~/.ecps/jwt_secrets.json

# Verify certificates
openssl x509 -in ~/.ecps/certs/server-cert.pem -text -noout

# Test HSM
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so --list-objects

# Test TPM
tpm2_getcap properties-fixed

# Run fuzzing with verbose output
python tests/fuzz_protobuf.py --verbose
```

## Compliance and Standards

The ECPS security hardening implementation follows these standards:

- **NIST Cybersecurity Framework**: Implementation of security controls
- **ISO 27001**: Information security management
- **FIPS 140-2**: Cryptographic module standards (for HSM)
- **Common Criteria**: Security evaluation criteria
- **OWASP**: Web application security practices

## Future Enhancements

Planned security enhancements:

1. **Key Escrow**: Secure key backup and recovery
2. **Certificate Transparency**: CT log integration
3. **Hardware Attestation**: Remote attestation support
4. **Zero-Trust Architecture**: Comprehensive zero-trust implementation
5. **Quantum-Resistant Cryptography**: Post-quantum cryptographic algorithms