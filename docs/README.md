# ECPS Documentation

This directory contains comprehensive documentation for the Embodied Cognition Protocol Stack (ECPS) - the "ROS 2 for Agentic AI Robotics".

## 📚 Documentation Index

### Core Documentation
- **[Academic Paper](paper.tex)** - Complete academic paper describing ECPS architecture and implementation
- **[Design Document](DesignDoc.md)** - Technical design and architecture overview
- **[Security Hardening](SECURITY_HARDENING.md)** - P2 security implementation guide

### API and Integration
- **[Unified API](UNIFIED_API.md)** - Complete API reference and usage guide
- **[Unified API Updates](UNIFIED_API_UPDATES.md)** - Recent API changes and improvements
- **[Identity Forwarding](IDENTITY_FORWARDING.md)** - Identity management and forwarding implementation
- **[KMS Integration](KMS_INTEGRATION_README.md)** - Key Management Service integration guide

### Implementation Status
- **[Architecture Fixes Status](ARCHITECTURE_FIXES_STATUS.md)** - Current implementation status and fixes
- **[Verification Report](VERIFICATION_REPORT.md)** - System verification and validation results

## 🚀 Quick Start

For getting started with ECPS, see:
1. **[Main README](../README.md)** - Installation and basic usage
2. **[Golden Path Example](../../examples/golden-path/README.md)** - Complete agentic AI robotics workflow
3. **[Protocol Specification](../spec/v1.0/docs/protocol-specification.md)** - Detailed protocol documentation

## 🏗️ Architecture Overview

ECPS provides a complete 7-layer protocol stack for agentic AI robotics:

```
┌─────────────────────────────────────────────────────────────┐
│                    Trust Layer (Security)                   │
├─────────────────────────────────────────────────────────────┤
│ L7: Actuation (EAP) - Robot Control & Action Execution     │
├─────────────────────────────────────────────────────────────┤
│ L6: Cognition (MCP/MEP) - AI Reasoning & Memory            │
├─────────────────────────────────────────────────────────────┤
│ L5: Perception (LTP) - Sensor Data & Computer Vision       │
├─────────────────────────────────────────────────────────────┤
│ L4: Observability - Telemetry & Monitoring                 │
├─────────────────────────────────────────────────────────────┤
│ L3: Serialization - Protocol Buffers & CloudEvents        │
├─────────────────────────────────────────────────────────────┤
│ L2: Transport - DDS/RTPS, gRPC, MQTT                       │
└─────────────────────────────────────────────────────────────┘
```

## 🤖 Agentic AI Robotics

ECPS enables the next generation of robotics where:
- **AI agents control robot bodies** rather than pre-programmed behaviors
- **LLMs reason about actions** based on real-time perception
- **Robots learn and adapt** through memory and experience
- **Natural language commands** are understood and executed
- **Autonomous decision making** replaces manual task specification

## 🔒 Security Features

ECPS includes production-grade P2 security hardening:
- **JWT Secret Rotation** - Automatic token rotation with configurable intervals
- **Mutual TLS (mTLS)** - Certificate-based authentication between all nodes
- **HSM/TPM Integration** - Hardware security module support
- **Protobuf Fuzzing** - Security testing with Atheris and libFuzzer
- **Role-Based Access Control** - Fine-grained permissions and authorization

## 📊 Performance Targets

ECPS is designed for real-time robotics applications:
- **Perception Latency**: < 50ms
- **Cognition Latency**: < 100ms
- **End-to-End Latency**: < 200ms (camera → robot action)
- **Throughput**: > 30 FPS sensor processing
- **Availability**: 99.9% uptime target

## 🌐 Cross-Language Support

ECPS provides identical functionality across multiple languages:
- **Python**: AI/ML ecosystem integration (OpenAI, PyTorch, etc.)
- **Go**: High-performance system services and robot control
- **JavaScript/TypeScript**: Web interfaces and monitoring
- **C++**: Real-time embedded systems
- **Java**: Enterprise integration

## 📖 Additional Resources

### Examples
- **[Golden Path](../../examples/golden-path/)** - Complete agentic AI robotics workflow
- **[Python Examples](../ecps_uv/examples/)** - Python SDK usage examples
- **[Go Examples](../ecps-go/examples/)** - Go implementation examples

### Testing
- **[Test Suite](../tests/)** - Comprehensive test coverage
- **[Conformance Tests](../spec/v1.0/conformance/)** - Protocol compliance validation
- **[Security Tests](../tests/fuzz_protobuf.py)** - Security validation and fuzzing

### Tools
- **[Binding Generator](../../scripts/generate-bindings.sh)** - Multi-language binding generation
- **[HSM Enrollment](../scripts/hsm-enrollment.sh)** - Hardware security setup
- **[EAP Log Tool](../ecps_uv/tools/eaplog_tool.py)** - Action log management

## 🤝 Contributing

For contributing to ECPS documentation:
1. Follow the existing documentation structure
2. Use clear, technical language
3. Include code examples where appropriate
4. Update this index when adding new documents
5. Ensure all links are functional

## 📄 License

All documentation is released under the MIT License to enable broad adoption and third-party implementations.

---

**ECPS: Enabling the future of agentic AI robotics** 🤖✨