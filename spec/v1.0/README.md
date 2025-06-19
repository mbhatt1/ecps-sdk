# ECPS v1.0 Protocol Specification

This directory contains the canonical protocol definitions for ECPS (Embodied Cognition Protocol Stack) version 1.0.

## Contents

- [`ecps.proto`](./ecps.proto) - Protocol Buffer definitions for all ECPS messages
- [`conformance/`](./conformance/) - Conformance test suite and test vectors
- [`docs/`](./docs/) - Protocol documentation and specifications

## Protocol Versions

- **MCP (Model Context Protocol)**: v1.0
- **LTP (Latent Tensor Protocol)**: v0.9  
- **MEP (Memory Exchange Protocol)**: v1.0
- **EAP (Embodied Action Protocol)**: v0.1

## Conformance Testing

See the [`conformance/`](./conformance/) directory for test runners and test vectors that validate ECPS implementations across different languages and transport layers.

## Implementation Guidelines

All ECPS implementations MUST conform to the protocol definitions in this specification. See the conformance tests for validation requirements.