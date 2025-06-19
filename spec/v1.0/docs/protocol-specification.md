# ECPS v1.0 Protocol Specification

## Overview

The Embodied Cognition Protocol Stack (ECPS) v1.0 defines a complete, transport-agnostic protocol stack for AI-agent to robot communication. This specification provides deterministic, replayable, and auditable communication protocols across four key layers:

- **L6 Cognition**: Model Context Protocol (MCP v1.0) and Memory Exchange Protocol (MEP v1.0)
- **L5 Perception**: Latent Tensor Protocol (LTP v0.9)
- **L7 Actuation**: Embodied Action Protocol (EAP v0.1)

## Protocol Definitions

### Model Context Protocol (MCP v1.0)

**Purpose**: Delivers natural-language prompts and optional tool schemas to AI agent reasoning cores.

**Message Structure**:
```protobuf
message MCP {
  string spec = 1;                    // MUST be "mcp/1.0"
  string id = 2;                      // CloudEvents id mirror
  string prompt = 3;                  // ≤16 KiB UTF-8
  bytes tool_json = 4;                // Optional JSON tool schema
  map<string, string> meta = 5;       // Metadata
}
```

**Constraints**:
- `prompt` field MUST be ≤ 16 KiB UTF-8 encoded
- `spec` field MUST be exactly "mcp/1.0"
- `id` field MUST mirror CloudEvents id for tracing

### Latent Tensor Protocol (LTP v0.9)

**Purpose**: Transports compressed N-dimensional arrays representing latent embeddings or processed sensor features.

**Message Structure**:
```protobuf
message LTP {
  string spec = 1;                    // MUST be "ltp/0.9"
  LTPFrameHeader header = 2;          // Frame header for wire protocol
  bytes tensor_zstd = 3;              // zstd-compressed ND array
  repeated uint32 shape = 4;          // Tensor dimensions [B,L,D]
  string dtype = 5;                   // Data type specification
  string frame_id = 6;                // Reference coordinate frame
  uint64 timestamp_ns = 7;            // Nanoseconds since Unix epoch
  uint32 compression_level = 8;       // zstd compression level (1-22)
  uint64 original_size = 9;           // Original tensor size before compression
  map<string, string> attributes = 10; // Additional attributes
}
```

**Data Types**: Supported `dtype` values:
- Floating point: `f32`, `f16`, `f64`
- Signed integers: `i8`, `i16`, `i32`, `i64`
- Unsigned integers: `u8`, `u16`, `u32`, `u64`
- Boolean: `bool`

**Constraints**:
- `tensor_zstd` MUST be zstd-compressed
- LTP frames SHOULD be ≤ 1 MiB for DDS compatibility
- `compression_level` MUST be between 1-22

**Frame Header**: Provides wire-level protocol support for chunking and acknowledgments.

### Memory Exchange Protocol (MEP v1.0)

**Purpose**: Standardized interface for AI agents to store and query latent embeddings in distributed memory stores.

**Service Definition**:
```protobuf
service MemoryStore {
  rpc Put(LTP) returns (Ack);
  rpc Query(QueryReq) returns (stream LTP);
}
```

**Query Semantics**:
- Servers MUST return at most `k` embeddings
- Results MUST have cosine similarity ≥ `min_sim`
- Results SHOULD be ordered by similarity (highest first)

**Eviction Policy**: LRU (Least Recently Used) is RECOMMENDED.

### Embodied Action Protocol (EAP v0.1)

**Purpose**: Defines action commands for robot actuation with deterministic replay support.

**Message Structure**:
```protobuf
message EAP {
  string spec = 1;                    // MUST be "eap/0.1"
  string id = 2;                      // CloudEvents id mirror
  bytes state_sha = 3;                // SHA-256 of perceptual snapshot
  oneof body { /* action types */ }
  map<string, string> meta = 20;      // Metadata (e.g., safety flags)
}
```

**Action Types**:
- `RobotPose`: Set robot pose with quaternion orientation
- `GripperOp`: Gripper control (open/close/grip)
- `CloudOp`: External API calls with OAuth2 support
- `SimStep`: Simulation stepping control
- `NavigateOp`: Navigation commands
- `ManipulateOp`: Manipulation operations (pick/place/push/pull)

**Deterministic Replay**: The `state_sha` field contains SHA-256 hash of the perceptual state, enabling deterministic action replay.

## CloudEvents Integration

All ECPS messages mirror CloudEvents v1.0 attributes:
- `id`: Unique event identifier (used as OTLP trace_id)
- `source`: Event source URI
- `type`: Event type classification
- `specversion`: CloudEvents specification version

This enables end-to-end tracing from perception through cognition to actuation.

## Transport Bindings

ECPS supports multiple transport layers:

### DDS/RTPS Binding
- **Use Case**: Real-time local control, high-frequency data streaming
- **QoS Requirements**:
  - Reliability: `RELIABLE` for critical messages, `BEST_EFFORT` for high-frequency sensor data
  - Durability: `TRANSIENT_LOCAL` for state messages, `VOLATILE` for transient data
  - History: `KEEP_LAST(4)` for EAP messages

### gRPC/HTTP-2 Binding
- **Use Case**: Cloud robot fleets, WAN communication
- **Features**: Supports streaming, back-pressure, request/response patterns
- **Streaming**: MEP queries use server streaming for continuous results

### MQTT 5 Binding
- **Use Case**: Constrained IoT devices, event-driven architectures
- **QoS**: MUST use QoS 1+ for message delivery guarantees

## Conformance Requirements

### Message Validation
1. All `spec` fields MUST contain exact version strings
2. CloudEvents `id` fields MUST be unique and properly formatted
3. Size constraints MUST be enforced (MCP prompts ≤ 16 KiB, LTP frames ≤ 1 MiB)
4. Compression MUST use zstd for LTP tensors

### Transport Requirements
1. Implementations MUST support at least one transport binding
2. DDS implementations MUST follow ROS 2 QoS guidelines
3. gRPC implementations MUST support streaming for MEP
4. MQTT implementations MUST use QoS 1+

### Observability Requirements
1. All implementations MUST emit OTLP traces
2. CloudEvents `id` MUST be used as OTLP `trace_id`
3. Key metrics MUST be emitted (latency, bandwidth, error rates)

## Security Considerations

1. **Transport Security**: TLS/DTLS MUST be used for WAN communications
2. **Authentication**: OAuth2 support for CloudOp external API calls
3. **Integrity**: SHA-256 hashing for action replay verification
4. **Authorization**: Transport-layer access controls RECOMMENDED

## Versioning Strategy

- **Major versions**: Breaking changes to message structure or semantics
- **Minor versions**: Backward-compatible additions (new fields, optional features)
- **Patch versions**: Bug fixes, clarifications, non-breaking updates

Version compatibility MUST be maintained within major version boundaries.