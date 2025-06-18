# ECPS Go SDK

This is the Go implementation of the Embodied Cognition Protocol Stack (ECPS), providing a complete framework for robotic and embodied AI systems communication.

## Overview

The ECPS Go SDK implements the complete Embodied Cognition Protocol Stack with idiomatic Go code. It provides:

- **Transport Layer** (L3): Abstraction over DDS/RTPS, gRPC, and MQTT transport protocols
- **Perception Layer** (L4): Latent Tensor Protocol (LTP) for efficient tensor transmission
- **Cognition Layer** (L6): Model Context Protocol (MCP) and Memory Event Protocol (MEP)
- **Actuation Layer** (L7): Embodied Action Protocol (EAP) for robotics and control

## Architecture

The SDK follows a layered architecture:

```
┌────────────────────────────────────────────────────────────┐
│                    Application Layer                       │
├────────────────────────────────────────────────────────────┤
│                      Actuation (L7)                        │
│                    ┌─────────────────┐                     │
│                    │       EAP       │                     │
│                    └─────────────────┘                     │
├────────────────────────────────────────────────────────────┤
│                      Cognition (L6)                        │
│     ┌─────────────────┐           ┌─────────────────┐      │
│     │       MCP       │           │       MEP       │      │
│     └─────────────────┘           └─────────────────┘      │
├────────────────────────────────────────────────────────────┤
│                     Perception (L4)                        │
│                    ┌─────────────────┐                     │
│                    │       LTP       │                     │
│                    └─────────────────┘                     │
├────────────────────────────────────────────────────────────┤
│                     Transport (L3)                         │
│ ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│ │     DDS     │  │    gRPC     │  │        MQTT         │  │
│ └─────────────┘  └─────────────┘  └─────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

## Features

- **Transport Agnostic**: Works across DDS, gRPC, and MQTT with the same API
- **Protocol Buffers**: Type-safe serialization with Protocol Buffers
- **CloudEvents**: Standard envelope format for all messages
- **OpenTelemetry**: Built-in observability with tracing, metrics, and logging
- **Async I/O**: Non-blocking asynchronous communication
- **Conformance Profiles**: Support for Edge-Lite, Standard, and Cloud-Fleet profiles

## Installation

```bash
go get github.com/ecps/ecps-go
```

## Dependencies

The SDK requires the following dependencies:

- Go 1.18 or higher
- Protocol Buffers
- CloudEvents Go SDK
- OpenTelemetry Go SDK
- CycloneDDS-Go (for DDS transport)

## Quick Start

### Create a Client

```go
package main

import (
    "context"
    "log"

    "github.com/ecps/ecps-go/pkg/core"
    "github.com/ecps/ecps-go/pkg/transport"
)

func main() {
    // Create context
    ctx := context.Background()

    // Create configuration
    config := core.DefaultConfig()
    config.AppID = "my-ecps-app"

    // Create transport
    transportImpl, err := transport.NewDDSTransport(ctx)
    if err != nil {
        log.Fatalf("Failed to create transport: %v", err)
    }

    // Create client
    client, err := core.NewClient(config, transportImpl, nil)
    if err != nil {
        log.Fatalf("Failed to create client: %v", err)
    }
    defer client.Close()

    // Use the client with protocol handlers
    // ...
}
```

### Send a Tensor (LTP)

```go
import (
    "github.com/ecps/ecps-go/pkg/perception"
)

// Create LTP handler
ltpHandler, err := perception.NewLTPHandler(
    client.Transport(),
    client.Serializer(),
    client.Telemetry(),
    client.Logger(),
)
if err != nil {
    log.Fatalf("Failed to create LTP handler: %v", err)
}

// Create tensor data (example: 2x3 matrix)
tensorData := []float32{1.0, 2.0, 3.0, 4.0, 5.0, 6.0}

// Define tensor metadata
metadata := &perception.TensorMetadata{
    Shape:       []int{2, 3},
    DType:       "float32",
    ContentType: "tensor/float",
    SpaceName:   "sample_space",
    FrameID:     "sample_frame",
    Timestamp:   time.Now(),
}

// Send tensor
tensorID, err := ltpHandler.SendTensor(ctx, tensorData, metadata, nil)
if err != nil {
    log.Fatalf("Failed to send tensor: %v", err)
}

log.Printf("Sent tensor with ID: %s", tensorID)
```

### Send a Prompt (MCP)

```go
import (
    "encoding/json"
    "github.com/ecps/ecps-go/pkg/cognition"
)

// Create MCP handler
mcpHandler, err := cognition.NewMCPHandler(
    client.Transport(),
    client.Serializer(),
    client.Telemetry(),
    client.Logger(),
)
if err != nil {
    log.Fatalf("Failed to create MCP handler: %v", err)
}

// Create prompt
prompt := "What is the capital of France?"

// Create tool JSON (optional)
toolParams := map[string]interface{}{
    "allowed_tools": []string{"search", "calculator"},
}
toolJSON, _ := json.Marshal(toolParams)

// Send prompt
messageID, err := mcpHandler.Send(
    ctx,
    prompt,
    "",  // Generate message ID
    toolJSON,
    map[string]string{"lang": "en"},
    nil, // Default QoS
)
if err != nil {
    log.Fatalf("Failed to send prompt: %v", err)
}

log.Printf("Sent prompt with ID: %s", messageID)
```

### Create Memory (MEP)

```go
import (
    "github.com/ecps/ecps-go/pkg/cognition"
)

// Create MEP handler
mepHandler, err := cognition.NewMEPHandler(
    client.Transport(),
    client.Serializer(),
    client.Telemetry(),
    client.Logger(),
)
if err != nil {
    log.Fatalf("Failed to create MEP handler: %v", err)
}

// Create memory content
content := []byte(`{"type": "fact", "content": "Paris is the capital of France"}`)

// Create memory metadata
metadata := &cognition.MemoryEventMetadata{
    ContentType: "application/json",
    Labels: map[string]string{
        "category": "geography",
        "source":   "user",
    },
    Timestamp: time.Now(),
}

// Create memory
memoryID, err := mepHandler.CreateMemory(ctx, content, metadata, nil)
if err != nil {
    log.Fatalf("Failed to create memory: %v", err)
}

log.Printf("Created memory with ID: %s", memoryID)
```

### Send Action (EAP)

```go
import (
    "github.com/ecps/ecps-go/pkg/actuation"
)

// Create EAP handler
eapHandler, err := actuation.NewEAPHandler(
    client.Transport(),
    client.Serializer(),
    client.Telemetry(),
    client.Logger(),
)
if err != nil {
    log.Fatalf("Failed to create EAP handler: %v", err)
}

// Define action parameters
target := "robot_arm"
actionName := "move_to_position"
parameters := map[string]interface{}{
    "position": []float64{0.5, 0.3, 0.7},
    "speed":    0.8,
}

// Send direct action
actionID, err := eapHandler.PerformDirectAction(
    ctx,
    target,
    actionName,
    parameters,
    nil,   // No payload
    5000,  // 5 second timeout
    50,    // Medium priority
    nil,   // Default QoS
)
if err != nil {
    log.Fatalf("Failed to send action: %v", err)
}

log.Printf("Sent action with ID: %s", actionID)
```

## Examples

The SDK includes complete examples in the `examples` directory:

- `basic_client`: Demonstrates how to create a client and send messages using all protocols
- `basic_server`: Shows how to create a server that handles incoming messages

Run the examples:

```bash
# Start the server
go run examples/basic_server/main.go

# In another terminal, run the client
go run examples/basic_client/main.go
```

## Conformance Profiles

The SDK supports three conformance profiles:

1. **Edge-Lite**: Minimal implementation for resource-constrained devices
2. **Standard**: Complete implementation with all features
3. **Cloud-Fleet**: Extended implementation for cloud and fleet management

Configure the profile:

```go
config := core.DefaultConfig()
config.ConformanceProfile = core.ProfileStandard
```

## Transport Options

### DDS/RTPS

```go
transport, err := transport.NewDDSTransport(ctx)
```

### gRPC

```go
transport, err := transport.NewGRPCTransport(ctx, "localhost:50051")
```

### MQTT

```go
transport, err := transport.NewMQTTTransport(ctx, "tcp://localhost:1883")
```

## Contributing

Contributions are welcome! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for details.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.