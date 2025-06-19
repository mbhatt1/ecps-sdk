# Unified ECPS Protocol (UEP) - Single API for All Operations

## 🔥 Revolutionary API Consolidation

The ECPS-UV SDK now provides a **single unified interface** that consolidates ALL protocols into one consistent API, dramatically simplifying development and reducing cognitive load.

## What's Unified

The Unified ECPS Protocol (UEP) consolidates these previously separate protocols:

- **MCP** (Model Context Protocol) for AI prompts
- **MEP** (Memory Exchange Protocol) for memory storage/retrieval  
- **EAP** (Event Action Protocol) for actuation/actions
- **LTP** (Latent Tensor Protocol) for perception data
- **A2A** coordination for agent-to-agent communication
- **Trust** and security operations
- **Telemetry** and observability

## Before vs After

### ❌ OLD WAY (Separate APIs)

```python
# Multiple handlers for different protocols
from ecps_uv.cognition import MCPHandler, MEPClient
from ecps_uv.actuation import EAPHandler
from ecps_uv.perception import LTPHandler
from ecps_uv.coordination import A2ACoordinator
from ecps_uv.trust import TrustManager

mcp_handler = MCPHandler(transport, serializer, telemetry)
mep_client = MEPClient(transport, serializer, telemetry)
eap_handler = EAPHandler(transport, serializer, telemetry)
ltp_handler = LTPHandler(transport, serializer, telemetry)
a2a_coordinator = A2ACoordinator(transport, serializer, telemetry)
trust_manager = TrustManager(transport, serializer, telemetry)

# Different methods for each operation
await mcp_handler.send(prompt, message_id, tool_json, meta)
await mep_client.put(tensor_zstd, shape, dtype, frame_id, timestamp_ns)
await eap_handler.send(action_type, action_data, message_id, state_sha, meta)
await ltp_handler.send(tensor_zstd, shape, dtype, frame_id, timestamp_ns)
await a2a_coordinator.coordinate(coordination_type, agent_ids, data)
await trust_manager.verify_identity(identity, trust_data)

# Different listening interfaces
await mcp_handler.listen(mcp_handlers)
await mep_client.listen_for_queries(mep_handlers)
await eap_handler.listen(eap_handlers)
# ... more listening setups

# Different querying interfaces
mcp_results = await mcp_handler.query_history()
mep_results = await mep_client.query(query_embedding, k, min_sim)
eap_results = await eap_handler.query_actions()
# ... different query methods
```

### ✅ NEW WAY (Unified API)

```python
# Single client with unified handler
from ecps_uv.core import ECPSClient, EdgeLiteProfile

client = ECPSClient(EdgeLiteProfile())

# Single method for ALL operations
await client.send_unified("prompt", prompt=prompt, tool_json=tool_json, meta=meta)
await client.send_unified("memory_put", tensor_zstd=tensor_zstd, shape=shape, dtype=dtype, frame_id=frame_id, timestamp_ns=timestamp_ns)
await client.send_unified("action", action_type=action_type, action_data=action_data, state_sha=state_sha, meta=meta)
await client.send_unified("perception", tensor_zstd=tensor_zstd, shape=shape, dtype=dtype, frame_id=frame_id, timestamp_ns=timestamp_ns)
await client.send_unified("coordinate", coordination_type=coordination_type, agent_ids=agent_ids, coordination_data=data)
await client.send_unified("trust", trust_operation="verify_identity", identity=identity, trust_data=trust_data)
await client.send_unified("telemetry", metric_type=metric_type, metric_data=metric_data, timestamp_ns=timestamp_ns)

# Single listening interface
handlers = {
    "prompt": [handle_prompt],
    "memory_put": [handle_memory_put],
    "action": [handle_action],
    "perception": [handle_perception],
    "coordinate": [handle_coordination],
    "trust": [handle_trust],
    "telemetry": [handle_telemetry],
}
await client.listen_unified(handlers)

# Single querying interface for ALL data types
memory_results = await client.query_unified("memory", {"k": 10, "min_sim": 0.8})
action_results = await client.query_unified("action", {"action_type": "set_pose", "limit": 5})
telemetry_results = await client.query_unified("telemetry", {"metric_type": "system_health", "limit": 10})

# Single statistics interface
stats = await client.get_unified_stats()
print(f"Memory embeddings: {stats['memory_embeddings']}")
print(f"Action history: {stats['action_history']}")
print(f"Telemetry data: {stats['telemetry_data']}")
```

## Complete Operation Types

The unified API supports these operation types:

### 1. **prompt** (MCP - Model Context Protocol)
```python
await client.send_unified("prompt", 
    prompt="Analyze the robot's current environment",
    tool_json=json.dumps(tool_schema).encode(),
    meta={"priority": "high", "agent_id": "robot_001"}
)
```

### 2. **memory_put** (MEP - Memory Exchange Protocol)
```python
await client.send_unified("memory_put",
    tensor_zstd=compressed_embedding,
    shape=[512],
    dtype="f32",
    frame_id="office_map_001",
    timestamp_ns=int(time.time() * 1e9)
)
```

### 3. **memory_query** (MEP - Memory Exchange Protocol)
```python
results = await client.send_unified("memory_query",
    query_embedding=query_tensor,
    k=10,
    min_sim=0.8
)
```

### 4. **action** (EAP - Event Action Protocol)
```python
await client.send_unified("action",
    action_type="set_pose",
    action_data={
        "position": {"x": 2.5, "y": 1.8, "z": 0.0},
        "orientation": {"roll": 0.0, "pitch": 0.0, "yaw": 1.57}
    },
    state_sha=b"sha256_hash_of_current_perception",
    meta={"urgency": "normal"}
)
```

### 5. **perception** (LTP - Latent Tensor Protocol)
```python
await client.send_unified("perception",
    tensor_zstd=compressed_image_data,
    shape=[224, 224, 3],
    dtype="uint8",
    frame_id="camera_front",
    timestamp_ns=int(time.time() * 1e9)
)
```

### 6. **coordinate** (A2A - Agent-to-Agent)
```python
await client.send_unified("coordinate",
    coordination_type="task_allocation",
    agent_ids=["robot_001", "robot_002", "robot_003"],
    coordination_data={
        "task": "warehouse_inventory",
        "zones": ["A1-A5", "B1-B5", "C1-C5"]
    },
    meta={"coordinator": "robot_001"}
)
```

### 7. **trust** (Trust and Security)
```python
await client.send_unified("trust",
    trust_operation="verify_identity",
    identity="robot_002",
    trust_data={
        "certificate": "-----BEGIN CERTIFICATE-----\n...",
        "signature": "base64_encoded_signature"
    },
    meta={"verification_level": "high"}
)
```

### 8. **telemetry** (Observability)
```python
await client.send_unified("telemetry",
    metric_type="system_health",
    metric_data={
        "cpu_usage": 45.2,
        "memory_usage": 67.8,
        "battery_level": 87.3
    },
    timestamp_ns=int(time.time() * 1e9),
    meta={"node_id": "robot_001"}
)
```

## Go Implementation

The unified API is also available in Go with identical functionality:

```go
// Create unified handler
uepHandler, err := cognition.NewUEPHandler(transport, serializer, telemetry, logger)

// All operations through single handler
uepHandler.SendPrompt(ctx, prompt, messageID, toolJSON, meta, qos)
uepHandler.StoreMemory(ctx, tensorZstd, shape, dtype, frameID, timestampNs, qos)
uepHandler.QueryMemory(ctx, queryEmbedding, k, minSim, qos)
uepHandler.SendAction(ctx, actionType, actionData, stateSHA, meta, qos)
uepHandler.SendPerception(ctx, tensorZstd, shape, dtype, frameID, timestampNs, qos)
uepHandler.CoordinateAgents(ctx, coordinationType, agentIDs, coordinationData, meta, qos)
uepHandler.ManageTrust(ctx, trustOperation, identity, trustData, meta, qos)
uepHandler.SendTelemetry(ctx, metricType, metricData, timestampNs, meta, qos)

// Unified interfaces
uepHandler.Listen(ctx, handlers, qos)
uepHandler.QueryUnified(dataType, queryParams)
uepHandler.GetStats()
```

## Benefits

### ✅ **Single API** for ALL protocols
No more juggling multiple handlers and different interfaces.

### ✅ **Consistent interface** across all operations
Same method signature pattern for all operation types.

### ✅ **Unified storage** and querying
All data types stored in a single backend with consistent querying.

### ✅ **Simplified error handling**
Single error handling pattern across all operations.

### ✅ **Better observability** and telemetry
Unified telemetry spans and metrics for all operations.

### ✅ **Easier testing** and debugging
Single interface to mock and test all functionality.

### ✅ **Reduced cognitive load** for developers
Learn one API instead of 7+ separate protocols.

## Migration Guide

### For Existing Code

The unified API is additive - existing separate protocol handlers still work for backward compatibility:

```python
# Old code still works
mcp_handler = MCPHandler(transport, serializer, telemetry)
await mcp_handler.send(prompt, message_id, tool_json, meta)

# But you can migrate to unified API
client = ECPSClient(config)
await client.send_unified("prompt", prompt=prompt, message_id=message_id, tool_json=tool_json, meta=meta)
```

### Recommended Migration Path

1. **Start with new projects**: Use the unified API for all new development
2. **Gradual migration**: Replace separate handlers one at a time in existing projects
3. **Testing**: Use unified API for easier integration testing
4. **Production**: Deploy unified API for simplified operations and monitoring

## Examples

- **Python**: `examples/unified_ecps_demo.py` - Complete demonstration
- **Go**: `ecps-go/examples/unified_demo/main.go` - Go implementation demo

## Implementation Details

The unified API is implemented through:

- **Python**: `ecps_uv.cognition.unified.UEPHandler`
- **Go**: `cognition.UEPHandler`
- **Core Integration**: Built into `ECPSClient` for seamless usage
- **Transport Agnostic**: Works with DDS, gRPC, and MQTT transports
- **Storage Backend**: Unified storage handling all data types
- **Telemetry Integration**: Comprehensive observability across all operations