#!/usr/bin/env python3
"""
Unified ECPS Protocol (UEP) Demo

This example demonstrates the new unified API that consolidates ALL ECPS protocols:
- MCP (Model Context Protocol) for AI prompts
- MEP (Memory Exchange Protocol) for memory storage/retrieval  
- EAP (Event Action Protocol) for actuation/actions
- LTP (Latent Tensor Protocol) for perception data
- A2A coordination for agent-to-agent communication
- Trust and security operations
- Telemetry and observability

Instead of using separate handlers for each protocol, everything goes through
a single unified interface.
"""

import asyncio
import json
import logging
import time
from typing import Dict, List, Any

import numpy as np

from ecps_uv.core import ECPSClient, EdgeLiteProfile
from ecps_uv.cognition.unified import UEPHandler

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def demonstrate_unified_api():
    """Demonstrate the unified ECPS API."""
    
    # Create ECPS client with Edge-Lite profile
    config = EdgeLiteProfile()
    client = ECPSClient(config)
    
    logger.info("🚀 Starting Unified ECPS Protocol (UEP) Demo")
    logger.info("=" * 60)
    
    try:
        # ========== 1. PROMPT OPERATIONS (MCP) ==========
        logger.info("📝 1. Sending AI Prompt (MCP)")
        
        prompt_result = await client.send_unified(
            "prompt",
            prompt="Analyze the robot's current environment and suggest optimal navigation path",
            tool_json=json.dumps({
                "type": "navigation_analysis",
                "parameters": {
                    "environment": "indoor_office",
                    "obstacles": ["desk", "chair", "person"],
                    "target": "conference_room_b"
                }
            }).encode(),
            meta={"priority": "high", "agent_id": "robot_001"}
        )
        logger.info(f"✅ Prompt sent with ID: {prompt_result}")
        
        # ========== 2. MEMORY OPERATIONS (MEP) ==========
        logger.info("\n🧠 2. Memory Storage and Retrieval (MEP)")
        
        # Create a sample embedding
        embedding = np.random.rand(512).astype(np.float32)
        
        # Store memory
        memory_result = await client.send_unified(
            "memory_put",
            tensor_zstd=embedding.tobytes(),  # In real use, this would be zstd compressed
            shape=[512],
            dtype="f32",
            frame_id="office_map_001",
            timestamp_ns=int(time.time() * 1e9)
        )
        logger.info(f"✅ Memory stored: {memory_result}")
        
        # Query similar memories
        query_result = await client.send_unified(
            "memory_query",
            query_embedding={
                "tensor_zstd": embedding.tobytes(),
                "shape": [512],
                "dtype": "f32",
                "frame_id": "office_map_query",
                "timestamp_ns": int(time.time() * 1e9)
            },
            k=5,
            min_sim=0.8
        )
        logger.info(f"✅ Found {len(query_result)} similar memories")
        
        # ========== 3. ACTION OPERATIONS (EAP) ==========
        logger.info("\n🤖 3. Robot Action Commands (EAP)")
        
        action_result = await client.send_unified(
            "action",
            action_type="set_pose",
            action_data={
                "position": {"x": 2.5, "y": 1.8, "z": 0.0},
                "orientation": {"roll": 0.0, "pitch": 0.0, "yaw": 1.57},
                "frame_id": "map"
            },
            state_sha=b"sha256_hash_of_current_perception",
            meta={"urgency": "normal", "estimated_duration": "5.2s"}
        )
        logger.info(f"✅ Action command sent with ID: {action_result}")
        
        # ========== 4. PERCEPTION OPERATIONS (LTP) ==========
        logger.info("\n👁️ 4. Perception Data (LTP)")
        
        # Create sample perception tensor (e.g., camera image features)
        perception_tensor = np.random.rand(224, 224, 3).astype(np.uint8)
        
        perception_result = await client.send_unified(
            "perception",
            tensor_zstd=perception_tensor.tobytes(),
            shape=[224, 224, 3],
            dtype="uint8",
            frame_id="camera_front",
            timestamp_ns=int(time.time() * 1e9)
        )
        logger.info(f"✅ Perception data sent with ID: {perception_result}")
        
        # ========== 5. COORDINATION OPERATIONS (A2A) ==========
        logger.info("\n🤝 5. Agent Coordination (A2A)")
        
        coordination_result = await client.send_unified(
            "coordinate",
            coordination_type="task_allocation",
            agent_ids=["robot_001", "robot_002", "robot_003"],
            coordination_data={
                "task": "warehouse_inventory",
                "zones": ["A1-A5", "B1-B5", "C1-C5"],
                "deadline": "2024-01-15T18:00:00Z"
            },
            meta={"coordinator": "robot_001", "consensus_required": "true"}
        )
        logger.info(f"✅ Coordination message sent with ID: {coordination_result}")
        
        # ========== 6. TRUST OPERATIONS ==========
        logger.info("\n🔐 6. Trust and Security Operations")
        
        trust_result = await client.send_unified(
            "trust",
            trust_operation="verify_identity",
            identity="robot_002",
            trust_data={
                "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
                "signature": "base64_encoded_signature",
                "challenge": "random_challenge_string"
            },
            meta={"verification_level": "high", "expires": "2024-01-15T12:00:00Z"}
        )
        logger.info(f"✅ Trust operation sent with ID: {trust_result}")
        
        # ========== 7. TELEMETRY OPERATIONS ==========
        logger.info("\n📊 7. Telemetry and Monitoring")
        
        telemetry_result = await client.send_unified(
            "telemetry",
            metric_type="system_health",
            metric_data={
                "cpu_usage": 45.2,
                "memory_usage": 67.8,
                "disk_usage": 23.1,
                "network_latency": 12.5,
                "battery_level": 87.3,
                "temperature": 42.1
            },
            timestamp_ns=int(time.time() * 1e9),
            meta={"node_id": "robot_001", "location": "warehouse_zone_a"}
        )
        logger.info(f"✅ Telemetry data sent with ID: {telemetry_result}")
        
        # ========== 8. UNIFIED QUERYING ==========
        logger.info("\n🔍 8. Unified Data Querying")
        
        # Query different types of stored data
        memory_data = await client.query_unified("memory", {"k": 3, "min_sim": 0.5})
        logger.info(f"✅ Found {len(memory_data)} memory entries")
        
        action_data = await client.query_unified("action", {"action_type": "set_pose", "limit": 5})
        logger.info(f"✅ Found {len(action_data)} action entries")
        
        telemetry_data = await client.query_unified("telemetry", {"metric_type": "system_health", "limit": 10})
        logger.info(f"✅ Found {len(telemetry_data)} telemetry entries")
        
        # ========== 9. UNIFIED STATISTICS ==========
        logger.info("\n📈 9. Unified Statistics")
        
        stats = await client.get_unified_stats()
        logger.info("📊 Unified Storage Statistics:")
        for data_type, count in stats.items():
            logger.info(f"   {data_type}: {count} entries")
        
        # ========== 10. UNIFIED LISTENING ==========
        logger.info("\n👂 10. Setting up Unified Message Listening")
        
        # Define handlers for different operation types
        async def handle_prompt(message, data):
            logger.info(f"🎯 Received prompt: {data.get('prompt', '')[:50]}...")
        
        async def handle_memory_put(message, data):
            logger.info(f"🧠 Received memory storage: frame_id={data.get('frame_id')}")
        
        async def handle_action(message, data):
            logger.info(f"🤖 Received action: {data.get('action_type')}")
        
        async def handle_coordination(message, data):
            logger.info(f"🤝 Received coordination: {data.get('coordination_type')}")
        
        async def handle_trust(message, data):
            logger.info(f"🔐 Received trust operation: {data.get('trust_operation')}")
        
        async def handle_telemetry(message, data):
            logger.info(f"📊 Received telemetry: {data.get('metric_type')}")
        
        # Set up unified listening
        handlers = {
            "prompt": [handle_prompt],
            "memory_put": [handle_memory_put],
            "action": [handle_action],
            "coordinate": [handle_coordination],
            "trust": [handle_trust],
            "telemetry": [handle_telemetry],
        }
        
        # Start listening (in a real application, this would run continuously)
        logger.info("✅ Unified message handlers configured")
        logger.info("   (In production, call client.listen_unified(handlers) to start listening)")
        
        logger.info("\n" + "=" * 60)
        logger.info("🎉 Unified ECPS Protocol Demo Complete!")
        logger.info("🔥 ALL protocols consolidated into a SINGLE API!")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error(f"❌ Error in unified demo: {e}")
        raise
    finally:
        await client.close()


async def demonstrate_comparison():
    """Demonstrate the difference between old separate APIs and new unified API."""
    
    logger.info("\n" + "🔄 API COMPARISON" + "\n" + "=" * 40)
    
    logger.info("❌ OLD WAY (Separate APIs):")
    logger.info("""
    # Separate handlers for each protocol
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
    """)
    
    logger.info("✅ NEW WAY (Unified API):")
    logger.info("""
    # Single unified handler
    client = ECPSClient(config)  # Contains UEPHandler internally
    
    # Single method for ALL operations
    await client.send_unified("prompt", prompt=prompt, tool_json=tool_json, meta=meta)
    await client.send_unified("memory_put", tensor_zstd=tensor_zstd, shape=shape, dtype=dtype, frame_id=frame_id, timestamp_ns=timestamp_ns)
    await client.send_unified("action", action_type=action_type, action_data=action_data, state_sha=state_sha, meta=meta)
    await client.send_unified("perception", tensor_zstd=tensor_zstd, shape=shape, dtype=dtype, frame_id=frame_id, timestamp_ns=timestamp_ns)
    await client.send_unified("coordinate", coordination_type=coordination_type, agent_ids=agent_ids, coordination_data=data)
    await client.send_unified("trust", trust_operation="verify_identity", identity=identity, trust_data=trust_data)
    
    # Single listening interface
    await client.listen_unified(handlers)
    
    # Single querying interface
    await client.query_unified(data_type, query_params)
    """)
    
    logger.info("🎯 BENEFITS:")
    logger.info("   ✅ Single API for ALL protocols")
    logger.info("   ✅ Consistent interface across all operations")
    logger.info("   ✅ Unified storage and querying")
    logger.info("   ✅ Simplified error handling")
    logger.info("   ✅ Better observability and telemetry")
    logger.info("   ✅ Easier testing and debugging")
    logger.info("   ✅ Reduced cognitive load for developers")


if __name__ == "__main__":
    asyncio.run(demonstrate_unified_api())
    asyncio.run(demonstrate_comparison())