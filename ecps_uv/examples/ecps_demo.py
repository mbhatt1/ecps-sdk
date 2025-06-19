#!/usr/bin/env python3
"""
ECPS-UV SDK Demo

This script demonstrates the basic usage of the ECPS-UV SDK,
including setting up clients and servers, sending and receiving
messages, and using the different protocol layers.
"""

import asyncio
import logging
import numpy as np
import time
import json
import os
import hashlib

# Import the ECPS-UV SDK
import ecps_uv
from ecps_uv.core import StandardProfile, CloudFleetProfile


async def run_server():
    """Run an ECPS server that handles MCP, MEP, and EAP messages."""
    print("Starting ECPS server...")
    
    # Create server with Standard profile (DDS transport)
    config = StandardProfile(
        transport_type="dds",
        transport_config={"domain_id": 0},
    )
    server = ecps_uv.ECPSServer(config)
    
    # Define MCP handler
    async def handle_mcp(mcp_message):
        print(f"Received MCP prompt: {mcp_message.prompt[:50]}...")
        
        # Simulate processing
        await asyncio.sleep(0.5)
        
        print("Processing complete")
    
    # Define EAP handler
    async def handle_eap(eap_message):
        # Determine action type
        action_type = None
        if eap_message.HasField("set_pose"):
            action_type = "set_pose"
            action = eap_message.set_pose
            print(f"Received Robot Pose: x={action.x}, y={action.y}, z={action.z}")
        elif eap_message.HasField("gripper"):
            action_type = "gripper"
            action = eap_message.gripper
            print(f"Received Gripper Op: command={action.command}, position={action.position}")
        elif eap_message.HasField("cloud"):
            action_type = "cloud"
            action = eap_message.cloud
            print(f"Received Cloud Op: api={action.api_name}, method={action.method_name}")
        elif eap_message.HasField("sim"):
            action_type = "sim"
            action = eap_message.sim
            print(f"Received Sim Step: duration={action.duration_s}s")
        else:
            print("Received unknown action type")
        
        print(f"Action ID: {eap_message.id}")
        print(f"State SHA: {eap_message.state_sha.hex()[:10]}...")
    
    # Register handlers
    server.on_mcp(handle_mcp)
    server.on_eap(handle_eap)
    
    # Start MEP service
    server.start_mep_service()
    
    # Start the server
    await server.start()
    
    print("ECPS server started")
    
    try:
        # Keep server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("Shutting down server...")
    finally:
        await server.close()


async def run_client():
    """Run an ECPS client that sends MCP, MEP, and EAP messages."""
    print("Starting ECPS client...")
    
    # Create client with Standard profile (DDS transport)
    config = StandardProfile(
        transport_type="dds",
        transport_config={"domain_id": 0},
    )
    client = ecps_uv.ECPSClient(config)
    
    # Wait for server to start
    await asyncio.sleep(2)
    
    print("\n--- Sending MCP Prompt ---")
    # Send MCP message
    prompt = "Move the robot arm to pick up the object at coordinates (0.5, 0.3, 0.2)"
    mcp_id = await client.send_mcp(prompt)
    print(f"Sent MCP message with ID: {mcp_id}")
    
    await asyncio.sleep(1)
    
    print("\n--- Storing Memory Embedding ---")
    # Create a sample embedding
    embedding = np.random.rand(1, 256).astype(np.float32)
    
    # Compress embedding
    import zstandard as zstd
    compressor = zstd.ZstdCompressor(level=3)
    tensor_bytes = embedding.tobytes()
    tensor_zstd = compressor.compress(tensor_bytes)
    
    # Store embedding
    success, message = await client.store_memory(
        tensor_zstd=tensor_zstd,
        shape=[1, 256],
        dtype="f32",
        frame_id="camera_1",
        timestamp_ns=int(time.time_ns()),
    )
    
    print(f"Memory storage {'successful' if success else 'failed'}: {message}")
    
    await asyncio.sleep(1)
    
    print("\n--- Querying Memory Embeddings ---")
    # Create a query embedding
    query_embedding = {
        "tensor_zstd": tensor_zstd,
        "shape": [1, 256],
        "dtype": "f32",
        "frame_id": "camera_1",
        "timestamp_ns": int(time.time_ns()),
    }
    
    # Query embeddings
    results = await client.query_memory(query_embedding, k=5, min_sim=0.7)
    print(f"Found {len(results)} similar embeddings")
    
    await asyncio.sleep(1)
    
    print("\n--- Sending Robot Pose Action ---")
    # Generate a state hash
    state_sha = hashlib.sha256(f"robot_state_{time.time()}".encode()).digest()
    
    # Send robot pose action
    pose_data = {
        "x": 0.5,
        "y": 0.3,
        "z": 0.2,
        "qw": 1.0,
        "qx": 0.0,
        "qy": 0.0,
        "qz": 0.0,
    }
    
    action_id = await client.send_action(
        action_type="set_pose",
        action_data=pose_data,
        state_sha=state_sha,
        meta={"safety": "stop_on_fail"},
    )
    
    print(f"Sent robot pose action with ID: {action_id}")
    
    await asyncio.sleep(1)
    
    print("\n--- Sending Gripper Action ---")
    # Send gripper action
    gripper_data = {
        "command": 1,  # OPEN
        "position": 1.0,
        "force_limit": 10.0,
    }
    
    action_id = await client.send_action(
        action_type="gripper",
        action_data=gripper_data,
        state_sha=state_sha,
    )
    
    print(f"Sent gripper action with ID: {action_id}")
    
    await asyncio.sleep(1)
    
    print("\n--- Sending Cloud Operation ---")
    # Send cloud operation
    cloud_data = {
        "api_name": "vision_service",
        "method_name": "detect_objects",
        "json_payload": json.dumps({"image_id": "camera_1_frame_42"}).encode(),
        "requires_oauth2": True,
    }
    
    action_id = await client.send_action(
        action_type="cloud",
        action_data=cloud_data,
        state_sha=state_sha,
    )
    
    print(f"Sent cloud operation with ID: {action_id}")
    
    await asyncio.sleep(1)
    
    print("\n--- Sending Simulation Step ---")
    # Send simulation step
    sim_data = {
        "duration_s": 0.1,
    }
    
    action_id = await client.send_action(
        action_type="sim",
        action_data=sim_data,
        state_sha=state_sha,
    )
    
    print(f"Sent simulation step with ID: {action_id}")
    
    # Close the client
    await client.close()


async def run_demo():
    """Run the complete ECPS demo with server and client."""
    # Create directory for examples
    os.makedirs("examples", exist_ok=True)
    
    # Start server in a separate task
    server_task = asyncio.create_task(run_server())
    
    # Wait for server to initialize
    await asyncio.sleep(2)
    
    try:
        # Run client
        await run_client()
        
        # Wait a bit to see final server logs
        await asyncio.sleep(1)
    finally:
        # Cancel server task
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass


if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    
    # Run the demo
    asyncio.run(run_demo())