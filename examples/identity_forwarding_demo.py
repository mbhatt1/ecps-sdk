"""
Identity Forwarding Demo for ECPS UV SDK.

This example demonstrates how to use identity forwarding instead of
per-request signing for better performance in high-throughput scenarios.
"""

import asyncio
import logging
from datetime import timedelta

from ecps_uv.core import ECPSClient
from ecps_uv.trust.identity import (
    IdentityType, 
    create_default_identity_provider
)
from ecps_uv.trust.trust import create_default_trust_provider
from ecps_uv.trust.identity_forwarding import (
    IdentityForwardingManager,
    create_default_identity_forwarding_manager
)
from ecps_uv.trust.secure_transport import SecureTransport
from ecps_uv.transport.mqtt import MQTTTransport
from ecps_uv.serialization.protobuf import ProtobufSerializer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def demonstrate_identity_forwarding():
    """Demonstrate identity forwarding capabilities."""
    
    print("🔐 ECPS Identity Forwarding Demo")
    print("=" * 50)
    
    # Create identity and trust providers
    identity_store, identity_provider = create_default_identity_provider()
    trust_provider = create_default_trust_provider()
    
    # Create identity forwarding manager
    forwarding_manager = create_default_identity_forwarding_manager(
        identity_provider, trust_provider
    )
    
    print("\n1. Setting up transport and client...")
    
    # Create transport and serializer
    transport = MQTTTransport(broker_url="mqtt://localhost:1883")
    serializer = ProtobufSerializer()
    transport.serializer = serializer
    
    # Create secure transport with identity forwarding
    secure_transport = SecureTransport(
        transport=transport,
        trust_provider=trust_provider,
        identity_forwarding_manager=forwarding_manager,
    )
    
    # Create ECPS client
    client = ECPSClient(transport=secure_transport, serializer=serializer)
    
    print("\n2. Establishing identity context (replaces per-request signing)...")
    
    # Get a sample user identity from the default store
    user_identities = identity_store.list_identities(IdentityType.USER)
    if not user_identities:
        print("❌ No user identities found in store")
        return
    
    user_identity = user_identities[0]
    print(f"   Using identity: {user_identity.name} ({user_identity.id})")
    
    # Establish identity context (this replaces authentication for every request)
    identity_context = await forwarding_manager.establish_identity_context(
        identity_id=user_identity.id,
        credential="password123",  # From default setup
        capabilities={"read", "write", "coordinate"},
        session_duration=timedelta(hours=2),
    )
    
    if not identity_context:
        print("❌ Failed to establish identity context")
        return
    
    print(f"   ✅ Identity context established")
    print(f"   Session ID: {identity_context.session_id}")
    print(f"   Expires: {identity_context.expires_at}")
    print(f"   Capabilities: {identity_context.capabilities}")
    
    # Set identity context on secure transport
    secure_transport.set_identity_context(identity_context)
    
    print("\n3. Demonstrating forwarded requests (no per-request signing)...")
    
    # Initialize client
    await client.initialize()
    
    # Example 1: Send a prompt (MCP operation) with forwarded identity
    print("\n   📝 Sending prompt with forwarded identity...")
    try:
        await client.send_unified(
            operation="prompt",
            data={
                "prompt": "What is the status of robot arm #1?",
                "context": {"location": "factory_floor_a"}
            },
            target="mcp_service"
        )
        print("   ✅ Prompt sent successfully (identity forwarded, not signed)")
    except Exception as e:
        print(f"   ❌ Failed to send prompt: {e}")
    
    # Example 2: Store memory (MEP operation) with forwarded identity
    print("\n   🧠 Storing memory with forwarded identity...")
    try:
        await client.send_unified(
            operation="memory_put",
            data={
                "key": "robot_arm_1_status",
                "value": {"status": "operational", "last_maintenance": "2024-01-15"},
                "metadata": {"type": "status", "priority": "high"}
            },
            target="mep_service"
        )
        print("   ✅ Memory stored successfully (identity forwarded, not signed)")
    except Exception as e:
        print(f"   ❌ Failed to store memory: {e}")
    
    # Example 3: Send action (EAP operation) with forwarded identity
    print("\n   🤖 Sending action with forwarded identity...")
    try:
        await client.send_unified(
            operation="action",
            data={
                "action_type": "move_to_position",
                "parameters": {"x": 100, "y": 200, "z": 50},
                "target_device": "robot_arm_1"
            },
            target="eap_service"
        )
        print("   ✅ Action sent successfully (identity forwarded, not signed)")
    except Exception as e:
        print(f"   ❌ Failed to send action: {e}")
    
    print("\n4. Demonstrating request validation...")
    
    # Create a forwarded request manually to show validation
    forwarded_request = forwarding_manager.create_forwarded_request(
        payload={"test": "validation"},
        identity_context=identity_context,
    )
    
    # Validate the request
    is_valid, error_reason = await forwarding_manager.validate_forwarded_request(
        forwarded_request,
        required_capability="read",
        service_name="demo_service",
    )
    
    if is_valid:
        print("   ✅ Forwarded request validation passed")
        print(f"   Service chain: {forwarded_request.service_chain}")
    else:
        print(f"   ❌ Forwarded request validation failed: {error_reason}")
    
    # Test authorization
    authorized, reason = await forwarding_manager.authorize_forwarded_request(
        forwarded_request,
        action="read",
        resource="sensor_data",
    )
    
    if authorized:
        print("   ✅ Authorization passed")
    else:
        print(f"   ❌ Authorization failed: {reason}")
    
    print("\n5. Demonstrating context management...")
    
    # Show active contexts
    active_contexts = forwarding_manager.get_active_contexts()
    print(f"   Active contexts: {len(active_contexts)}")
    
    # Refresh context
    refreshed = forwarding_manager.refresh_context(
        identity_context.session_id,
        additional_duration=timedelta(hours=1),
    )
    print(f"   Context refreshed: {refreshed}")
    
    # Show time remaining
    print(f"   Time remaining: {identity_context.time_remaining}")
    
    print("\n6. Performance comparison...")
    print("   Traditional approach: Sign every request")
    print("   - High CPU overhead for cryptographic operations")
    print("   - Network overhead for signatures")
    print("   - Latency impact on each request")
    print()
    print("   Identity forwarding approach:")
    print("   ✅ Authenticate once, forward identity context")
    print("   ✅ No per-request signing overhead")
    print("   ✅ Reduced network traffic")
    print("   ✅ Better performance for high-throughput scenarios")
    print("   ✅ Session-based security with proper expiration")
    
    # Cleanup
    print("\n7. Cleanup...")
    await client.shutdown()
    await forwarding_manager.shutdown()
    print("   ✅ Demo completed successfully")


async def demonstrate_service_chain():
    """Demonstrate how identity is forwarded through a service chain."""
    
    print("\n" + "=" * 50)
    print("🔗 Service Chain Identity Forwarding Demo")
    print("=" * 50)
    
    # Create components
    identity_store, identity_provider = create_default_identity_provider()
    trust_provider = create_default_trust_provider()
    forwarding_manager = create_default_identity_forwarding_manager(
        identity_provider, trust_provider
    )
    
    # Get service identity
    service_identities = identity_store.list_identities(IdentityType.SERVICE)
    if not service_identities:
        print("❌ No service identities found")
        return
    
    service_identity = service_identities[0]
    
    # Establish service identity context
    service_context = await forwarding_manager.establish_identity_context(
        identity_id=service_identity.id,
        credential="service-api-key",
        capabilities={"coordinate", "process", "forward"},
    )
    
    if not service_context:
        print("❌ Failed to establish service context")
        return
    
    print(f"Service identity: {service_identity.name}")
    
    # Simulate a request passing through multiple services
    original_request = forwarding_manager.create_forwarded_request(
        payload={"task": "process_sensor_data", "sensor_id": "temp_01"},
        identity_context=service_context,
    )
    
    print(f"\nOriginal request ID: {original_request.request_id}")
    
    # Service 1: Data Ingestion
    print("\n1. Request reaches Data Ingestion Service...")
    is_valid, error = await forwarding_manager.validate_forwarded_request(
        original_request, "process", "data_ingestion_service"
    )
    print(f"   Validation: {'✅ Passed' if is_valid else f'❌ Failed: {error}'}")
    
    # Service 2: Data Processing
    print("\n2. Request forwarded to Data Processing Service...")
    is_valid, error = await forwarding_manager.validate_forwarded_request(
        original_request, "process", "data_processing_service"
    )
    print(f"   Validation: {'✅ Passed' if is_valid else f'❌ Failed: {error}'}")
    
    # Service 3: Result Storage
    print("\n3. Request forwarded to Result Storage Service...")
    is_valid, error = await forwarding_manager.validate_forwarded_request(
        original_request, "process", "result_storage_service"
    )
    print(f"   Validation: {'✅ Passed' if is_valid else f'❌ Failed: {error}'}")
    
    print(f"\nFinal service chain: {' → '.join(original_request.service_chain)}")
    print("✅ Identity successfully forwarded through entire service chain")
    print("   No per-service authentication required!")
    
    # Cleanup
    await forwarding_manager.shutdown()


async def main():
    """Run the identity forwarding demonstrations."""
    try:
        await demonstrate_identity_forwarding()
        await demonstrate_service_chain()
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Demo failed with error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())