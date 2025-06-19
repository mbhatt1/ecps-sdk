"""
Default Identity Forwarding Demo for ECPS UV SDK.

This example demonstrates how identity forwarding is now enabled by default
in the ECPS UV SDK, providing better performance out of the box.
"""

import asyncio
import logging

from ecps_uv.core import ECPSClient, StandardProfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def main():
    """Demonstrate default identity forwarding behavior."""
    
    print("🚀 ECPS UV SDK - Default Identity Forwarding Demo")
    print("=" * 60)
    
    print("\n1. Creating ECPS client with default configuration...")
    
    # Create client with standard profile (identity forwarding enabled by default)
    config = StandardProfile()
    client = ECPSClient(config)
    
    print(f"   ✅ Identity forwarding enabled: {config.identity_forwarding_enabled}")
    print(f"   ✅ Default session duration: {config.session_duration_hours} hours")
    
    print("\n2. Establishing identity context (replaces per-request signing)...")
    
    # Establish identity context - this is now the default way to authenticate
    success = await client.establish_identity(
        identity_id="user-123",
        credential="password123",  # From default identity store
        capabilities={"read", "write", "coordinate", "telemetry"}
    )
    
    if not success:
        print("❌ Failed to establish identity context")
        return
    
    # Check identity status
    status = client.get_identity_status()
    print(f"   ✅ Identity established: {status['identity_name']}")
    print(f"   ✅ Session ID: {status['session_id'][:8]}...")
    print(f"   ✅ Expires: {status['expires_at']}")
    print(f"   ✅ Capabilities: {', '.join(status['capabilities'])}")
    
    print("\n3. Sending requests with automatic identity forwarding...")
    
    # All these requests now automatically use identity forwarding
    # No per-request signing overhead!
    
    try:
        # Send MCP prompt
        print("\n   📝 Sending MCP prompt...")
        await client.send_unified(
            operation="prompt",
            data={
                "prompt": "Analyze the current system status",
                "context": {"system": "production", "priority": "high"}
            },
            target="ai_assistant"
        )
        print("   ✅ MCP prompt sent (identity forwarded automatically)")
        
        # Store memory
        print("\n   🧠 Storing memory...")
        await client.send_unified(
            operation="memory_put",
            data={
                "key": "system_status_analysis",
                "value": {"status": "operational", "load": 0.75, "alerts": []},
                "metadata": {"timestamp": "2024-01-15T10:30:00Z", "source": "monitoring"}
            },
            target="memory_service"
        )
        print("   ✅ Memory stored (identity forwarded automatically)")
        
        # Send action
        print("\n   🤖 Sending action command...")
        await client.send_unified(
            operation="action",
            data={
                "action_type": "optimize_performance",
                "parameters": {"target_load": 0.6, "method": "gradual"},
                "priority": "medium"
            },
            target="system_controller"
        )
        print("   ✅ Action sent (identity forwarded automatically)")
        
        # Send telemetry
        print("\n   📊 Sending telemetry...")
        await client.send_unified(
            operation="telemetry",
            data={
                "metrics": {
                    "cpu_usage": 0.75,
                    "memory_usage": 0.60,
                    "network_throughput": 1250000
                },
                "timestamp": "2024-01-15T10:30:00Z"
            },
            target="telemetry_collector"
        )
        print("   ✅ Telemetry sent (identity forwarded automatically)")
        
    except Exception as e:
        print(f"   ❌ Error sending requests: {e}")
    
    print("\n4. Performance benefits of default identity forwarding...")
    print("   ✅ No per-request cryptographic signing overhead")
    print("   ✅ Reduced network traffic (no signatures in each message)")
    print("   ✅ Better throughput for high-volume operations")
    print("   ✅ Session-based security with automatic expiration")
    print("   ✅ Seamless service chain forwarding")
    
    print("\n5. Identity management operations...")
    
    # Refresh identity context
    print("\n   🔄 Refreshing identity context...")
    refresh_success = await client.refresh_identity(additional_hours=4)
    if refresh_success:
        updated_status = client.get_identity_status()
        print(f"   ✅ Identity refreshed, new expiry: {updated_status['expires_at']}")
    else:
        print("   ❌ Failed to refresh identity")
    
    # Show final status
    final_status = client.get_identity_status()
    print(f"\n   📋 Final identity status:")
    print(f"      Authenticated: {final_status['authenticated']}")
    print(f"      Time remaining: {final_status['time_remaining']}")
    
    print("\n6. Comparison with legacy per-request signing...")
    print("\n   Legacy approach (per-request signing):")
    print("   ❌ Sign every individual request")
    print("   ❌ High CPU overhead for crypto operations")
    print("   ❌ Large message payloads with signatures")
    print("   ❌ Poor performance at scale")
    print()
    print("   New default approach (identity forwarding):")
    print("   ✅ Authenticate once, forward identity context")
    print("   ✅ Minimal CPU overhead after session establishment")
    print("   ✅ Compact message payloads")
    print("   ✅ Excellent performance at scale")
    print("   ✅ Enabled by default in all profiles")
    
    # Clean up
    print("\n7. Cleanup...")
    await client.revoke_identity()
    print("   ✅ Identity context revoked")
    print("   ✅ Demo completed successfully")
    
    print("\n" + "=" * 60)
    print("🎉 Identity forwarding is now the default security mechanism!")
    print("   No configuration changes needed - it just works better.")


async def demonstrate_profile_defaults():
    """Show how different profiles have identity forwarding enabled by default."""
    
    print("\n" + "=" * 60)
    print("📋 Profile Default Settings")
    print("=" * 60)
    
    from ecps_uv.core import EdgeLiteProfile, StandardProfile, CloudFleetProfile
    
    # Edge-Lite Profile
    edge_config = EdgeLiteProfile()
    print(f"\n🔧 Edge-Lite Profile:")
    print(f"   Identity forwarding: {edge_config.identity_forwarding_enabled}")
    print(f"   Session duration: {edge_config.session_duration_hours} hours")
    print(f"   Transport: {edge_config.transport_type}")
    print(f"   Observability: {edge_config.observability_enabled}")
    
    # Standard Profile
    standard_config = StandardProfile()
    print(f"\n🔧 Standard Profile:")
    print(f"   Identity forwarding: {standard_config.identity_forwarding_enabled}")
    print(f"   Session duration: {standard_config.session_duration_hours} hours")
    print(f"   Transport: {standard_config.transport_type}")
    print(f"   Observability: {standard_config.observability_enabled}")
    
    # Cloud-Fleet Profile
    cloud_config = CloudFleetProfile()
    print(f"\n🔧 Cloud-Fleet Profile:")
    print(f"   Identity forwarding: {cloud_config.identity_forwarding_enabled}")
    print(f"   Session duration: {cloud_config.session_duration_hours} hours")
    print(f"   Transport: {cloud_config.transport_type}")
    print(f"   Observability: {cloud_config.observability_enabled}")
    
    print(f"\n✅ All profiles have identity forwarding enabled by default!")


if __name__ == "__main__":
    async def run_demo():
        try:
            await main()
            await demonstrate_profile_defaults()
        except KeyboardInterrupt:
            print("\n\n⚠️  Demo interrupted by user")
        except Exception as e:
            print(f"\n\n❌ Demo failed with error: {e}")
            import traceback
            traceback.print_exc()
    
    asyncio.run(run_demo())