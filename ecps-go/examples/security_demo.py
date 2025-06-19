#!/usr/bin/env python3
"""
ECPS Security Hardening Demo

This script demonstrates the security features implemented in ECPS-UV SDK:
- JWT secret rotation
- mTLS between nodes
- HSM/TPM integration
- Protobuf fuzzing
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Add the parent directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from ecps_uv.trust.trust import (
    SecurityConfig, 
    ECPSSecurityManager, 
    initialize_security,
    get_security_manager,
    shutdown_security,
    Principal
)
from ecps_uv.trust.mtls import NodeIdentity
from ecps_uv.trust.jwt_rotation import get_jwt_manager

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('security_demo')


async def demo_jwt_rotation():
    """Demonstrate JWT secret rotation."""
    logger.info("=== JWT Secret Rotation Demo ===")
    
    jwt_manager = get_jwt_manager()
    if not jwt_manager:
        logger.error("JWT manager not available")
        return
    
    # Create a token
    payload = {
        "user_id": "robot_001",
        "roles": ["robot_operator"],
        "permissions": {"move:robot": True}
    }
    
    token = jwt_manager.create_token(payload, expires_in_hours=1)
    logger.info(f"Created JWT token: {token[:50]}...")
    
    # Validate the token
    try:
        decoded = jwt_manager.validate_token(token)
        logger.info(f"Token validated successfully: {decoded['user_id']}")
    except Exception as e:
        logger.error(f"Token validation failed: {e}")
    
    # Show current secret info
    current_secret = jwt_manager.get_current_secret()
    if current_secret:
        logger.info(f"Current secret key_id: {current_secret.key_id}")
        logger.info(f"Secret expires at: {current_secret.expires_at}")


async def demo_mtls():
    """Demonstrate mTLS functionality."""
    logger.info("=== mTLS Demo ===")
    
    security_manager = get_security_manager()
    if not security_manager or not security_manager.mtls_transport:
        logger.error("mTLS transport not available")
        return
    
    try:
        # Get server credentials
        server_creds = security_manager.get_mtls_server_credentials()
        logger.info("mTLS server credentials created successfully")
        
        # Get client credentials
        client_creds = security_manager.get_mtls_channel_credentials()
        logger.info("mTLS client credentials created successfully")
        
        logger.info("mTLS is ready for secure communication")
        
    except Exception as e:
        logger.error(f"mTLS demo failed: {e}")


async def demo_authorization():
    """Demonstrate authorization system."""
    logger.info("=== Authorization Demo ===")
    
    security_manager = get_security_manager()
    if not security_manager:
        logger.error("Security manager not available")
        return
    
    # Create test principals
    robot_operator = Principal(
        id="user_001",
        name="Robot Operator",
        roles=["robot_operator"],
        permissions={}
    )
    
    robot_admin = Principal(
        id="admin_001",
        name="Robot Administrator", 
        roles=["robot_admin"],
        permissions={}
    )
    
    # Test authorization
    test_cases = [
        (robot_operator, "move", "robot"),
        (robot_operator, "configure", "robot"),  # Should fail
        (robot_admin, "move", "robot"),
        (robot_admin, "configure", "robot"),
    ]
    
    for principal, action, resource in test_cases:
        try:
            authorized, reason = await security_manager.authorize_action(
                principal, action, resource
            )
            status = "ALLOWED" if authorized else "DENIED"
            logger.info(f"{principal.name}: {action} on {resource} -> {status}")
            if reason:
                logger.info(f"  Reason: {reason}")
        except Exception as e:
            logger.error(f"Authorization check failed: {e}")


async def demo_security_status():
    """Show security system status."""
    logger.info("=== Security Status ===")
    
    security_manager = get_security_manager()
    if not security_manager:
        logger.error("Security manager not available")
        return
    
    status = security_manager.get_security_status()
    
    logger.info("Security Component Status:")
    logger.info(f"  Initialized: {status['initialized']}")
    logger.info(f"  JWT Rotation: {status['jwt_rotation']}")
    logger.info(f"  mTLS: {status['mtls']}")
    logger.info(f"  Authorization: {status['authorization']}")
    logger.info(f"  Hardware Security: {status['hardware_security']}")


async def demo_fuzzing():
    """Demonstrate protobuf fuzzing."""
    logger.info("=== Protobuf Fuzzing Demo ===")
    
    try:
        # Import fuzzing module
        from tests.fuzz_protobuf import ProtobufFuzzer
        
        fuzzer = ProtobufFuzzer()
        
        # Generate test cases
        test_cases = fuzzer.generate_test_cases()
        logger.info(f"Generated {len(test_cases)} test cases")
        
        # Run a few test cases
        for i, test_case in enumerate(test_cases[:5]):
            results = fuzzer.fuzz_all_message_types(test_case)
            
            success_count = sum(1 for r in results if r['success'])
            error_count = len(results) - success_count
            
            logger.info(f"Test case {i+1}: {success_count} success, {error_count} errors")
        
        # Show statistics
        logger.info("Fuzzing Statistics:")
        for key, value in fuzzer.stats.items():
            logger.info(f"  {key}: {value}")
            
    except ImportError:
        logger.warning("Fuzzing module not available")
    except Exception as e:
        logger.error(f"Fuzzing demo failed: {e}")


async def main():
    """Main demo function."""
    logger.info("Starting ECPS Security Hardening Demo")
    
    # Create node identity
    node_identity = NodeIdentity(
        node_id="demo_robot_001",
        common_name="demo-robot-001.local",
        organization="ECPS Demo",
        organizational_unit="Demo Robots",
        country="US",
        state="California",
        locality="San Francisco",
        dns_names=["demo-robot-001.local"],
        ip_addresses=["127.0.0.1"]
    )
    
    # Create security configuration
    config = SecurityConfig(
        jwt_rotation_enabled=True,
        jwt_rotation_interval_hours=24,
        mtls_enabled=True,
        hsm_enabled=False,  # Disabled for demo
        tpm_enabled=False,  # Disabled for demo
        fuzzing_enabled=True,
        node_identity=node_identity
    )
    
    try:
        # Initialize security
        logger.info("Initializing security components...")
        security_manager = await initialize_security(config)
        logger.info("Security initialization completed")
        
        # Run demos
        await demo_security_status()
        await demo_jwt_rotation()
        await demo_mtls()
        await demo_authorization()
        await demo_fuzzing()
        
        logger.info("All demos completed successfully")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise
    
    finally:
        # Cleanup
        logger.info("Shutting down security components...")
        await shutdown_security()
        logger.info("Demo completed")


if __name__ == "__main__":
    # Check for HSM enrollment
    hsm_script = Path(__file__).parent.parent / "scripts" / "hsm-enrollment.sh"
    if hsm_script.exists():
        logger.info(f"HSM enrollment script available: {hsm_script}")
        logger.info("Run './scripts/hsm-enrollment.sh detect' to check for HSM/TPM devices")
    
    # Run the demo
    asyncio.run(main())