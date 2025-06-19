#!/usr/bin/env python3
"""
Example demonstrating the identity management capabilities in the ECPS UV SDK.

This example shows how to use the identity management system to:
1. Create and manage different types of identities
2. Authenticate identities using credentials
3. Generate and validate identity tokens
4. Associate identities with principals for authorization
"""

import asyncio
import logging
from datetime import datetime, timedelta

from ecps_uv.trust import (
    Identity,
    IdentityProvider,
    IdentityStore,
    IdentityType,
    Principal,
    RBACAuthorizer,
    TrustLevel,
    TrustMechanism,
    TrustProvider,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("identity_demo")


async def setup_trust_system():
    """Set up the trust system with identity management."""
    # Create identity store and provider
    identity_store = IdentityStore()
    identity_provider = IdentityProvider(
        identity_store=identity_store,
        jwt_secret="demo-jwt-secret",
    )
    
    # Create trust provider
    authorizer = RBACAuthorizer()
    trust_provider = TrustProvider(
        trust_level=TrustLevel.AUTHORIZATION,
        mechanisms=[TrustMechanism.JWT],
        jwt_secret="demo-jwt-secret",
        authorizer=authorizer,
    )
    
    # Add permissions for roles
    authorizer.add_role_permission("admin", "manage", "identities")
    authorizer.add_role_permission("admin", "read", "all_data")
    authorizer.add_role_permission("admin", "write", "all_data")
    authorizer.add_role_permission("user", "read", "user_data")
    authorizer.add_role_permission("user", "write", "user_data")
    authorizer.add_role_permission("device", "write", "sensor_data")
    authorizer.add_role_permission("robot", "control", "actuators")
    
    # Create principals
    admin_principal = Principal(
        id="admin1",
        name="Administrator",
        roles=["admin"],
        permissions={"manage:system": True},
    )
    trust_provider.add_principal(admin_principal)
    
    user_principal = Principal(
        id="user1",
        name="Regular User",
        roles=["user"],
        permissions={},
    )
    trust_provider.add_principal(user_principal)
    
    device_principal = Principal(
        id="device1",
        name="IoT Sensor",
        roles=["device"],
        permissions={},
    )
    trust_provider.add_principal(device_principal)
    
    robot_principal = Principal(
        id="robot1",
        name="Robot Arm",
        roles=["robot"],
        permissions={},
    )
    trust_provider.add_principal(robot_principal)
    
    return identity_store, identity_provider, trust_provider


async def create_identities(identity_store):
    """Create different types of identities."""
    logger.info("Creating different types of identities...")
    
    # Create user identity
    user = identity_store.create_identity(
        name="John Doe",
        type=IdentityType.USER,
        attributes={"email": "john.doe@example.com", "department": "Engineering"},
    )
    identity_store.set_credential(user.id, "user-password")
    identity_store.associate_principal(user.id, "user1")
    logger.info(f"Created user identity: {user.id} ({user.name})")
    
    # Create service identity
    service = identity_store.create_identity(
        name="API Service",
        type=IdentityType.SERVICE,
        attributes={"service_type": "api", "version": "1.0"},
    )
    identity_store.set_credential(service.id, "api-key-12345")
    identity_store.associate_principal(service.id, "admin1")  # Services often have admin privileges
    logger.info(f"Created service identity: {service.id} ({service.name})")
    
    # Create device identity
    device = identity_store.create_identity(
        name="Temperature Sensor",
        type=IdentityType.DEVICE,
        attributes={"device_type": "sensor", "location": "server-room"},
    )
    identity_store.set_credential(device.id, "device-token-xyz")
    identity_store.associate_principal(device.id, "device1")
    logger.info(f"Created device identity: {device.id} ({device.name})")
    
    # Create robot identity
    robot = identity_store.create_identity(
        name="Assembly Robot",
        type=IdentityType.ROBOT,
        attributes={"model": "UR10", "location": "assembly-line-1"},
    )
    identity_store.set_credential(robot.id, "robot-secret-abc")
    identity_store.associate_principal(robot.id, "robot1")
    logger.info(f"Created robot identity: {robot.id} ({robot.name})")
    
    return user, service, device, robot


async def authenticate_identities(identity_provider, user, service, device, robot):
    """Authenticate different identities."""
    logger.info("\nAuthenticating identities...")
    
    # Authenticate user
    auth_user = await identity_provider.authenticate(user.id, "user-password")
    if auth_user:
        logger.info(f"User authenticated: {auth_user.name}")
        # Create token
        token = identity_provider.create_identity_token(
            auth_user, 
            expires_in=timedelta(hours=1)
        )
        logger.info(f"User token created: {token[:20]}...")
        
        # Validate token
        validated_user = identity_provider.validate_identity_token(token)
        if validated_user:
            logger.info(f"User token validated for: {validated_user.name}")
            
            # Get associated principal
            principal_id = await identity_provider.identity_to_principal(validated_user)
            logger.info(f"User maps to principal: {principal_id}")
    else:
        logger.error("User authentication failed")
    
    # Authenticate service with wrong credential (should fail)
    auth_service = await identity_provider.authenticate(service.id, "wrong-key")
    if auth_service:
        logger.info(f"Service authenticated: {auth_service.name}")
    else:
        logger.warning("Service authentication failed with wrong credential (expected)")
    
    # Authenticate service with correct credential
    auth_service = await identity_provider.authenticate(service.id, "api-key-12345")
    if auth_service:
        logger.info(f"Service authenticated: {auth_service.name}")
        token = identity_provider.create_identity_token(
            auth_service, 
            expires_in=timedelta(days=30)  # Services often have longer-lived tokens
        )
        logger.info(f"Service token created: {token[:20]}...")
    
    # Authenticate device
    auth_device = await identity_provider.authenticate(device.id, "device-token-xyz")
    if auth_device:
        logger.info(f"Device authenticated: {auth_device.name}")
        token = identity_provider.create_identity_token(
            auth_device, 
            expires_in=timedelta(days=90)  # Devices often have very long-lived tokens
        )
        logger.info(f"Device token created: {token[:20]}...")
    
    # Authenticate robot
    auth_robot = await identity_provider.authenticate(robot.id, "robot-secret-abc")
    if auth_robot:
        logger.info(f"Robot authenticated: {auth_robot.name}")
        token = identity_provider.create_identity_token(
            auth_robot, 
            expires_in=timedelta(days=7)
        )
        logger.info(f"Robot token created: {token[:20]}...")


async def identity_management_operations(identity_store, identity_provider):
    """Demonstrate identity management operations."""
    logger.info("\nDemonstrating identity management operations...")
    
    # List all identities
    all_identities = identity_store.list_identities()
    logger.info(f"Total identities: {len(all_identities)}")
    
    # List by type
    user_identities = identity_store.list_identities(IdentityType.USER)
    logger.info(f"User identities: {len(user_identities)}")
    
    device_identities = identity_store.list_identities(IdentityType.DEVICE)
    logger.info(f"Device identities: {len(device_identities)}")
    
    # Update an identity
    if user_identities:
        user = user_identities[0]
        user.attributes["department"] = "Research"
        user.attributes["role"] = "Senior Engineer"
        identity_store.update_identity(user)
        logger.info(f"Updated user identity: {user.id} with new attributes")
        
        # Verify update
        updated_user = identity_store.get_identity(user.id)
        logger.info(f"Updated user department: {updated_user.attributes.get('department')}")
    
    # Disable an identity
    if len(all_identities) > 3:
        identity_to_disable = all_identities[3]
        identity_to_disable.enabled = False
        identity_store.update_identity(identity_to_disable)
        logger.info(f"Disabled identity: {identity_to_disable.id} ({identity_to_disable.name})")
        
        # Try to authenticate (should fail)
        disabled_auth = await identity_provider.authenticate(
            identity_to_disable.id, 
            "any-credential"  # Credential doesn't matter, it should fail on disabled
        )
        if disabled_auth:
            logger.error("ERROR: Disabled identity was authenticated!")
        else:
            logger.info("Correctly rejected authentication for disabled identity")
    
    # Delete an identity
    if len(all_identities) > 0:
        identity_to_delete = all_identities[0]
        identity_store.delete_identity(identity_to_delete.id)
        logger.info(f"Deleted identity: {identity_to_delete.id}")
        
        # Verify deletion
        remaining_identities = identity_store.list_identities()
        logger.info(f"Remaining identities: {len(remaining_identities)}")


async def main():
    """Main entry point for the identity management demo."""
    logger.info("=== ECPS UV SDK Identity Management Demo ===")
    
    # Set up trust system
    identity_store, identity_provider, trust_provider = await setup_trust_system()
    
    # Create identities
    user, service, device, robot = await create_identities(identity_store)
    
    # Authenticate identities
    await authenticate_identities(identity_provider, user, service, device, robot)
    
    # Identity management operations
    await identity_management_operations(identity_store, identity_provider)
    
    logger.info("\nIdentity management demo completed successfully!")


if __name__ == "__main__":
    asyncio.run(main())