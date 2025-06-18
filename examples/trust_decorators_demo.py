#!/usr/bin/env python3
"""
Example demonstrating the decorator-based security API in the ECPS UV SDK.

This example shows how to use the decorators to easily apply authentication
and authorization checks to functions and methods.
"""

import asyncio
import logging
from datetime import datetime, timedelta

from ecps_uv.trust import (
    Principal,
    RBACAuthorizer,
    TrustLevel,
    TrustMechanism,
    TrustProvider,
    AuthenticationError,
    AuthorizationError,
    requires_authentication,
    requires_authorization,
    secure_operation,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("trust_decorators_demo")


async def setup_trust_provider():
    """Set up a trust provider with test principals."""
    # Create an RBAC authorizer
    authorizer = RBACAuthorizer()
    
    # Add permissions for roles
    authorizer.add_role_permission("admin", "read", "sensor_data")
    authorizer.add_role_permission("admin", "write", "sensor_data")
    authorizer.add_role_permission("user", "read", "sensor_data")
    
    # Create trust provider
    provider = TrustProvider(
        trust_level=TrustLevel.AUTHORIZATION,
        mechanisms=[TrustMechanism.JWT],
        jwt_secret="demo-secret-key",
        authorizer=authorizer,
    )
    
    # Add test principals
    admin_principal = Principal(
        id="admin1",
        name="Administrator",
        roles=["admin"],
        permissions={"write:config": True},
        attributes={"department": "IT"},
    )
    provider.add_principal(admin_principal)
    
    user_principal = Principal(
        id="user1",
        name="Regular User",
        roles=["user"],
        permissions={},
        attributes={"department": "Operations"},
    )
    provider.add_principal(user_principal)
    
    return provider


# Example using the requires_authentication decorator
@requires_authentication(None)  # We'll set this later
async def get_user_profile(principal):
    """Get a user profile (requires authentication)."""
    logger.info(f"Getting profile for authenticated user: {principal.name}")
    return {
        "id": principal.id,
        "name": principal.name,
        "roles": principal.roles,
        "department": principal.attributes.get("department", "Unknown"),
    }


# Example using the requires_authorization decorator
@requires_authorization(None, "read", "sensor_data")  # We'll set this later
async def read_sensor_data(principal, sensor_id):
    """Read sensor data (requires read permission)."""
    logger.info(f"User {principal.name} reading data from sensor {sensor_id}")
    return {
        "sensor_id": sensor_id,
        "temperature": 22.5,
        "humidity": 45.2,
        "timestamp": datetime.now().isoformat(),
    }


# Example using the requires_authorization decorator
@requires_authorization(None, "write", "sensor_data")  # We'll set this later
async def write_sensor_data(principal, sensor_id, data):
    """Write sensor data (requires write permission)."""
    logger.info(f"User {principal.name} writing data to sensor {sensor_id}: {data}")
    return {"status": "success", "sensor_id": sensor_id}


# Example using the secure_operation decorator for convenience
@secure_operation(None, "read", "config")  # We'll set this later
async def get_config(principal, config_name):
    """Get configuration (requires read:config permission)."""
    logger.info(f"User {principal.name} reading config: {config_name}")
    return {"name": config_name, "value": "some_config_value"}


# Example with authentication only
@secure_operation(None, authenticate_only=True)  # We'll set this later
async def public_endpoint(principal, data):
    """Public endpoint that only requires authentication."""
    logger.info(f"User {principal.name} accessing public endpoint with data: {data}")
    return {"status": "received", "from": principal.id}


class SensorService:
    """Example service class using decorator-based security."""
    
    def __init__(self, trust_provider):
        self.trust_provider = trust_provider
    
    @requires_authentication(None)  # We'll set this later
    async def list_sensors(self, principal):
        """List available sensors (requires authentication)."""
        logger.info(f"User {principal.name} listing sensors")
        return ["sensor1", "sensor2", "sensor3"]
    
    @requires_authorization(None, "write", "sensor_config")  # We'll set this later
    async def configure_sensor(self, principal, sensor_id, config):
        """Configure a sensor (requires write permission)."""
        logger.info(f"User {principal.name} configuring sensor {sensor_id}: {config}")
        return {"status": "configured", "sensor_id": sensor_id}


async def run_demo():
    """Run the decorator API demo."""
    # Set up the trust provider
    trust_provider = await setup_trust_provider()
    
    # Update the decorators with the trust provider
    # In a real application, you would set this at initialization time
    get_user_profile.__closure__[0].cell_contents = trust_provider
    read_sensor_data.__closure__[0].cell_contents = trust_provider
    write_sensor_data.__closure__[0].cell_contents = trust_provider
    get_config.__closure__[0].cell_contents = trust_provider
    public_endpoint.__closure__[0].cell_contents = trust_provider
    
    # Create a service instance
    sensor_service = SensorService(trust_provider)
    sensor_service.list_sensors.__closure__[0].cell_contents = trust_provider
    sensor_service.configure_sensor.__closure__[0].cell_contents = trust_provider
    
    # Test with admin principal
    admin_id = "admin1"
    try:
        # Authentication test
        profile = await get_user_profile(admin_id)
        logger.info(f"Admin profile: {profile}")
        
        # Authorization tests (admin can read and write)
        sensor_data = await read_sensor_data(admin_id, "sensor1")
        logger.info(f"Read sensor data: {sensor_data}")
        
        write_result = await write_sensor_data(admin_id, "sensor2", {"value": 25.0})
        logger.info(f"Write result: {write_result}")
        
        # Service methods
        sensors = await sensor_service.list_sensors(admin_id)
        logger.info(f"Available sensors: {sensors}")
        
    except (AuthenticationError, AuthorizationError) as e:
        logger.error(f"Error with admin: {e}")
    
    # Test with user principal
    user_id = "user1"
    try:
        # Authentication test (should work)
        profile = await get_user_profile(user_id)
        logger.info(f"User profile: {profile}")
        
        # Authorization test - read (should work)
        sensor_data = await read_sensor_data(user_id, "sensor1")
        logger.info(f"Read sensor data: {sensor_data}")
        
        # Authorization test - write (should fail)
        try:
            write_result = await write_sensor_data(user_id, "sensor2", {"value": 25.0})
            logger.info(f"Write result: {write_result}")
        except AuthorizationError as e:
            logger.warning(f"Expected authorization error: {e}")
        
        # Service methods
        sensors = await sensor_service.list_sensors(user_id)
        logger.info(f"Available sensors: {sensors}")
        
        # This should fail (user doesn't have write:sensor_config permission)
        try:
            result = await sensor_service.configure_sensor(user_id, "sensor1", {"active": True})
            logger.info(f"Configure result: {result}")
        except AuthorizationError as e:
            logger.warning(f"Expected authorization error: {e}")
            
    except (AuthenticationError, AuthorizationError) as e:
        logger.error(f"Error with user: {e}")
    
    # Test with non-existent principal (should fail authentication)
    try:
        profile = await get_user_profile("nonexistent")
        logger.info(f"Profile: {profile}")
    except AuthenticationError as e:
        logger.warning(f"Expected authentication error: {e}")


if __name__ == "__main__":
    asyncio.run(run_demo())