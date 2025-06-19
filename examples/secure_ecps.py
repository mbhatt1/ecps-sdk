#!/usr/bin/env python3
"""
Example demonstrating the trust layer in the ECPS UV SDK.

This example shows how to use the trust layer to secure communications
between ECPS components, including authentication, authorization, and
message signing.
"""

import argparse
import asyncio
import logging
import signal
import sys
import time
from datetime import datetime, timedelta

from ecps_uv.cognition.mcp import MCPHandler
from ecps_uv.serialization.protobuf import ProtobufSerializer
from ecps_uv.transport.dds import DDSTransport
from ecps_uv.trust import (
    Principal,
    RBACAuthorizer,
    TrustLevel,
    TrustMechanism,
    TrustProvider,
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger("secure_ecps")

# Constants
MESSAGE_TOPIC = "secure_messages"


async def create_trust_provider(args):
    """
    Create and configure a trust provider.
    
    Args:
        args: Command line arguments
        
    Returns:
        Configured trust provider
    """
    # Configure trust level
    trust_level = TrustLevel(args.trust_level)
    logger.info(f"Using trust level: {trust_level.name}")
    
    # Configure trust mechanisms
    mechanisms = [TrustMechanism.JWT]
    if args.use_tls:
        mechanisms.append(TrustMechanism.TLS)
    
    # Create an RBAC authorizer
    authorizer = RBACAuthorizer()
    
    # Add permissions for roles
    authorizer.add_role_permission("admin", "publish", MESSAGE_TOPIC)
    authorizer.add_role_permission("admin", "subscribe", MESSAGE_TOPIC)
    authorizer.add_role_permission("user", "subscribe", MESSAGE_TOPIC)
    
    # Create trust provider
    provider = TrustProvider(
        trust_level=trust_level,
        mechanisms=mechanisms,
        jwt_secret=args.jwt_secret,
        private_key_path=args.key_file,
        public_key_path=args.cert_file,
        authorizer=authorizer,
    )
    
    # Add test principals
    admin_principal = Principal(
        id="admin1",
        name="Administrator",
        roles=["admin"],
        permissions={"publish:secure_messages": True},
        attributes={"department": "IT"},
    )
    provider.add_principal(admin_principal)
    
    user_principal = Principal(
        id="user1",
        name="Regular User",
        roles=["user"],
        permissions={"subscribe:secure_messages": True},
        attributes={"department": "Marketing"},
    )
    provider.add_principal(user_principal)
    
    return provider


async def create_secure_transport(args, trust_provider):
    """
    Create a transport with security features.
    
    Args:
        args: Command line arguments
        trust_provider: Trust provider
        
    Returns:
        Secure transport
    """
    # Create base transport (using DDS)
    base_transport = DDSTransport()
    
    # Create serializer
    serializer = ProtobufSerializer()
    base_transport.serializer = serializer
    
    # Wrap with secure transport
    secure_transport = trust_provider.secure_transport(base_transport)
    
    # Set principal for client mode
    if args.role == "client":
        # Authenticate principal
        principal = await trust_provider.authenticate(args.principal)
        if not principal:
            raise ValueError(f"Authentication failed for principal: {args.principal}")
            
        # Create JWT for the principal
        token = trust_provider.create_jwt(
            principal, 
            expires_in=timedelta(hours=1)
        )
        
        # Set principal on secure transport
        secure_transport.set_principal(principal.id, token)
        
        logger.info(f"Authenticated as {principal.name} ({principal.id})")
        
        # Check authorization for publishing
        authorized, reason = await trust_provider.authorize(
            principal, 
            "publish", 
            MESSAGE_TOPIC
        )
        if not authorized:
            logger.warning(f"Not authorized to publish: {reason}")
        else:
            logger.info("Authorized to publish messages")
    
    return secure_transport


async def run_server(args, trust_provider):
    """
    Run the server role.
    
    Args:
        args: Command line arguments
        trust_provider: Trust provider
    """
    logger.info("Starting secure server...")
    
    # Create secure transport
    transport = await create_secure_transport(args, trust_provider)
    
    # Create MCP handler
    mcp_handler = MCPHandler(transport, transport.serializer, None)
    
    # Start transport
    await transport.transport.start()
    
    # Message handler
    async def message_handler(mcp_message):
        # Extract principal from context if available
        principal_info = ""
        
        # Extract the principal from the security context
        # Check if this message came through secure transport with identity context
        if hasattr(mcp_message, "meta") and mcp_message.meta:
            # First try to get from security token
            security_token = mcp_message.meta.get("security_token")
            if security_token:
                try:
                    # Validate JWT and extract principal
                    principal = await trust_provider.validate_jwt(security_token)
                    if principal:
                        principal_info = f" from authenticated user {principal.name} ({principal.id})"
                except Exception as e:
                    logger.warning(f"Failed to validate security token: {e}")
            
            # Fallback to sender_id if no security token
            if not principal_info:
                sender_id = mcp_message.meta.get("sender_id")
                if sender_id:
                    principal = trust_provider.get_principal(sender_id)
                    if principal:
                        principal_info = f" from {principal.name} ({principal.id})"
                    else:
                        principal_info = f" from unknown sender {sender_id}"
        
        logger.info(f"Received secure message{principal_info}: {mcp_message.prompt}")
        
        # Extract metadata
        if hasattr(mcp_message, "meta") and mcp_message.meta:
            logger.info(f"Message metadata: {mcp_message.meta}")
        
        # Send a response if appropriate
        if not mcp_message.meta.get("is_response"):
            logger.info(f"Sending response to message ID: {mcp_message.id}")
            await mcp_handler.send_response(
                mcp_message.id,
                f"Secure echo: {mcp_message.prompt}",
                None,
                {"server_time": datetime.now().isoformat(), "is_response": "true"},
            )
    
    # Listen for messages
    await mcp_handler.listen([message_handler])
    
    logger.info(f"Server listening for secure messages on topic: {MESSAGE_TOPIC}")
    
    # Keep running until interrupted
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        logger.info("Server shutting down")
        await transport.transport.stop()


async def run_client(args, trust_provider):
    """
    Run the client role.
    
    Args:
        args: Command line arguments
        trust_provider: Trust provider
    """
    logger.info("Starting secure client...")
    
    # Create secure transport
    transport = await create_secure_transport(args, trust_provider)
    
    # Create MCP handler
    mcp_handler = MCPHandler(transport, transport.serializer, None)
    
    # Start transport
    await transport.transport.start()
    
    # Response handler
    async def response_handler(mcp_message):
        # Only process responses
        if mcp_message.meta.get("is_response") == "true":
            logger.info(f"Received response: {mcp_message.prompt}")
            if mcp_message.meta:
                logger.info(f"Response metadata: {mcp_message.meta}")
    
    # Listen for responses
    await mcp_handler.listen([response_handler])
    
    # Get authenticated principal
    principal = await trust_provider.authenticate(args.principal)
    if not principal:
        raise ValueError(f"Authentication failed for principal: {args.principal}")
    
    # Send messages periodically
    message_count = 0
    try:
        while True:
            message_count += 1
            message = f"Secure message #{message_count} from {principal.id}"
            
            # Send message
            message_id = await mcp_handler.send(
                message,
                None,
                None,
                {
                    "sender_id": principal.id,
                    "sender": principal.name,
                    "timestamp": datetime.now().isoformat(),
                }
            )
            
            logger.info(f"Sent secure message with ID: {message_id}")
            
            # Wait before sending next message
            await asyncio.sleep(2)
    except asyncio.CancelledError:
        logger.info("Client shutting down")
        await transport.transport.stop()


async def main():
    """Main entry point."""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="ECPS Secure Communication Example")
    parser.add_argument(
        "--role", 
        choices=["client", "server"], 
        default="client",
        help="Role to run (client or server)"
    )
    parser.add_argument(
        "--trust-level", 
        type=int, 
        default=3,
        help="Trust level (0-4): 0=None, 1=Encryption, 2=Authentication, 3=Authorization, 4=Audited"
    )
    parser.add_argument(
        "--jwt-secret", 
        default="your-256-bit-secret",
        help="JWT secret"
    )
    parser.add_argument(
        "--key-file", 
        help="Private key file (PEM format)"
    )
    parser.add_argument(
        "--cert-file", 
        help="Certificate file (PEM format)"
    )
    parser.add_argument(
        "--use-tls", 
        action="store_true",
        help="Use TLS encryption"
    )
    parser.add_argument(
        "--principal", 
        default="user1",
        help="Principal ID to authenticate as"
    )
    
    args = parser.parse_args()
    
    # Create trust provider
    trust_provider = await create_trust_provider(args)
    
    # Run client or server
    if args.role == "server":
        await run_server(args, trust_provider)
    else:
        await run_client(args, trust_provider)


if __name__ == "__main__":
    # Set up signal handling for graceful shutdown
    loop = asyncio.get_event_loop()
    
    # Handle SIGINT (Ctrl+C) and SIGTERM
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.create_task(
            asyncio.shield(asyncio.gather(*asyncio.all_tasks())).cancel()
        ))
    
    try:
        loop.run_until_complete(main())
    except asyncio.CancelledError:
        pass
    finally:
        loop.close()