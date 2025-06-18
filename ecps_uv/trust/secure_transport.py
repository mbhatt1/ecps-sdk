"""
Secure transport wrapper for ECPS UV SDK.

This module provides a secure transport wrapper that adds security
features to any transport implementation.
"""

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from ecps_uv.trust.trust import Principal, TrustLevel, TrustProvider

logger = logging.getLogger("ecps_uv.trust.secure_transport")


@dataclass
class SecureMessage:
    """Wrapper for secure messages."""
    # Original message in serialized form
    message: bytes
    # Type name of the original message
    message_type: str
    # Message signature (if signed)
    signature: Optional[bytes] = None
    # Encrypted symmetric key (if encrypted)
    encrypted_key: Optional[bytes] = None
    # Initialization vector for symmetric encryption
    iv: Optional[bytes] = None
    # Security token (e.g., JWT)
    security_token: Optional[str] = None
    # ID of the sender
    sender_id: Optional[str] = None
    # Message timestamp
    timestamp: int = field(default_factory=lambda: int(time.time_ns()))

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary.
        
        Returns:
            Dictionary representation
        """
        result = {
            "message": base64.b64encode(self.message).decode("ascii"),
            "message_type": self.message_type,
            "timestamp": self.timestamp,
        }
        
        if self.signature:
            result["signature"] = base64.b64encode(self.signature).decode("ascii")
            
        if self.encrypted_key:
            result["encrypted_key"] = base64.b64encode(self.encrypted_key).decode("ascii")
            
        if self.iv:
            result["iv"] = base64.b64encode(self.iv).decode("ascii")
            
        if self.security_token:
            result["security_token"] = self.security_token
            
        if self.sender_id:
            result["sender_id"] = self.sender_id
            
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecureMessage":
        """
        Create from dictionary.
        
        Args:
            data: Dictionary representation
            
        Returns:
            SecureMessage instance
        """
        # Convert base64 fields back to bytes
        message = base64.b64decode(data["message"])
        
        signature = None
        if "signature" in data:
            signature = base64.b64decode(data["signature"])
            
        encrypted_key = None
        if "encrypted_key" in data:
            encrypted_key = base64.b64decode(data["encrypted_key"])
            
        iv = None
        if "iv" in data:
            iv = base64.b64decode(data["iv"])
            
        return cls(
            message=message,
            message_type=data["message_type"],
            signature=signature,
            encrypted_key=encrypted_key,
            iv=iv,
            security_token=data.get("security_token"),
            sender_id=data.get("sender_id"),
            timestamp=data.get("timestamp", int(time.time_ns())),
        )


class SecureTransport:
    """Secure transport wrapper."""

    def __init__(
        self, 
        transport: Any, 
        trust_provider: TrustProvider,
        principal_id: Optional[str] = None,
        security_token: Optional[str] = None,
    ):
        """
        Initialize the secure transport.
        
        Args:
            transport: The transport to wrap
            trust_provider: The trust provider
            principal_id: ID of the principal to use
            security_token: Security token (e.g., JWT)
        """
        self.transport = transport
        self.trust_provider = trust_provider
        self.principal_id = principal_id
        self.security_token = security_token
        self.serializer = getattr(transport, "serializer", None)

    def set_principal(self, principal_id: str, security_token: str) -> None:
        """
        Set the principal ID and security token.
        
        Args:
            principal_id: ID of the principal
            security_token: Security token (e.g., JWT)
        """
        self.principal_id = principal_id
        self.security_token = security_token

    async def publish(
        self, 
        topic: str, 
        message: Any, 
        qos: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Publish a message with security features.
        
        Args:
            topic: Topic to publish to
            message: Message to publish
            qos: Quality of service parameters
        """
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.publish(topic, message, qos)
        
        # Check if we have a serializer
        if not self.serializer:
            raise ValueError("Transport does not provide a serializer")
        
        # Serialize the original message
        message_bytes = await self.serializer.serialize(message, use_json=False)
        
        # Create secure message
        secure_msg = SecureMessage(
            message=message_bytes,
            message_type=type(message).__name__,
            sender_id=self.principal_id,
        )
        
        # Add security token if available
        if self.security_token:
            secure_msg.security_token = self.security_token
        
        # Sign message if trust level requires it
        if self.trust_provider.trust_level >= TrustLevel.AUTHENTICATED:
            try:
                signature = self.trust_provider.sign_message(message_bytes)
                secure_msg.signature = signature
            except Exception as e:
                logger.error(f"Failed to sign message: {e}")
                raise
        
        # Encrypt message if trust level requires it
        if self.trust_provider.trust_level >= TrustLevel.ENCRYPTION:
            # In a real implementation, we would use a hybrid encryption scheme:
            # 1. Generate a random symmetric key
            # 2. Encrypt the message with the symmetric key
            # 3. Encrypt the symmetric key with the recipient's public key
            # 4. Include the encrypted key and IV in the secure message
            
            # For this example, we'll just note that encryption would happen here
            # and leave the original message intact
            
            # In a real implementation:
            # encrypted_msg, encrypted_key, iv = encrypt_with_hybrid_scheme(message_bytes)
            # secure_msg.message = encrypted_msg
            # secure_msg.encrypted_key = encrypted_key
            # secure_msg.iv = iv
            pass
        
        # Convert to dictionary for transport
        secure_dict = secure_msg.to_dict()
        
        # Publish secure message
        await self.transport.publish(topic, secure_dict, qos)

    async def subscribe(
        self, 
        topic: str, 
        handler: Callable, 
        message_type: Any = None, 
        qos: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Subscribe to a topic with security features.
        
        Args:
            topic: Topic to subscribe to
            handler: Callback function for received messages
            message_type: Expected message type
            qos: Quality of service parameters
        """
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.subscribe(topic, handler, message_type, qos)
        
        # Check if we have a serializer
        if not self.serializer:
            raise ValueError("Transport does not provide a serializer")
        
        # Create secure message handler
        async def secure_handler(secure_dict: Dict[str, Any]) -> None:
            try:
                # Convert dictionary to SecureMessage
                secure_msg = SecureMessage.from_dict(secure_dict)
                
                # Verify signature if trust level requires it
                if (self.trust_provider.trust_level >= TrustLevel.AUTHENTICATED and 
                    secure_msg.signature is not None):
                    if not self.trust_provider.verify_message(secure_msg.message, secure_msg.signature):
                        logger.error("Message signature verification failed")
                        return
                
                # Decrypt message if trust level requires it
                message_bytes = secure_msg.message
                if (self.trust_provider.trust_level >= TrustLevel.ENCRYPTION and 
                    secure_msg.encrypted_key is not None):
                    # In a real implementation, we would:
                    # 1. Decrypt the symmetric key with our private key
                    # 2. Decrypt the message with the symmetric key and IV
                    
                    # For this example, we'll just note that decryption would happen here
                    # message_bytes = decrypt_with_hybrid_scheme(secure_msg)
                    pass
                
                # Authenticate sender if trust level requires it
                principal = None
                if (self.trust_provider.trust_level >= TrustLevel.AUTHENTICATED and 
                    secure_msg.security_token):
                    principal = self.trust_provider.validate_jwt(secure_msg.security_token)
                    if not principal:
                        logger.error("Security token validation failed")
                        return
                    
                    # Check if sender ID matches the token subject
                    if (secure_msg.sender_id and 
                        secure_msg.sender_id != principal.id):
                        logger.error("Sender ID does not match security token subject")
                        return
                
                # Authorize action if trust level requires it
                if (self.trust_provider.trust_level >= TrustLevel.AUTHORIZED and 
                    principal is not None):
                    authorized, reason = await self.trust_provider.authorize(
                        principal, 
                        "subscribe", 
                        topic
                    )
                    if not authorized:
                        logger.error(f"Sender is not authorized: {reason}")
                        return
                
                # Deserialize original message
                orig_message = await self.serializer.deserialize(
                    message_bytes, 
                    message_type or secure_msg.message_type
                )
                
                # Call original handler with the deserialized message
                await handler(orig_message)
                
            except Exception as e:
                logger.error(f"Error handling secure message: {e}")

        # Subscribe with secure handler
        await self.transport.subscribe(topic, secure_handler, Dict[str, Any], qos)

    async def request(
        self, 
        service: str, 
        request: Any, 
        timeout: float = 5.0, 
        qos: Optional[Dict[str, Any]] = None
    ) -> Any:
        """
        Send a request with security features.
        
        Args:
            service: Service name
            request: Request message
            timeout: Request timeout
            qos: Quality of service parameters
            
        Returns:
            Response message
        """
        # Not implementing security for request/response yet
        # In a real implementation, we would wrap the request in a SecureMessage
        # and unwrap the response
        return await self.transport.request(service, request, timeout, qos)

    async def stream_request(
        self, 
        service: str, 
        request: Any, 
        handler: Callable, 
        timeout: float = 5.0, 
        qos: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Send a streaming request with security features.
        
        Args:
            service: Service name
            request: Request message
            handler: Handler for streaming responses
            timeout: Request timeout
            qos: Quality of service parameters
        """
        # Not implementing security for streaming request yet
        # In a real implementation, we would wrap the request in a SecureMessage
        # and unwrap the responses
        await self.transport.stream_request(service, request, handler, timeout, qos)

    async def register_service(
        self, 
        service: str, 
        handler: Callable, 
        request_type: Any, 
        response_type: Any, 
        qos: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a service with security features.
        
        Args:
            service: Service name
            handler: Service handler
            request_type: Request message type
            response_type: Response message type
            qos: Quality of service parameters
        """
        # Not implementing security for service registration yet
        # In a real implementation, we would unwrap incoming SecureMessage objects
        # and wrap outgoing responses
        await self.transport.register_service(
            service, 
            handler, 
            request_type, 
            response_type, 
            qos
        )

    async def register_stream_service(
        self, 
        service: str, 
        handler: Callable, 
        request_type: Any, 
        response_type: Any, 
        qos: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Register a streaming service with security features.
        
        Args:
            service: Service name
            handler: Service handler
            request_type: Request message type
            response_type: Response message type
            qos: Quality of service parameters
        """
        # Not implementing security for streaming service registration yet
        # In a real implementation, we would unwrap incoming SecureMessage objects
        # and wrap outgoing responses
        await self.transport.register_stream_service(
            service, 
            handler, 
            request_type, 
            response_type, 
            qos
        )