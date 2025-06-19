"""
Secure transport wrapper for ECPS UV SDK.

This module provides a secure transport wrapper that adds security
features to any transport implementation, using identity forwarding
instead of per-request signing for better performance.
"""

import asyncio
import base64
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import secrets

from ecps_uv.trust.trust import Principal, TrustLevel, TrustProvider
from ecps_uv.trust.identity_forwarding import (
    IdentityContext,
    IdentityForwardingManager,
    ForwardedRequest
)

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
    """Secure transport wrapper using identity forwarding."""

    def __init__(
        self,
        transport: Any,
        trust_provider: TrustProvider,
        identity_forwarding_manager: Optional[IdentityForwardingManager] = None,
        identity_context: Optional[IdentityContext] = None,
    ):
        """
        Initialize the secure transport.
        
        Args:
            transport: The transport to wrap
            trust_provider: The trust provider
            identity_forwarding_manager: Manager for identity forwarding
            identity_context: Current identity context (if established)
        """
        self.transport = transport
        self.trust_provider = trust_provider
        self.identity_forwarding_manager = identity_forwarding_manager
        self.identity_context = identity_context
        self.serializer = getattr(transport, "serializer", None)

    def set_identity_context(self, identity_context: IdentityContext) -> None:
        """
        Set the identity context for this transport.
        
        Args:
            identity_context: The identity context to use
        """
        self.identity_context = identity_context

    async def publish(
        self,
        topic: str,
        message: Any,
        qos: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Publish a message with identity forwarding.
        
        Args:
            topic: Topic to publish to
            message: Message to publish
            qos: Quality of service parameters
        """
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.publish(topic, message, qos)
        
        # Check if we have identity context
        if not self.identity_context:
            raise ValueError("No identity context available for secure transport")
        
        # Check if identity context is still valid
        if self.identity_context.is_expired:
            raise ValueError("Identity context has expired")
        
        # Create forwarded request instead of signing each message
        if self.identity_forwarding_manager:
            forwarded_request = self.identity_forwarding_manager.create_forwarded_request(
                message, self.identity_context
            )
            
            # Convert to dictionary for transport
            forwarded_dict = forwarded_request.to_dict()
            
            # Publish forwarded request
            await self.transport.publish(topic, forwarded_dict, qos)
        else:
            # Fallback to legacy secure message approach
            if not self.serializer:
                raise ValueError("Transport does not provide a serializer")
            
            # Serialize the original message
            message_bytes = await self.serializer.serialize(message, use_json=False)
            
            # Create secure message with identity context
            secure_msg = SecureMessage(
                message=message_bytes,
                message_type=type(message).__name__,
                sender_id=self.identity_context.identity.id,
                security_token=self.identity_context.session_id,  # Use session ID as token
            )
            
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
        Subscribe to a topic with identity forwarding validation.
        
        Args:
            topic: Topic to subscribe to
            handler: Callback function for received messages
            message_type: Expected message type
            qos: Quality of service parameters
        """
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.subscribe(topic, handler, message_type, qos)
        
        # Create forwarded request handler
        async def forwarded_handler(forwarded_dict: Dict[str, Any]) -> None:
            try:
                # Check if this is a forwarded request
                if "identity_context" in forwarded_dict and self.identity_forwarding_manager:
                    # Handle forwarded request
                    forwarded_request = ForwardedRequest(
                        payload=forwarded_dict["payload"],
                        identity_context=IdentityContext(
                            identity=forwarded_dict["identity_context"]["identity"],
                            principal_id=forwarded_dict["identity_context"]["principal_id"],
                            session_id=forwarded_dict["identity_context"]["session_id"],
                            established_at=datetime.fromisoformat(forwarded_dict["identity_context"]["established_at"]),
                            expires_at=datetime.fromisoformat(forwarded_dict["identity_context"]["expires_at"]),
                            capabilities=set(forwarded_dict["identity_context"]["capabilities"]),
                            attributes=forwarded_dict["identity_context"]["attributes"],
                        ),
                        request_id=forwarded_dict["request_id"],
                        timestamp=datetime.fromisoformat(forwarded_dict["timestamp"]),
                        service_chain=forwarded_dict["service_chain"],
                    )
                    
                    # Validate forwarded request
                    is_valid, error_reason = await self.identity_forwarding_manager.validate_forwarded_request(
                        forwarded_request, None, f"subscribe:{topic}"
                    )
                    
                    if not is_valid:
                        logger.error(f"Forwarded request validation failed: {error_reason}")
                        return
                    
                    # Authorize if required
                    if self.trust_provider.trust_level >= TrustLevel.AUTHORIZED:
                        authorized, reason = await self.identity_forwarding_manager.authorize_forwarded_request(
                            forwarded_request, "subscribe", topic
                        )
                        if not authorized:
                            logger.error(f"Forwarded request authorization failed: {reason}")
                            return
                    
                    # Call original handler with the payload
                    await handler(forwarded_request.payload)
                    
                else:
                    # Handle legacy secure message
                    if not self.serializer:
                        raise ValueError("Transport does not provide a serializer")
                    
                    # Convert dictionary to SecureMessage
                    secure_msg = SecureMessage.from_dict(forwarded_dict)
                    
                    # Validate session ID if available
                    if (self.trust_provider.trust_level >= TrustLevel.AUTHENTICATED and
                        secure_msg.security_token and self.identity_forwarding_manager):
                        context = self.identity_forwarding_manager.get_context_by_session(secure_msg.security_token)
                        if not context:
                            logger.error("Invalid or expired session ID")
                            return
                    
                    # Deserialize original message
                    orig_message = await self.serializer.deserialize(
                        secure_msg.message,
                        message_type or secure_msg.message_type
                    )
                    
                    # Call original handler with the deserialized message
                    await handler(orig_message)
                
            except Exception as e:
                logger.error(f"Error handling forwarded message: {e}")

        # Subscribe with forwarded handler
        await self.transport.subscribe(topic, forwarded_handler, Dict[str, Any], qos)

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
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.request(service, request, timeout, qos)
        
        # Check if we have identity context
        if not self.identity_context:
            raise ValueError("No identity context available for secure transport")
        
        # Check if identity context is still valid
        if self.identity_context.is_expired:
            raise ValueError("Identity context has expired")
        
        # Create forwarded request if manager is available
        if self.identity_forwarding_manager:
            forwarded_request = self.identity_forwarding_manager.create_forwarded_request(
                request, self.identity_context
            )
            
            # Convert to dictionary for transport
            forwarded_dict = forwarded_request.to_dict()
            
            # Send forwarded request and get response
            response_dict = await self.transport.request(service, forwarded_dict, timeout, qos)
            
            # Validate and unwrap response if it's a forwarded response
            if isinstance(response_dict, dict) and "identity_context" in response_dict:
                # Validate the response identity context
                if self.identity_forwarding_manager.validate_forwarded_request(
                    ForwardedRequest.from_dict(response_dict)
                ):
                    return response_dict["payload"]
                else:
                    raise ValueError("Invalid forwarded response")
            else:
                return response_dict
        else:
            # Fallback to secure message approach
            if not self.serializer:
                raise ValueError("Transport does not provide a serializer")
            
            # Serialize the request
            request_bytes = await self.serializer.serialize(request, use_json=False)
            
            # Create secure message
            secure_msg = await self._create_secure_message(request_bytes, type(request).__name__)
            
            # Send secure request
            secure_dict = secure_msg.to_dict()
            response_dict = await self.transport.request(service, secure_dict, timeout, qos)
            
            # Unwrap secure response
            if isinstance(response_dict, dict) and "message" in response_dict:
                secure_response = SecureMessage.from_dict(response_dict)
                response_bytes = await self._unwrap_secure_message(secure_response)
                return await self.serializer.deserialize(response_bytes, use_json=False)
            else:
                return response_dict

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
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.stream_request(service, request, handler, timeout, qos)
        
        # Check if we have identity context
        if not self.identity_context:
            raise ValueError("No identity context available for secure transport")
        
        # Check if identity context is still valid
        if self.identity_context.is_expired:
            raise ValueError("Identity context has expired")
        
        # Create secure handler wrapper
        async def secure_handler(response: Any) -> None:
            try:
                # Unwrap secure response if needed
                if isinstance(response, dict) and "message" in response:
                    secure_response = SecureMessage.from_dict(response)
                    response_bytes = await self._unwrap_secure_message(secure_response)
                    unwrapped_response = await self.serializer.deserialize(response_bytes, use_json=False)
                    await handler(unwrapped_response)
                else:
                    await handler(response)
            except Exception as e:
                logger.error(f"Error in secure streaming handler: {e}")
                raise
        
        # Create forwarded request if manager is available
        if self.identity_forwarding_manager:
            forwarded_request = self.identity_forwarding_manager.create_forwarded_request(
                request, self.identity_context
            )
            
            # Convert to dictionary for transport
            forwarded_dict = forwarded_request.to_dict()
            
            # Send forwarded streaming request
            await self.transport.stream_request(service, forwarded_dict, secure_handler, timeout, qos)
        else:
            # Fallback to secure message approach
            if not self.serializer:
                raise ValueError("Transport does not provide a serializer")
            
            # Serialize the request
            request_bytes = await self.serializer.serialize(request, use_json=False)
            
            # Create secure message
            secure_msg = await self._create_secure_message(request_bytes, type(request).__name__)
            
            # Send secure streaming request
            secure_dict = secure_msg.to_dict()
            await self.transport.stream_request(service, secure_dict, secure_handler, timeout, qos)

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
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.register_service(service, handler, request_type, response_type, qos)
        
        # Create secure handler wrapper
        async def secure_handler(request: Any) -> Any:
            try:
                # Unwrap secure request if needed
                if isinstance(request, dict) and "message" in request:
                    secure_request = SecureMessage.from_dict(request)
                    request_bytes = await self._unwrap_secure_message(secure_request)
                    unwrapped_request = await self.serializer.deserialize(request_bytes, use_json=False)
                    
                    # Call original handler
                    response = await handler(unwrapped_request)
                    
                    # Wrap response in secure message
                    if response is not None:
                        response_bytes = await self.serializer.serialize(response, use_json=False)
                        secure_response = await self._create_secure_message(response_bytes, type(response).__name__)
                        return secure_response.to_dict()
                    else:
                        return None
                elif isinstance(request, dict) and "identity_context" in request:
                    # Handle forwarded request
                    if self.identity_forwarding_manager:
                        forwarded_request = ForwardedRequest.from_dict(request)
                        if self.identity_forwarding_manager.validate_forwarded_request(forwarded_request):
                            # Call original handler with unwrapped payload
                            response = await handler(forwarded_request.payload)
                            
                            # Create forwarded response
                            if response is not None:
                                forwarded_response = self.identity_forwarding_manager.create_forwarded_request(
                                    response, forwarded_request.identity_context
                                )
                                return forwarded_response.to_dict()
                            else:
                                return None
                        else:
                            raise ValueError("Invalid forwarded request")
                    else:
                        raise ValueError("Received forwarded request but no manager available")
                else:
                    # Direct request, call handler as-is
                    return await handler(request)
            except Exception as e:
                logger.error(f"Error in secure service handler: {e}")
                raise
        
        await self.transport.register_service(service, secure_handler, request_type, response_type, qos)

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
        # Skip security if trust level is none
        if self.trust_provider.trust_level == TrustLevel.NONE:
            return await self.transport.register_stream_service(service, handler, request_type, response_type, qos)
        
        # Create secure streaming handler wrapper
        async def secure_streaming_handler(request: Any, response_handler: Callable) -> None:
            try:
                # Create secure response handler
                async def secure_response_handler(response: Any) -> None:
                    if response is not None:
                        if self.serializer:
                            response_bytes = await self.serializer.serialize(response, use_json=False)
                            secure_response = await self._create_secure_message(response_bytes, type(response).__name__)
                            await response_handler(secure_response.to_dict())
                        else:
                            await response_handler(response)
                    else:
                        await response_handler(None)
                
                # Unwrap secure request if needed
                if isinstance(request, dict) and "message" in request:
                    secure_request = SecureMessage.from_dict(request)
                    request_bytes = await self._unwrap_secure_message(secure_request)
                    unwrapped_request = await self.serializer.deserialize(request_bytes, use_json=False)
                    
                    # Call original handler
                    await handler(unwrapped_request, secure_response_handler)
                elif isinstance(request, dict) and "identity_context" in request:
                    # Handle forwarded request
                    if self.identity_forwarding_manager:
                        forwarded_request = ForwardedRequest.from_dict(request)
                        if self.identity_forwarding_manager.validate_forwarded_request(forwarded_request):
                            # Call original handler with unwrapped payload
                            await handler(forwarded_request.payload, secure_response_handler)
                        else:
                            raise ValueError("Invalid forwarded request")
                    else:
                        raise ValueError("Received forwarded request but no manager available")
                else:
                    # Direct request, call handler as-is
                    await handler(request, response_handler)
            except Exception as e:
                logger.error(f"Error in secure streaming service handler: {e}")
                raise
        
        await self.transport.register_stream_service(service, secure_streaming_handler, request_type, response_type, qos)

    async def _create_secure_message(self, message_bytes: bytes, message_type: str) -> SecureMessage:
        """
        Create a secure message with encryption if required.
        
        Args:
            message_bytes: The message to secure
            message_type: The type of the message
            
        Returns:
            SecureMessage with appropriate security features
        """
        secure_msg = SecureMessage(
            message=message_bytes,
            message_type=message_type,
            sender_id=self.identity_context.identity.id if self.identity_context else None,
            security_token=self.identity_context.session_id if self.identity_context else None,
        )
        
        # Add encryption if trust level requires it
        if self.trust_provider.trust_level >= TrustLevel.ENCRYPTION:
            # Generate a random symmetric key for AES encryption
            symmetric_key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(16)  # 128-bit IV
            
            # Encrypt the message with AES
            cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            
            # Pad the message to block size
            block_size = 16
            padding_length = block_size - (len(message_bytes) % block_size)
            padded_message = message_bytes + bytes([padding_length] * padding_length)
            
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
            
            # Encrypt the symmetric key with the recipient's public key (if available)
            if hasattr(self.trust_provider, 'public_key') and self.trust_provider.public_key:
                encrypted_key = self.trust_provider.public_key.encrypt(
                    symmetric_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                secure_msg.encrypted_key = encrypted_key
            
            secure_msg.message = encrypted_message
            secure_msg.iv = iv
        
        # Add signature if trust level requires it
        if self.trust_provider.trust_level >= TrustLevel.SIGNING:
            if hasattr(self.trust_provider, 'private_key') and self.trust_provider.private_key:
                signature = self.trust_provider.private_key.sign(
                    secure_msg.message,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                secure_msg.signature = signature
        
        return secure_msg

    async def _unwrap_secure_message(self, secure_msg: SecureMessage) -> bytes:
        """
        Unwrap a secure message, verifying signature and decrypting if needed.
        
        Args:
            secure_msg: The secure message to unwrap
            
        Returns:
            The original message bytes
        """
        message_bytes = secure_msg.message
        
        # Verify signature if present
        if secure_msg.signature and hasattr(self.trust_provider, 'public_key') and self.trust_provider.public_key:
            try:
                self.trust_provider.public_key.verify(
                    secure_msg.signature,
                    message_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
            except Exception as e:
                logger.error(f"Signature verification failed: {e}")
                raise ValueError("Invalid message signature")
        
        # Decrypt if encrypted
        if secure_msg.encrypted_key and secure_msg.iv:
            if hasattr(self.trust_provider, 'private_key') and self.trust_provider.private_key:
                # Decrypt the symmetric key
                symmetric_key = self.trust_provider.private_key.decrypt(
                    secure_msg.encrypted_key,
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Decrypt the message
                cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(secure_msg.iv), backend=default_backend())
                decryptor = cipher.decryptor()
                padded_message = decryptor.update(message_bytes) + decryptor.finalize()
                
                # Remove padding
                padding_length = padded_message[-1]
                message_bytes = padded_message[:-padding_length]
        
        return message_bytes