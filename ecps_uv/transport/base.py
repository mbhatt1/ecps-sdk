"""
Base Transport class for ECPS-UV SDK.

This module defines the abstract Transport interface that all specific
transport implementations (DDS, gRPC, MQTT) must implement.
"""

import abc
import logging
from typing import Any, Callable, Dict, List, Optional, Union

logger = logging.getLogger("ecps_uv.transport")


class Transport(abc.ABC):
    """
    Abstract base class for all transport implementations.
    
    A Transport is responsible for sending and receiving messages over
    a specific protocol (DDS, gRPC, MQTT).
    """
    
    def __init__(
        self,
        serializer: Any,
        config: Optional[Dict[str, Any]] = None,
        loop: Optional[Any] = None,
        is_server: bool = False,
    ):
        """
        Initialize the transport.
        
        Args:
            serializer: Serializer to use for message encoding/decoding
            config: Transport-specific configuration
            loop: UV event loop to use
            is_server: Whether this transport is for a server (True) or client (False)
        """
        self.serializer = serializer
        self.config = config or {}
        self.loop = loop
        self.is_server = is_server
        self.handlers = {}  # Topic/route/path -> handler function
    
    @abc.abstractmethod
    async def connect(self):
        """Establish connection using this transport."""
        pass
    
    @abc.abstractmethod
    async def close(self):
        """Close the transport and release resources."""
        pass
    
    @abc.abstractmethod
    async def start(self):
        """Start the transport server (if is_server=True)."""
        pass
    
    @abc.abstractmethod
    async def publish(
        self,
        topic: str,
        message: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Publish a message to a topic/route/path.
        
        Args:
            topic: Topic, route, or path to publish to
            message: Message to publish (will be serialized)
            qos: Quality of Service parameters (transport-specific)
        """
        pass
    
    @abc.abstractmethod
    async def subscribe(
        self,
        topic: str,
        handler: Callable,
        message_type: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Subscribe to a topic/route/path.
        
        Args:
            topic: Topic, route, or path to subscribe to
            handler: Callback function to handle received messages
            message_type: Type of messages expected on this topic
            qos: Quality of Service parameters (transport-specific)
        """
        pass
    
    @abc.abstractmethod
    async def request(
        self,
        service: str,
        request: Any,
        timeout: float = 10.0,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Send a request to a service and await response.
        
        Args:
            service: Service name
            request: Request message (will be serialized)
            timeout: Timeout in seconds
            qos: Quality of Service parameters (transport-specific)
            
        Returns:
            response: Response message (deserialized)
        """
        pass
    
    @abc.abstractmethod
    async def register_service(
        self,
        service: str,
        handler: Callable,
        request_type: Any,
        response_type: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Register a service handler.
        
        Args:
            service: Service name
            handler: Callback function to handle service requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos: Quality of Service parameters (transport-specific)
        """
        pass
    
    @abc.abstractmethod
    async def stream_request(
        self,
        service: str,
        request: Any,
        handler: Callable,
        timeout: float = 60.0,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Send a request to a service and handle streamed responses.
        
        Args:
            service: Service name
            request: Request message (will be serialized)
            handler: Callback function to handle streamed responses
            timeout: Timeout in seconds
            qos: Quality of Service parameters (transport-specific)
        """
        pass
    
    @abc.abstractmethod
    async def register_stream_service(
        self,
        service: str,
        handler: Callable,
        request_type: Any,
        response_type: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Register a streaming service handler.
        
        Args:
            service: Service name
            handler: Callback function to handle streaming requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos: Quality of Service parameters (transport-specific)
        """
        pass