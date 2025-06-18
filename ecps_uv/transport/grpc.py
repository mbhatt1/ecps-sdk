"""
gRPC/HTTP-2 Transport implementation for ECPS-UV SDK.

This module provides a Transport implementation using gRPC/HTTP-2,
suitable for cloud robot fleets, long-running operations, and 
request/response patterns over WAN connections.
"""

import asyncio
import logging
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

import uv
import grpc
from grpc.aio import server as grpc_server
from grpc.aio import channel as grpc_channel
import grpc.aio

from ecps_uv.transport.base import Transport

logger = logging.getLogger("ecps_uv.transport.grpc")


class GRPCTransport(Transport):
    """
    Transport implementation using gRPC/HTTP-2.
    
    This transport is suitable for cloud robot fleets, long-running operations,
    and request/response patterns over WAN connections.
    """
    
    def __init__(
        self,
        serializer: Any,
        config: Optional[Dict[str, Any]] = None,
        loop: Optional[Any] = None,
        is_server: bool = False,
    ):
        """
        Initialize the gRPC transport.
        
        Args:
            serializer: Serializer to use for message encoding/decoding
            config: gRPC-specific configuration
            loop: UV event loop to use
            is_server: Whether this transport is for a server (True) or client (False)
        """
        super().__init__(serializer, config, loop, is_server)
        
        # gRPC-specific configuration
        self.host = config.get("host", "localhost")
        self.port = config.get("port", 50051)
        self.address = f"{self.host}:{self.port}"
        self.use_tls = config.get("use_tls", False)
        self.ca_cert = config.get("ca_cert")
        self.client_cert = config.get("client_cert")
        self.client_key = config.get("client_key")
        
        # gRPC objects
        self.server = None
        self.channels = {}  # address -> channel
        self.stubs = {}  # service_name -> stub
        self.servicers = {}  # service_name -> servicer
        
        # Service definitions
        self.service_handlers = {}  # service_name -> {method_name -> handler}
    
    def _create_channel_credentials(self):
        """Create channel credentials for secure connections."""
        if not self.use_tls:
            return grpc.aio.ChannelCredentials()
        
        # Create TLS credentials
        if self.client_cert and self.client_key:
            # Mutual TLS authentication
            credentials = grpc.aio.ssl_channel_credentials(
                root_certificates=self.ca_cert.encode() if self.ca_cert else None,
                private_key=self.client_key.encode() if self.client_key else None,
                certificate_chain=self.client_cert.encode() if self.client_cert else None,
            )
        else:
            # Server-only TLS authentication
            credentials = grpc.aio.ssl_channel_credentials(
                root_certificates=self.ca_cert.encode() if self.ca_cert else None,
            )
        
        return credentials
    
    def _create_server_credentials(self):
        """Create server credentials for secure connections."""
        if not self.use_tls:
            return None
        
        # Create TLS credentials
        if self.client_cert and self.client_key:
            # Mutual TLS authentication
            credentials = grpc.aio.ssl_server_credentials(
                [(self.client_key.encode(), self.client_cert.encode())],
                root_certificates=self.ca_cert.encode() if self.ca_cert else None,
                require_client_auth=True,
            )
        else:
            # Server-only TLS authentication
            credentials = grpc.aio.ssl_server_credentials(
                [(self.client_key.encode(), self.client_cert.encode())],
            )
        
        return credentials
    
    async def connect(self):
        """Establish gRPC connection."""
        if self.is_server:
            # For servers, connect() doesn't do anything
            return
        
        # For clients, create a channel to the server
        if self.address not in self.channels:
            credentials = self._create_channel_credentials() if self.use_tls else None
            
            if credentials:
                channel = grpc.aio.secure_channel(self.address, credentials)
            else:
                channel = grpc.aio.insecure_channel(self.address)
            
            self.channels[self.address] = channel
            logger.info(f"Created gRPC channel to {self.address}")
    
    async def close(self):
        """Close the gRPC transport and release resources."""
        # Close all channels
        for address, channel in self.channels.items():
            await channel.close()
        
        self.channels.clear()
        self.stubs.clear()
        
        # Stop server if running
        if self.server:
            await self.server.stop(grace=1.0)
            self.server = None
        
        logger.info("gRPC transport closed")
    
    async def start(self):
        """Start the gRPC server."""
        if not self.is_server:
            logger.warning("start() called on a client-mode gRPC transport")
            return
        
        # Create server if not already created
        if not self.server:
            self.server = grpc_server()
            
            # Add services to server
            for service_name, servicer in self.servicers.items():
                self.server.add_service(servicer)
            
            # Get server credentials
            credentials = self._create_server_credentials() if self.use_tls else None
            
            # Start server
            if credentials:
                self.server.add_secure_port(self.address, credentials)
            else:
                self.server.add_insecure_port(self.address)
            
            await self.server.start()
            logger.info(f"gRPC server started on {self.address}")
    
    async def publish(
        self,
        topic: str,
        message: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Publish a message to a gRPC topic.
        
        In gRPC, publishing is implemented as a unary RPC call.
        
        Args:
            topic: Topic/service/method to publish to (format: "service.method")
            message: Message to publish (will be serialized)
            qos: Quality of Service parameters (ignored for gRPC)
        """
        # Parse service and method
        service_name, method_name = topic.split(".")
        
        # Ensure channel is connected
        if self.address not in self.channels:
            await self.connect()
        
        # Get or create stub for this service
        if service_name not in self.stubs:
            # Create dynamic stub for ECPS services
            try:
                # Import the main ECPS protobuf module
                from ecps_uv.proto import ecps_pb2_grpc
                
                # Map service names to actual stub classes
                stub_mapping = {
                    "MemoryStore": ecps_pb2_grpc.MemoryStoreStub,
                    # Add other services as needed
                }
                
                if service_name in stub_mapping:
                    stub_class = stub_mapping[service_name]
                    self.stubs[service_name] = stub_class(self.channels[self.address])
                else:
                    # Fallback: create a generic stub
                    logger.warning(f"No specific stub found for service {service_name}, using generic approach")
                    self.stubs[service_name] = self._create_generic_stub(service_name)
                    
            except ImportError as e:
                logger.error(f"Failed to import gRPC stubs: {e}")
                # Create a generic stub as fallback
                self.stubs[service_name] = self._create_generic_stub(service_name)
        
        # Get stub
        stub = self.stubs[service_name]
        
        # Get method
        method = getattr(stub, method_name)
        
        # Call method
        try:
            await method(message)
            logger.debug(f"Published message to {topic}")
        except grpc.aio.AioRpcError as e:
            logger.error(f"Failed to publish message to {topic}: {e}")
            raise
    
    async def subscribe(
        self,
        topic: str,
        handler: Callable,
        message_type: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Subscribe to a gRPC topic.
        
        In gRPC, subscribing is implemented as a server-side streaming RPC.
        
        Args:
            topic: Topic/service/method to subscribe to (format: "service.method")
            handler: Callback function to handle received messages
            message_type: Type of messages expected on this topic
            qos: Quality of Service parameters (ignored for gRPC)
        """
        # Parse service and method
        service_name, method_name = topic.split(".")
        
        # Ensure channel is connected
        if self.address not in self.channels:
            await self.connect()
        
        # Get or create stub for this service
        if service_name not in self.stubs:
            # Create dynamic stub for ECPS services
            try:
                # Import the main ECPS protobuf module
                from ecps_uv.proto import ecps_pb2_grpc
                
                # Map service names to actual stub classes
                stub_mapping = {
                    "MemoryStore": ecps_pb2_grpc.MemoryStoreStub,
                    # Add other services as needed
                }
                
                if service_name in stub_mapping:
                    stub_class = stub_mapping[service_name]
                    self.stubs[service_name] = stub_class(self.channels[self.address])
                else:
                    # Fallback: create a generic stub
                    logger.warning(f"No specific stub found for service {service_name}, using generic approach")
                    self.stubs[service_name] = self._create_generic_stub(service_name)
                    
            except ImportError as e:
                logger.error(f"Failed to import gRPC stubs: {e}")
                # Create a generic stub as fallback
                self.stubs[service_name] = self._create_generic_stub(service_name)
        
        # Get stub
        stub = self.stubs[service_name]
        
        # Get method
        method = getattr(stub, method_name)
        
        # Create an empty request message for subscription
        # This assumes the request message has a default constructor
        request = message_type()
        
        # Start streaming
        try:
            stream = method(request)
            
            # Create a task to handle incoming messages
            task = uv.Loop.current().create_task(
                self._handle_stream(stream, handler)
            )
            
            # Store handler
            self.handlers[topic] = handler
            
            logger.debug(f"Subscribed to {topic}")
        except grpc.aio.AioRpcError as e:
            logger.error(f"Failed to subscribe to {topic}: {e}")
            raise
    
    async def _handle_stream(self, stream, handler):
        """Handle incoming messages from a gRPC stream."""
        try:
            async for message in stream:
                await handler(message)
        except grpc.aio.AioRpcError as e:
            if e.code() == grpc.StatusCode.CANCELLED:
                # Stream was cancelled, which is normal when closing
                pass
            else:
                logger.error(f"Error in gRPC stream: {e}")
        except Exception as e:
            logger.error(f"Error handling message in gRPC stream: {e}")
    
    async def request(
        self,
        service: str,
        request: Any,
        timeout: float = 10.0,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Send a request to a gRPC service and await response.
        
        Args:
            service: Service name and method (format: "service.method")
            request: Request message (will be serialized)
            timeout: Timeout in seconds
            qos: Quality of Service parameters (ignored for gRPC)
            
        Returns:
            response: Response message (deserialized)
        """
        # Parse service and method
        service_name, method_name = service.split(".")
        
        # Ensure channel is connected
        if self.address not in self.channels:
            await self.connect()
        
        # Get or create stub for this service
        if service_name not in self.stubs:
            # Create dynamic stub for ECPS services
            try:
                # Import the main ECPS protobuf module
                from ecps_uv.proto import ecps_pb2_grpc
                
                # Map service names to actual stub classes
                stub_mapping = {
                    "MemoryStore": ecps_pb2_grpc.MemoryStoreStub,
                    # Add other services as needed
                }
                
                if service_name in stub_mapping:
                    stub_class = stub_mapping[service_name]
                    self.stubs[service_name] = stub_class(self.channels[self.address])
                else:
                    # Fallback: create a generic stub
                    logger.warning(f"No specific stub found for service {service_name}, using generic approach")
                    self.stubs[service_name] = self._create_generic_stub(service_name)
                    
            except ImportError as e:
                logger.error(f"Failed to import gRPC stubs: {e}")
                # Create a generic stub as fallback
                self.stubs[service_name] = self._create_generic_stub(service_name)
        
        # Get stub
        stub = self.stubs[service_name]
        
        # Get method
        method = getattr(stub, method_name)
        
        # Call method with timeout
        try:
            response = await asyncio.wait_for(method(request), timeout)
            return response
        except asyncio.TimeoutError:
            logger.error(f"Request to {service} timed out after {timeout}s")
            raise
        except grpc.aio.AioRpcError as e:
            logger.error(f"Failed to call {service}: {e}")
            raise
    
    async def register_service(
        self,
        service: str,
        handler: Callable,
        request_type: Any,
        response_type: Any,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Register a gRPC service handler.
        
        Args:
            service: Service name and method (format: "service.method")
            handler: Callback function to handle service requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos: Quality of Service parameters (ignored for gRPC)
        """
        if not self.is_server:
            logger.error("register_service() called on a client-mode gRPC transport")
            return
        
        # Parse service and method
        service_name, method_name = service.split(".")
        
        # Store handler
        if service_name not in self.service_handlers:
            self.service_handlers[service_name] = {}
        
        self.service_handlers[service_name][method_name] = handler
        
        # Create servicer if not already created
        if service_name not in self.servicers:
            # Create a dynamic servicer class
            servicer = self._create_servicer(service_name)
            self.servicers[service_name] = servicer
        
        logger.debug(f"Registered handler for {service}")
    
    def _create_servicer(self, service_name):
        """Create a dynamic servicer class for a gRPC service."""
        try:
            # Import the main ECPS protobuf module
            from ecps_uv.proto import ecps_pb2_grpc
            
            # Map service names to actual servicer classes
            servicer_mapping = {
                "MemoryStore": ecps_pb2_grpc.MemoryStoreServicer,
                # Add other services as needed
            }
            
            if service_name in servicer_mapping:
                servicer_class = servicer_mapping[service_name]
            else:
                # Create a generic servicer
                logger.warning(f"No specific servicer found for service {service_name}, using generic approach")
                return self._create_generic_servicer(service_name)
                
        except ImportError as e:
            logger.error(f"Failed to import gRPC servicers: {e}")
            return self._create_generic_servicer(service_name)
        
        # Create servicer instance
        handlers = self.service_handlers[service_name]
        
        # Create a dynamic servicer instance with all required methods
        servicer = servicer_class()
        
        # Add handler methods to servicer
        for method_name, handler in handlers.items():
            async def method_impl(request, context, handler=handler):
                try:
                    response = await handler(request)
                    return response
                except Exception as e:
                    logger.error(f"Error in gRPC handler: {e}")
                    await context.abort(grpc.StatusCode.INTERNAL, str(e))
            
            setattr(servicer, method_name, method_impl)
        
        return servicer
    
    def _create_generic_servicer(self, service_name):
        """Create a generic servicer for services without specific protobuf definitions."""
        class GenericServicer:
            def __init__(self, handlers):
                self.handlers = handlers
                self._service_name = service_name
            
            def __getattr__(self, method_name):
                if method_name in self.handlers:
                    handler = self.handlers[method_name]
                    
                    async def method_impl(request, context):
                        try:
                            response = await handler(request)
                            return response
                        except Exception as e:
                            logger.error(f"Error in generic gRPC handler: {e}")
                            await context.abort(grpc.StatusCode.INTERNAL, str(e))
                    
                    return method_impl
                else:
                    # Return a default handler
                    async def default_handler(request, context):
                        await context.abort(grpc.StatusCode.UNIMPLEMENTED, f"Method {method_name} not implemented")
                    
                    return default_handler
        
        handlers = self.service_handlers[service_name]
        return GenericServicer(handlers)
    
    def _create_generic_stub(self, service_name: str):
        """Create a generic stub for services without specific protobuf definitions."""
        class GenericStub:
            def __init__(self, channel):
                self.channel = channel
                self._service_name = service_name
            
            def __getattr__(self, method_name):
                # Create a generic method that can handle any RPC call
                async def generic_method(request, timeout=None):
                    # For generic stubs, we'll use the unary-unary pattern
                    method_path = f"/{self._service_name}/{method_name}"
                    
                    # Serialize request
                    if hasattr(request, 'SerializeToString'):
                        serialized_request = request.SerializeToString()
                    else:
                        # Fallback serialization
                        import json
                        serialized_request = json.dumps(request).encode()
                    
                    # Make the call
                    response_bytes = await self.channel.unary_unary(
                        method_path,
                        request_serializer=lambda x: x,
                        response_deserializer=lambda x: x,
                    )(serialized_request, timeout=timeout)
                    
                    # For now, return raw bytes - in a real implementation,
                    # you'd deserialize based on the expected response type
                    return response_bytes
                
                return generic_method
        
        return GenericStub(self.channels[self.address])
    
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
            service: Service name and method (format: "service.method")
            request: Request message (will be serialized)
            handler: Callback function to handle streamed responses
            timeout: Timeout in seconds
            qos: Quality of Service parameters (ignored for gRPC)
        """
        # Parse service and method
        service_name, method_name = service.split(".")
        
        # Ensure channel is connected
        if self.address not in self.channels:
            await self.connect()
        
        # Get or create stub for this service
        if service_name not in self.stubs:
            # Create dynamic stub for ECPS services
            try:
                # Import the main ECPS protobuf module
                from ecps_uv.proto import ecps_pb2_grpc
                
                # Map service names to actual stub classes
                stub_mapping = {
                    "MemoryStore": ecps_pb2_grpc.MemoryStoreStub,
                    # Add other services as needed
                }
                
                if service_name in stub_mapping:
                    stub_class = stub_mapping[service_name]
                    self.stubs[service_name] = stub_class(self.channels[self.address])
                else:
                    # Fallback: create a generic stub
                    logger.warning(f"No specific stub found for service {service_name}, using generic approach")
                    self.stubs[service_name] = self._create_generic_stub(service_name)
                    
            except ImportError as e:
                logger.error(f"Failed to import gRPC stubs: {e}")
                # Create a generic stub as fallback
                self.stubs[service_name] = self._create_generic_stub(service_name)
        
        # Get stub
        stub = self.stubs[service_name]
        
        # Get method
        method = getattr(stub, method_name)
        
        # Call streaming method
        try:
            # Start stream
            stream = method(request)
            
            # Define a task to handle the stream with timeout
            async def handle_stream_with_timeout():
                try:
                    async for message in stream:
                        await handler(message)
                except grpc.aio.AioRpcError as e:
                    if e.code() == grpc.StatusCode.CANCELLED:
                        # Stream was cancelled, which is normal when closing
                        pass
                    else:
                        logger.error(f"Error in gRPC stream: {e}")
                        raise
            
            # Wait for stream to complete with timeout
            await asyncio.wait_for(handle_stream_with_timeout(), timeout)
        except asyncio.TimeoutError:
            logger.error(f"Stream request to {service} timed out after {timeout}s")
            # Cancel the stream
            stream.cancel()
            raise
        except grpc.aio.AioRpcError as e:
            logger.error(f"Failed to stream from {service}: {e}")
            raise
    
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
            service: Service name and method (format: "service.method")
            handler: Callback function to handle streaming requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos: Quality of Service parameters (ignored for gRPC)
        """
        if not self.is_server:
            logger.error("register_stream_service() called on a client-mode gRPC transport")
            return
        
        # Parse service and method
        service_name, method_name = service.split(".")
        
        # Store handler
        if service_name not in self.service_handlers:
            self.service_handlers[service_name] = {}
        
        self.service_handlers[service_name][method_name] = handler
        
        # Create servicer if not already created
        if service_name not in self.servicers:
            # Create a dynamic servicer class
            servicer = self._create_stream_servicer(service_name)
            self.servicers[service_name] = servicer
        
        logger.debug(f"Registered streaming handler for {service}")
    
    def _create_stream_servicer(self, service_name):
        """Create a dynamic servicer class for a streaming gRPC service."""
        try:
            # Import the main ECPS protobuf module
            from ecps_uv.proto import ecps_pb2_grpc
            
            # Map service names to actual servicer classes
            servicer_mapping = {
                "MemoryStore": ecps_pb2_grpc.MemoryStoreServicer,
                # Add other services as needed
            }
            
            if service_name in servicer_mapping:
                servicer_class = servicer_mapping[service_name]
            else:
                # Create a generic servicer
                logger.warning(f"No specific servicer found for service {service_name}, using generic approach")
                return self._create_generic_stream_servicer(service_name)
                
        except ImportError as e:
            logger.error(f"Failed to import gRPC servicers: {e}")
            return self._create_generic_stream_servicer(service_name)
        
        # Create servicer instance
        handlers = self.service_handlers[service_name]
        
        # Create a dynamic servicer instance with all required methods
        servicer = servicer_class()
        
        # Add handler methods to servicer
        for method_name, handler in handlers.items():
            async def method_impl(request, context, handler=handler):
                try:
                    # Handler should generate responses and yield them
                    async for response in handler(request):
                        yield response
                except Exception as e:
                    logger.error(f"Error in gRPC streaming handler: {e}")
                    await context.abort(grpc.StatusCode.INTERNAL, str(e))
            
            setattr(servicer, method_name, method_impl)
        
        return servicer
    
    def _create_generic_stream_servicer(self, service_name):
        """Create a generic streaming servicer for services without specific protobuf definitions."""
        class GenericStreamServicer:
            def __init__(self, handlers):
                self.handlers = handlers
                self._service_name = service_name
            
            def __getattr__(self, method_name):
                if method_name in self.handlers:
                    handler = self.handlers[method_name]
                    
                    async def method_impl(request, context):
                        try:
                            # Handler should generate responses and yield them
                            async for response in handler(request):
                                yield response
                        except Exception as e:
                            logger.error(f"Error in generic gRPC streaming handler: {e}")
                            await context.abort(grpc.StatusCode.INTERNAL, str(e))
                    
                    return method_impl
                else:
                    # Return a default handler
                    async def default_handler(request, context):
                        await context.abort(grpc.StatusCode.UNIMPLEMENTED, f"Method {method_name} not implemented")
                    
                    return default_handler
        
        handlers = self.service_handlers[service_name]
        return GenericStreamServicer(handlers)
        
        logger.debug(f"Registered streaming handler for {service}")
    
    def _create_stream_servicer(self, service_name):
        """Create a dynamic servicer class for a streaming gRPC service."""
        # Dynamic import of generated service servicer
        module_name = f"ecps_uv.proto.{service_name}_pb2_grpc"
        try:
            module = __import__(module_name, fromlist=[f"add_{service_name}Servicer_to_server"])
            add_servicer_func = getattr(module, f"add_{service_name}Servicer_to_server")
            servicer_class = getattr(module, f"{service_name}Servicer")
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to import gRPC servicer for service {service_name}: {e}")
            raise
        
        # Create servicer instance
        handlers = self.service_handlers[service_name]
        
        # Create a dynamic servicer instance with all required methods
        servicer = servicer_class()
        
        # Add handler methods to servicer
        for method_name, handler in handlers.items():
            async def method_impl(request, context, handler=handler):
                try:
                    # Handler should generate responses and yield them
                    async for response in handler(request):
                        yield response
                except Exception as e:
                    logger.error(f"Error in gRPC streaming handler: {e}")
                    await context.abort(grpc.StatusCode.INTERNAL, str(e))
            
            setattr(servicer, method_name, method_impl)
        
        return servicer