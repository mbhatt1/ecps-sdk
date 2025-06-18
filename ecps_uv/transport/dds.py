"""
DDS/RTPS Transport implementation for ECPS-UV SDK.

This module provides a Transport implementation using DDS/RTPS via 
Cyclone DDS for real-time, local control, and high-frequency data streaming
within a LAN environment.
"""

import asyncio
import logging
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

import uv
import cyclonedds.domain as domain
import cyclonedds.pub as pub
import cyclonedds.sub as sub
import cyclonedds.topic as topic
import cyclonedds.idl as idl
import cyclonedds.qos as qos

from ecps_uv.transport.base import Transport

logger = logging.getLogger("ecps_uv.transport.dds")


class DDSTransport(Transport):
    """
    Transport implementation using DDS/RTPS via Cyclone DDS.
    
    This transport is suitable for real-time, local control, and
    high-frequency data streaming within a LAN environment.
    """
    
    def __init__(
        self,
        serializer: Any,
        config: Optional[Dict[str, Any]] = None,
        loop: Optional[Any] = None,
        is_server: bool = False,
    ):
        """
        Initialize the DDS transport.
        
        Args:
            serializer: Serializer to use for message encoding/decoding
            config: DDS-specific configuration
            loop: UV event loop to use
            is_server: Whether this transport is for a server (True) or client (False)
        """
        super().__init__(serializer, config, loop, is_server)
        
        # DDS-specific configuration
        self.domain_id = config.get("domain_id", 0)
        self.participant = None
        self.publishers = {}  # topic_name -> publisher
        self.subscribers = {}  # topic_name -> subscriber
        self.readers = {}  # topic_name -> reader
        self.writers = {}  # topic_name -> writer
        self.topics = {}  # topic_name -> topic
        
        # QoS settings
        self.default_qos = self._create_default_qos()
    
    def _create_default_qos(self) -> qos.Policy:
        """Create default QoS policy for DDS topics."""
        # Default QoS settings based on ECPS specification
        policy = qos.Policy(
            # RELIABLE QoS for guaranteed delivery
            reliability=qos.Reliability.RELIABLE,
            # TRANSIENT_LOCAL for late-joining readers
            durability=qos.Durability.TRANSIENT_LOCAL,
            # KEEP_LAST(4) for EAP and other messages
            history=qos.History(kind=qos.HistoryKind.KEEP_LAST, depth=4),
        )
        return policy
    
    def _apply_qos_settings(self, qos_params: Optional[Dict[str, Any]] = None) -> qos.Policy:
        """
        Apply QoS settings to create a DDS QoS policy.
        
        Args:
            qos_params: QoS parameters to apply
            
        Returns:
            policy: DDS QoS policy
        """
        if not qos_params:
            return self.default_qos
        
        # Start with default QoS
        policy = self.default_qos
        
        # Apply specific QoS parameters
        if "reliability" in qos_params:
            if qos_params["reliability"].upper() == "RELIABLE":
                policy.reliability = qos.Reliability.RELIABLE
            elif qos_params["reliability"].upper() == "BEST_EFFORT":
                policy.reliability = qos.Reliability.BEST_EFFORT
        
        if "durability" in qos_params:
            if qos_params["durability"].upper() == "VOLATILE":
                policy.durability = qos.Durability.VOLATILE
            elif qos_params["durability"].upper() == "TRANSIENT_LOCAL":
                policy.durability = qos.Durability.TRANSIENT_LOCAL
            elif qos_params["durability"].upper() == "TRANSIENT":
                policy.durability = qos.Durability.TRANSIENT
            elif qos_params["durability"].upper() == "PERSISTENT":
                policy.durability = qos.Durability.PERSISTENT
        
        if "history" in qos_params:
            history_kind = qos_params["history"].get("kind", "KEEP_LAST")
            history_depth = qos_params["history"].get("depth", 4)
            
            if history_kind.upper() == "KEEP_LAST":
                policy.history = qos.History(
                    kind=qos.HistoryKind.KEEP_LAST,
                    depth=history_depth,
                )
            elif history_kind.upper() == "KEEP_ALL":
                policy.history = qos.History(kind=qos.HistoryKind.KEEP_ALL)
        
        return policy
    
    async def connect(self):
        """Establish DDS connection."""
        # Create DDS participant
        self.participant = domain.DomainParticipant(self.domain_id)
        logger.info(f"DDS participant created for domain {self.domain_id}")
    
    async def close(self):
        """Close the DDS transport and release resources."""
        # Clean up all resources
        for reader in self.readers.values():
            reader.close()
        
        for writer in self.writers.values():
            writer.close()
        
        for topic_obj in self.topics.values():
            topic_obj.close()
        
        if self.participant:
            self.participant.close()
            self.participant = None
        
        logger.info("DDS transport closed")
    
    async def start(self):
        """Start the DDS transport server."""
        if not self.is_server:
            logger.warning("start() called on a client-mode DDS transport")
            return
        
        # For DDS, start() is the same as connect()
        await self.connect()
    
    async def publish(
        self,
        topic_name: str,
        message: Any,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Publish a message to a DDS topic.
        
        Args:
            topic_name: Topic name to publish to
            message: Message to publish (will be serialized)
            qos_params: Quality of Service parameters
        """
        # Ensure participant is initialized
        if not self.participant:
            await self.connect()
        
        # Get or create writer for this topic
        if topic_name not in self.writers:
            # Get message type from serializer
            message_type = type(message)
            
            # Create or get topic
            if topic_name not in self.topics:
                qos_policy = self._apply_qos_settings(qos_params)
                topic_obj = topic.Topic(
                    self.participant,
                    topic_name,
                    message_type,
                    qos=qos_policy,
                )
                self.topics[topic_name] = topic_obj
            else:
                topic_obj = self.topics[topic_name]
            
            # Create writer
            writer = pub.DataWriter(self.participant, topic_obj)
            self.writers[topic_name] = writer
            logger.debug(f"Created DDS writer for topic {topic_name}")
        
        # Get writer and publish message
        writer = self.writers[topic_name]
        writer.write(message)
        logger.debug(f"Published message to topic {topic_name}")
    
    async def subscribe(
        self,
        topic_name: str,
        handler: Callable,
        message_type: Any,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Subscribe to a DDS topic.
        
        Args:
            topic_name: Topic name to subscribe to
            handler: Callback function to handle received messages
            message_type: Type of messages expected on this topic
            qos_params: Quality of Service parameters
        """
        # Ensure participant is initialized
        if not self.participant:
            await self.connect()
        
        # Create or get topic
        if topic_name not in self.topics:
            qos_policy = self._apply_qos_settings(qos_params)
            topic_obj = topic.Topic(
                self.participant,
                topic_name,
                message_type,
                qos=qos_policy,
            )
            self.topics[topic_name] = topic_obj
        else:
            topic_obj = self.topics[topic_name]
        
        # Create reader
        reader = sub.DataReader(self.participant, topic_obj)
        self.readers[topic_name] = reader
        logger.debug(f"Created DDS reader for topic {topic_name}")
        
        # Store handler
        self.handlers[topic_name] = handler
        
        # Create a task to monitor this reader
        task = uv.Loop.current().create_task(
            self._reader_loop(reader, topic_name, handler)
        )
    
    async def _reader_loop(self, reader, topic_name, handler):
        """Background task to read messages from a DDS topic."""
        while True:
            # Wait for samples
            samples = reader.take(10)
            
            # Process each sample
            for sample in samples:
                try:
                    # Call handler with message
                    await handler(sample)
                except Exception as e:
                    logger.error(f"Error handling message on topic {topic_name}: {e}")
            
            # Small sleep to avoid busy loop
            await asyncio.sleep(0.01)
    
    async def request(
        self,
        service: str,
        request: Any,
        timeout: float = 10.0,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Send a request to a service and await response.
        
        For DDS, we implement the request-reply pattern using two topics:
        - service/request for requests
        - service/reply for replies
        
        Args:
            service: Service name
            request: Request message (will be serialized)
            timeout: Timeout in seconds
            qos_params: Quality of Service parameters
            
        Returns:
            response: Response message (deserialized)
        """
        # Generate a unique correlation ID for this request
        correlation_id = str(uuid.uuid4())
        
        # Create a future to hold the response
        response_future = self.loop.create_future()
        
        # Subscribe to reply topic with correlation ID
        reply_topic = f"{service}/reply/{correlation_id}"
        
        # Handler for replies
        async def reply_handler(message):
            response_future.set_result(message)
        
        # Subscribe to reply topic
        await self.subscribe(
            reply_topic,
            reply_handler,
            type(request),  # Assume same type for request and response
            qos_params,
        )
        
        # Add correlation ID to request (assuming it has an 'id' field)
        if hasattr(request, "id"):
            request.id = correlation_id
        
        # Publish request
        request_topic = f"{service}/request"
        await self.publish(request_topic, request, qos_params)
        
        try:
            # Wait for response with timeout
            response = await asyncio.wait_for(response_future, timeout)
            return response
        except asyncio.TimeoutError:
            logger.error(f"Request to service {service} timed out after {timeout}s")
            raise
        finally:
            # Clean up reader for reply topic
            if reply_topic in self.readers:
                reader = self.readers[reply_topic]
                reader.close()
                del self.readers[reply_topic]
    
    async def register_service(
        self,
        service: str,
        handler: Callable,
        request_type: Any,
        response_type: Any,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Register a service handler.
        
        For DDS, we implement the request-reply pattern using two topics:
        - service/request for requests
        - service/reply for replies
        
        Args:
            service: Service name
            handler: Callback function to handle service requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos_params: Quality of Service parameters
        """
        # Subscribe to request topic
        request_topic = f"{service}/request"
        
        # Wrapper handler that publishes response to reply topic
        async def request_handler(request):
            # Get correlation ID from request
            correlation_id = request.id if hasattr(request, "id") else str(uuid.uuid4())
            
            # Call actual handler
            response = await handler(request)
            
            # Publish response to reply topic with correlation ID
            reply_topic = f"{service}/reply/{correlation_id}"
            await self.publish(reply_topic, response, qos_params)
        
        # Subscribe to request topic
        await self.subscribe(
            request_topic,
            request_handler,
            request_type,
            qos_params,
        )
    
    async def stream_request(
        self,
        service: str,
        request: Any,
        handler: Callable,
        timeout: float = 60.0,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Send a request to a service and handle streamed responses.
        
        For DDS, we implement streaming using a topic with correlation ID:
        - service/stream/{correlation_id} for streamed responses
        
        Args:
            service: Service name
            request: Request message (will be serialized)
            handler: Callback function to handle streamed responses
            timeout: Timeout in seconds
            qos_params: Quality of Service parameters
        """
        # Generate a unique correlation ID for this request
        correlation_id = str(uuid.uuid4())
        
        # Create a future to indicate completion
        done_future = self.loop.create_future()
        
        # Subscribe to stream topic with correlation ID
        stream_topic = f"{service}/stream/{correlation_id}"
        
        # Handler for streamed responses
        async def stream_handler(message):
            # Check if this is the final message
            is_final = False
            if hasattr(message, "is_final"):
                is_final = message.is_final
            
            # Call user handler
            await handler(message)
            
            # If final message, complete the future
            if is_final:
                done_future.set_result(True)
        
        # Subscribe to stream topic
        await self.subscribe(
            stream_topic,
            stream_handler,
            type(request),  # Assume response is of same type or has been configured
            qos_params,
        )
        
        # Add correlation ID to request (assuming it has an 'id' field)
        if hasattr(request, "id"):
            request.id = correlation_id
        
        # Publish request
        request_topic = f"{service}/request"
        await self.publish(request_topic, request, qos_params)
        
        try:
            # Wait for completion with timeout
            await asyncio.wait_for(done_future, timeout)
        except asyncio.TimeoutError:
            logger.error(f"Stream request to service {service} timed out after {timeout}s")
            raise
        finally:
            # Clean up reader for stream topic
            if stream_topic in self.readers:
                reader = self.readers[stream_topic]
                reader.close()
                del self.readers[stream_topic]
    
    async def register_stream_service(
        self,
        service: str,
        handler: Callable,
        request_type: Any,
        response_type: Any,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Register a streaming service handler.
        
        For DDS, we implement streaming using a topic with correlation ID:
        - service/stream/{correlation_id} for streamed responses
        
        Args:
            service: Service name
            handler: Callback function to handle streaming requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos_params: Quality of Service parameters
        """
        # Subscribe to request topic
        request_topic = f"{service}/request"
        
        # Wrapper handler that publishes streamed responses
        async def request_handler(request):
            # Get correlation ID from request
            correlation_id = request.id if hasattr(request, "id") else str(uuid.uuid4())
            
            # Stream topic for this request
            stream_topic = f"{service}/stream/{correlation_id}"
            
            # Define publisher function to pass to handler
            async def publish_response(response, is_final=False):
                # Add is_final flag if the response type supports it
                if hasattr(response, "is_final"):
                    response.is_final = is_final
                
                # Publish response to stream topic
                await self.publish(stream_topic, response, qos_params)
            
            # Call actual handler with publisher function
            await handler(request, publish_response)
        
        # Subscribe to request topic
        await self.subscribe(
            request_topic,
            request_handler,
            request_type,
            qos_params,
        )