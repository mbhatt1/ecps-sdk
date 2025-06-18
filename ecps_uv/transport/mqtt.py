"""
MQTT 5 Transport implementation for ECPS-UV SDK.

This module provides a Transport implementation using MQTT 5,
suitable for constrained IoT devices and scenarios requiring
lightweight, publish-subscribe communication.
"""

import asyncio
import json
import logging
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

import uv
import paho.mqtt.client as mqtt
import paho.mqtt.properties as mqtt_properties

from ecps_uv.transport.base import Transport

logger = logging.getLogger("ecps_uv.transport.mqtt")


class MQTTTransport(Transport):
    """
    Transport implementation using MQTT 5.
    
    This transport is suitable for constrained IoT devices and scenarios
    requiring lightweight, publish-subscribe communication.
    """
    
    def __init__(
        self,
        serializer: Any,
        config: Optional[Dict[str, Any]] = None,
        loop: Optional[Any] = None,
        is_server: bool = False,
    ):
        """
        Initialize the MQTT transport.
        
        Args:
            serializer: Serializer to use for message encoding/decoding
            config: MQTT-specific configuration
            loop: UV event loop to use
            is_server: Whether this transport is for a server (True) or client (False)
        """
        super().__init__(serializer, config, loop, is_server)
        
        # MQTT-specific configuration
        self.broker_host = config.get("broker_host", "localhost")
        self.broker_port = config.get("broker_port", 1883)
        self.client_id = config.get("client_id", f"ecps-{'server' if is_server else 'client'}-{uuid.uuid4()}")
        self.use_tls = config.get("use_tls", False)
        self.ca_cert = config.get("ca_cert")
        self.client_cert = config.get("client_cert")
        self.client_key = config.get("client_key")
        self.username = config.get("username")
        self.password = config.get("password")
        self.keep_alive = config.get("keep_alive", 60)
        
        # MQTT objects
        self.client = None
        self.is_connected = False
        self.subscriptions = {}  # topic -> (handler, message_type)
        
        # Map of correlation IDs to futures for request-response
        self.response_futures = {}  # correlation_id -> future
        
        # Service handlers
        self.service_handlers = {}  # service_name -> handler
        
        # MQTT QoS mapping
        self.default_qos = 1  # Default to QoS 1 (at least once)
    
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        """Callback for when the client connects to the broker."""
        if rc == 0:
            logger.info(f"Connected to MQTT broker at {self.broker_host}:{self.broker_port}")
            self.is_connected = True
            
            # Resubscribe to all topics
            for topic, (handler, message_type, qos) in self.subscriptions.items():
                client.subscribe(topic, qos=qos)
                logger.debug(f"Resubscribed to topic {topic} with QoS {qos}")
        else:
            logger.error(f"Failed to connect to MQTT broker: {rc}")
    
    def _on_disconnect(self, client, userdata, rc, properties=None):
        """Callback for when the client disconnects from the broker."""
        logger.info(f"Disconnected from MQTT broker: {rc}")
        self.is_connected = False
    
    def _on_message(self, client, userdata, msg):
        """Callback for when a message is received from the broker."""
        logger.debug(f"Received message on topic {msg.topic}")
        
        # Check if this is a response to a request
        if msg.topic.startswith("response/"):
            correlation_id = msg.topic.split("/")[-1]
            if correlation_id in self.response_futures:
                future = self.response_futures[correlation_id]
                if not future.done():
                    try:
                        # Deserialize message
                        message_dict = json.loads(msg.payload)
                        message_type = message_dict.get("__type__")
                        message_data = message_dict.get("data", {})
                        
                        # Create response object
                        response = self._create_message_from_dict(message_type, message_data)
                        future.set_result(response)
                    except Exception as e:
                        future.set_exception(e)
                return
        
        # Regular message handling
        if msg.topic in self.subscriptions:
            handler, message_type, _ = self.subscriptions[msg.topic]
            try:
                # Deserialize message
                message_dict = json.loads(msg.payload)
                message_data = message_dict.get("data", {})
                
                # Create message object
                message = self._create_message_from_dict(message_type.__name__, message_data)
                
                # Call handler asynchronously
                asyncio.create_task(handler(message))
            except Exception as e:
                logger.error(f"Error handling message on topic {msg.topic}: {e}")
    
    def _create_message_from_dict(self, message_type_name, message_data):
        """Create a message object from a dictionary."""
        # Dynamic import of message type
        try:
            module_name = f"ecps_uv.proto.ecps_pb2"
            module = __import__(module_name, fromlist=[message_type_name])
            message_class = getattr(module, message_type_name)
            
            # Create message
            message = message_class()
            
            # Populate fields
            for field, value in message_data.items():
                if hasattr(message, field):
                    setattr(message, field, value)
            
            return message
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to create message of type {message_type_name}: {e}")
            raise
    
    def _message_to_dict(self, message):
        """Convert a message object to a dictionary."""
        # Get message type name
        message_type = type(message).__name__
        
        # Convert to dictionary
        message_dict = {
            "__type__": message_type,
            "data": {},
        }
        
        # Get all fields
        for field in message.DESCRIPTOR.fields:
            field_name = field.name
            field_value = getattr(message, field_name)
            message_dict["data"][field_name] = field_value
        
        return message_dict
    
    async def connect(self):
        """Establish MQTT connection."""
        # Create MQTT client if not already created
        if not self.client:
            # Create MQTT client with protocol v5
            self.client = mqtt.Client(client_id=self.client_id, protocol=mqtt.MQTTv5)
            
            # Set TLS if needed
            if self.use_tls:
                self.client.tls_set(
                    ca_certs=self.ca_cert,
                    certfile=self.client_cert,
                    keyfile=self.client_key,
                )
            
            # Set username and password if provided
            if self.username and self.password:
                self.client.username_pw_set(self.username, self.password)
            
            # Set callbacks
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            self.client.on_message = self._on_message
            
            # Start the MQTT client loop in a background thread
            self.client.connect_async(self.broker_host, self.broker_port, self.keep_alive)
            self.client.loop_start()
            
            # Wait for connection to be established
            while not self.is_connected:
                await asyncio.sleep(0.1)
            
            logger.info(f"Connected to MQTT broker at {self.broker_host}:{self.broker_port}")
    
    async def close(self):
        """Close the MQTT transport and release resources."""
        if self.client:
            # Disconnect from broker
            self.client.disconnect()
            
            # Stop the client loop
            self.client.loop_stop()
            
            # Clean up
            self.client = None
            self.is_connected = False
            
            logger.info("MQTT transport closed")
    
    async def start(self):
        """Start the MQTT transport server."""
        # For MQTT, start() is the same as connect()
        await self.connect()
    
    async def publish(
        self,
        topic: str,
        message: Any,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Publish a message to an MQTT topic.
        
        Args:
            topic: Topic to publish to
            message: Message to publish (will be serialized)
            qos_params: Quality of Service parameters
        """
        # Ensure client is connected
        if not self.is_connected:
            await self.connect()
        
        # Get QoS level
        qos = self.default_qos
        if qos_params and "qos" in qos_params:
            qos = qos_params["qos"]
        
        # Convert message to dictionary
        message_dict = self._message_to_dict(message)
        
        # Serialize to JSON
        payload = json.dumps(message_dict)
        
        # Create MQTT 5 properties if needed
        properties = None
        if qos_params:
            properties = mqtt_properties.Properties(mqtt_properties.PacketTypes.PUBLISH)
            
            # Add message expiry interval
            if "expiry_interval" in qos_params:
                properties.MessageExpiryInterval = qos_params["expiry_interval"]
            
            # Add content type
            if "content_type" in qos_params:
                properties.ContentType = qos_params["content_type"]
            else:
                properties.ContentType = "application/json"
            
            # Add user properties
            if "user_properties" in qos_params:
                properties.UserProperty = qos_params["user_properties"]
        
        # Publish with retry logic
        max_retries = qos_params.get("retry_count", 3) if qos_params else 3
        retry_delay = 0.1
        
        for attempt in range(max_retries + 1):
            try:
                result = self.client.publish(topic, payload, qos=qos, properties=properties)
                
                # Wait for publish to complete for QoS > 0
                if qos > 0:
                    result.wait_for_publish(timeout=5.0)
                
                # Check if publish was successful
                if result.rc == mqtt.MQTT_ERR_SUCCESS:
                    logger.debug(f"Published message to topic {topic} with QoS {qos}")
                    return
                else:
                    raise Exception(f"Publish failed with code: {result.rc}")
                    
            except Exception as e:
                if attempt < max_retries:
                    logger.warning(f"Publish attempt {attempt + 1} failed: {e}, retrying in {retry_delay}s")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    logger.error(f"Failed to publish message to topic {topic} after {max_retries + 1} attempts: {e}")
                    raise
    
    async def subscribe(
        self,
        topic: str,
        handler: Callable,
        message_type: Any,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Subscribe to an MQTT topic.
        
        Args:
            topic: Topic to subscribe to
            handler: Callback function to handle received messages
            message_type: Type of messages expected on this topic
            qos_params: Quality of Service parameters
        """
        # Ensure client is connected
        if not self.is_connected:
            await self.connect()
        
        # Get QoS level
        qos = self.default_qos
        if qos_params and "qos" in qos_params:
            qos = qos_params["qos"]
        
        # Subscribe to topic
        result = self.client.subscribe(topic, qos=qos)
        
        # Check if subscribe was successful
        if result[0] != mqtt.MQTT_ERR_SUCCESS:
            logger.error(f"Failed to subscribe to topic {topic}: {result[0]}")
            raise Exception(f"Failed to subscribe to topic: {result[0]}")
        
        # Store subscription
        self.subscriptions[topic] = (handler, message_type, qos)
        
        logger.debug(f"Subscribed to topic {topic} with QoS {qos}")
    
    async def request(
        self,
        service: str,
        request: Any,
        timeout: float = 10.0,
        qos_params: Optional[Dict[str, Any]] = None,
    ):
        """
        Send a request to a service and await response.
        
        For MQTT, we implement the request-reply pattern using two topics:
        - service/request for requests
        - response/{correlation_id} for replies
        
        Args:
            service: Service name
            request: Request message (will be serialized)
            timeout: Timeout in seconds
            qos_params: Quality of Service parameters
            
        Returns:
            response: Response message (deserialized)
        """
        # Ensure client is connected
        if not self.is_connected:
            await self.connect()
        
        # Generate a unique correlation ID for this request
        correlation_id = str(uuid.uuid4())
        
        # Create a future to hold the response
        response_future = asyncio.Future()
        self.response_futures[correlation_id] = response_future
        
        # Subscribe to response topic
        response_topic = f"response/{correlation_id}"
        await self.subscribe(
            response_topic,
            lambda msg: None,  # Response is handled by _on_message
            type(request),  # Assume response is of same type
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
            # Clean up
            if correlation_id in self.response_futures:
                del self.response_futures[correlation_id]
            
            # Unsubscribe from response topic
            if response_topic in self.subscriptions:
                self.client.unsubscribe(response_topic)
                del self.subscriptions[response_topic]
    
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
        
        For MQTT, we implement the request-reply pattern using two topics:
        - service/request for requests
        - response/{correlation_id} for replies
        
        Args:
            service: Service name
            handler: Callback function to handle service requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos_params: Quality of Service parameters
        """
        # Ensure client is connected
        if not self.is_connected:
            await self.connect()
        
        # Get QoS level
        qos = self.default_qos
        if qos_params and "qos" in qos_params:
            qos = qos_params["qos"]
        
        # Request topic
        request_topic = f"{service}/request"
        
        # Define wrapper handler that publishes response to response topic
        async def request_handler(request):
            # Get correlation ID from request
            correlation_id = request.id if hasattr(request, "id") else str(uuid.uuid4())
            
            # Call actual handler
            response = await handler(request)
            
            # Publish response to response topic
            response_topic = f"response/{correlation_id}"
            await self.publish(response_topic, response, qos_params)
        
        # Subscribe to request topic
        await self.subscribe(
            request_topic,
            request_handler,
            request_type,
            qos_params,
        )
        
        # Store service handler
        self.service_handlers[service] = handler
        
        logger.debug(f"Registered service handler for {service}")
    
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
        
        For MQTT, we implement streaming using a topic with correlation ID:
        - service/stream/{correlation_id} for streamed responses
        
        Args:
            service: Service name
            request: Request message (will be serialized)
            handler: Callback function to handle streamed responses
            timeout: Timeout in seconds
            qos_params: Quality of Service parameters
        """
        # Ensure client is connected
        if not self.is_connected:
            await self.connect()
        
        # Generate a unique correlation ID for this request
        correlation_id = str(uuid.uuid4())
        
        # Create a future to indicate completion
        done_future = asyncio.Future()
        
        # Subscribe to stream topic
        stream_topic = f"{service}/stream/{correlation_id}"
        
        # Define handler for streamed responses
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
            type(request),  # Assume response is of same type
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
            # Unsubscribe from stream topic
            if stream_topic in self.subscriptions:
                self.client.unsubscribe(stream_topic)
                del self.subscriptions[stream_topic]
    
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
        
        For MQTT, we implement streaming using a topic with correlation ID:
        - service/stream/{correlation_id} for streamed responses
        
        Args:
            service: Service name
            handler: Callback function to handle streaming requests
            request_type: Type of request messages
            response_type: Type of response messages
            qos_params: Quality of Service parameters
        """
        # Ensure client is connected
        if not self.is_connected:
            await self.connect()
        
        # Request topic
        request_topic = f"{service}/request"
        
        # Define wrapper handler that publishes streamed responses
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
        
        # Store service handler
        self.service_handlers[service] = handler
        
        logger.debug(f"Registered streaming service handler for {service}")