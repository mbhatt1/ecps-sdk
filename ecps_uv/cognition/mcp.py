"""
Model Context Protocol (MCP) handler for ECPS.

This module provides handling for MCP messages, which deliver natural-language
prompts and optional tool schemas to AI agents.
"""

import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

from opentelemetry import trace

# Import MCP message type
try:
    from ecps_uv.proto import ecps_pb2
except ImportError:
    # Dynamically generated protobuf modules might not be available at import time
    ecps_pb2 = None

logger = logging.getLogger("ecps_uv.cognition.mcp")

# Maximum prompt size in bytes (16 KiB)
MAX_PROMPT_SIZE = 16 * 1024


class MCPHandler:
    """
    Handler for Model Context Protocol (MCP) messages.
    
    This handler provides functionality for creating, sending, receiving,
    and processing MCP messages, which deliver prompts to AI agents.
    """
    
    def __init__(
        self,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
    ):
        """
        Initialize the MCP handler.
        
        Args:
            transport: Transport layer to use for sending/receiving messages
            serializer: Serializer to use for message encoding/decoding
            telemetry: Telemetry provider for observability (optional)
        """
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
    
    def _get_mcp_message_class(self):
        """Get the MCP message class from ecps_pb2."""
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        if hasattr(ecps_pb2, "MCP"):
            return ecps_pb2.MCP
        
        raise AttributeError("MCP message type not found in ecps_pb2")
    
    def create_mcp_message(
        self,
        prompt: str,
        message_id: Optional[str] = None,
        tool_json: Optional[bytes] = None,
        meta: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        Create an MCP message.
        
        Args:
            prompt: The prompt text (≤16 KiB UTF-8)
            message_id: Unique ID for the message (optional, generated if not provided)
            tool_json: Optional JSON blob representing tool schema
            meta: Optional metadata key-value pairs
            
        Returns:
            mcp_message: MCP message
        """
        # Check prompt size
        prompt_bytes = prompt.encode("utf-8")
        if len(prompt_bytes) > MAX_PROMPT_SIZE:
            logger.warning(
                f"Prompt size ({len(prompt_bytes)} bytes) exceeds max size "
                f"({MAX_PROMPT_SIZE} bytes), truncating"
            )
            # Truncate to fit within limit (at UTF-8 character boundary)
            prompt = prompt_bytes[:MAX_PROMPT_SIZE].decode("utf-8", errors="ignore")
        
        # Generate message ID if not provided
        if message_id is None:
            message_id = str(uuid.uuid4())
        
        # Create MCP message
        MCP = self._get_mcp_message_class()
        mcp_message = MCP()
        
        # Set fields
        mcp_message.spec = "mcp/1.0"
        mcp_message.id = message_id
        mcp_message.prompt = prompt
        
        if tool_json:
            mcp_message.tool_json = tool_json
        
        if meta:
            for key, value in meta.items():
                mcp_message.meta[key] = value
        
        # Record metrics if telemetry is available
        if self.telemetry:
            self.telemetry.record_mcp_prompt_size(
                len(prompt),
                attributes={
                    "id": message_id,
                    "has_tool": bool(tool_json),
                    "meta_count": len(meta) if meta else 0,
                },
            )
        
        return mcp_message
    
    async def send(
        self,
        prompt: str,
        message_id: Optional[str] = None,
        tool_json: Optional[bytes] = None,
        meta: Optional[Dict[str, str]] = None,
        topic: str = "mcp",
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send an MCP message.
        
        Args:
            prompt: The prompt text (≤16 KiB UTF-8)
            message_id: Unique ID for the message (optional, generated if not provided)
            tool_json: Optional JSON blob representing tool schema
            meta: Optional metadata key-value pairs
            topic: Topic to publish to (default: "mcp")
            qos: Quality of Service parameters
            
        Returns:
            message_id: ID of the sent message
        """
        # Create MCP message
        mcp_message = self.create_mcp_message(prompt, message_id, tool_json, meta)
        
        # Create a span if telemetry is available
        span = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "mcp.send",
                kind=trace.SpanKind.PRODUCER,
                attributes={
                    "topic": topic,
                    "message_id": mcp_message.id,
                    "prompt_length": len(mcp_message.prompt),
                    "has_tool": bool(mcp_message.tool_json),
                },
            )
        
        try:
            # Publish message
            await self.transport.publish(topic, mcp_message, qos)
            
            # Return message ID
            return mcp_message.id
        finally:
            # End span if created
            if span:
                span.end()
    
    async def listen(
        self,
        handlers: List[Callable],
        topic: str = "mcp",
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Listen for MCP messages and process them.
        
        Args:
            handlers: List of callback functions to handle received messages
            topic: Topic to subscribe to (default: "mcp")
            qos: Quality of Service parameters
        """
        # Get MCP message class
        MCP = self._get_mcp_message_class()
        
        # Define message handler
        async def message_handler(mcp_message):
            # Create a span if telemetry is available
            span = None
            if self.telemetry:
                span = self.telemetry.create_span(
                    "mcp.receive",
                    kind=trace.SpanKind.CONSUMER,
                    attributes={
                        "topic": topic,
                        "message_id": mcp_message.id,
                        "prompt_length": len(mcp_message.prompt),
                        "has_tool": bool(mcp_message.tool_json),
                    },
                )
            
            try:
                # Call all handlers
                for handler in handlers:
                    try:
                        await handler(mcp_message)
                    except Exception as e:
                        logger.error(f"Error in MCP handler: {e}")
                        if span:
                            span.record_exception(e)
            finally:
                # End span if created
                if span:
                    span.end()
        
        # Subscribe to topic
        await self.transport.subscribe(topic, message_handler, MCP, qos)
        
        logger.debug(f"Subscribed to MCP messages on topic {topic}")