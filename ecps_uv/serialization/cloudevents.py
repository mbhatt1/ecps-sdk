"""
CloudEvents wrapper for ECPS messages.

This module provides a wrapper for ECPS messages using CloudEvents 1.0,
ensuring interoperability across different services, platforms, and 
programming languages.
"""

import logging
import uuid
from typing import Any, Dict, Optional, Tuple, Union

from cloudevents.http import CloudEvent, to_structured, from_http
from google.protobuf.message import Message

logger = logging.getLogger("ecps_uv.serialization.cloudevents")


class CloudEventsWrapper:
    """
    Wrapper for ECPS messages using CloudEvents 1.0.
    
    This wrapper handles packaging serialized protobuf messages into
    CloudEvents envelopes and extracting protobuf messages from
    CloudEvents envelopes.
    """
    
    def __init__(self, serializer: Any):
        """
        Initialize the CloudEvents wrapper.
        
        Args:
            serializer: Serializer to use for message encoding/decoding
        """
        self.serializer = serializer
        self.default_source = "urn:ecps:client"
        self.spec_version = "1.0"
    
    def _get_message_type(self, message: Message) -> str:
        """
        Get the CloudEvents type for an ECPS message.
        
        Args:
            message: ECPS message
            
        Returns:
            ce_type: CloudEvents type
        """
        # Get message type name
        message_type = type(message).__name__
        
        # Map to CloudEvents type
        if message_type == "MCP":
            return "ecps.mcp.prompt"
        elif message_type == "LTP":
            return "ecps.ltp.tensor"
        elif message_type == "EAP":
            return "ecps.eap.action"
        elif message_type == "Ack":
            return "ecps.mep.ack"
        elif message_type == "QueryReq":
            return "ecps.mep.query"
        else:
            return f"ecps.unknown.{message_type.lower()}"
    
    def _get_content_type(self, use_json: bool) -> str:
        """
        Get the content type for serialized data.
        
        Args:
            use_json: Whether the data is JSON-encoded
            
        Returns:
            content_type: Content type string
        """
        if use_json:
            return "application/cloudevents+json"
        else:
            return "application/cloudevents+protobuf"
    
    def _get_message_id(self, message: Message) -> str:
        """
        Get or create a message ID.
        
        Args:
            message: ECPS message
            
        Returns:
            message_id: Unique message ID
        """
        # Check if message has an id field
        if hasattr(message, "id") and message.id:
            return message.id
        
        # Generate a new ID
        return str(uuid.uuid4())
    
    def wrap(
        self,
        message: Message,
        use_json: bool = False,
        source: Optional[str] = None,
    ) -> Tuple[Dict[str, str], bytes]:
        """
        Wrap an ECPS message in a CloudEvents envelope.
        
        Args:
            message: ECPS message to wrap
            use_json: Whether to use JSON encoding
            source: Source identifier (e.g., "urn:robot:arm1")
            
        Returns:
            headers: CloudEvents HTTP headers
            body: CloudEvents HTTP body
        """
        # Get message ID
        message_id = self._get_message_id(message)
        
        # Set ID in message if it has an id field
        if hasattr(message, "id") and not message.id:
            message.id = message_id
        
        # Get CloudEvents type
        ce_type = self._get_message_type(message)
        
        # Get source
        source = source or self.default_source
        
        # Get content type
        content_type = self._get_content_type(use_json)
        
        # Serialize message
        data = self.serializer.serialize(message, use_json=use_json)
        
        # Create CloudEvent
        event = CloudEvent(
            {
                "id": message_id,
                "source": source,
                "type": ce_type,
                "specversion": self.spec_version,
                "datacontenttype": content_type,
            },
            data,
        )
        
        # Convert to structured HTTP format
        headers, body = to_structured(event)
        
        return headers, body
    
    def unwrap(
        self,
        headers: Dict[str, str],
        body: bytes,
        message_type: Any,
    ) -> Tuple[Message, Dict[str, str]]:
        """
        Unwrap an ECPS message from a CloudEvents envelope.
        
        Args:
            headers: CloudEvents HTTP headers
            body: CloudEvents HTTP body
            message_type: Type of message to deserialize to
            
        Returns:
            message: Unwrapped ECPS message
            attributes: CloudEvents attributes
        """
        # Parse CloudEvent
        event = from_http(headers, body)
        
        # Get CloudEvents attributes
        attributes = {
            "id": event["id"],
            "source": event["source"],
            "type": event["type"],
            "specversion": event["specversion"],
            "datacontenttype": event.get("datacontenttype", "application/cloudevents+protobuf"),
        }
        
        # Determine serialization format
        use_json = attributes["datacontenttype"] == "application/cloudevents+json"
        
        # Deserialize message
        message = self.serializer.deserialize(event.data, message_type, use_json=use_json)
        
        # Mirror CloudEvents ID to message if it has an id field
        if hasattr(message, "id") and not message.id:
            message.id = attributes["id"]
        
        return message, attributes
    
    def extract_trace_id(self, headers: Dict[str, str]) -> Optional[str]:
        """
        Extract trace ID from CloudEvents headers.
        
        For ECPS, the CloudEvents ID is used as the trace ID for
        end-to-end correlation via OpenTelemetry.
        
        Args:
            headers: CloudEvents HTTP headers
            
        Returns:
            trace_id: Trace ID for OpenTelemetry
        """
        # Extract CloudEvents attributes from headers
        ce_id = headers.get("ce-id")
        
        return ce_id