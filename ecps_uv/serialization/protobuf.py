"""
Protocol Buffers serialization for ECPS.

This module provides serialization and deserialization of ECPS messages
using Protocol Buffers. It supports binary encoding for efficiency and
optionally JSON encoding for debugging.
"""

import logging
from typing import Any, Dict, Optional, Type, Union

from google.protobuf import json_format
from google.protobuf.message import Message

# Import protobuf messages for ECPS
try:
    from ecps_uv.proto import ecps_pb2
except ImportError:
    # Dynamically generated protobuf modules might not be available at import time
    ecps_pb2 = None

logger = logging.getLogger("ecps_uv.serialization.protobuf")


class ProtobufSerializer:
    """
    Serializer for Protocol Buffers messages.
    
    This serializer handles encoding and decoding of ECPS messages using
    Protocol Buffers, supporting both binary and JSON formats.
    """
    
    def __init__(self, prefer_json: bool = False):
        """
        Initialize the Protocol Buffers serializer.
        
        Args:
            prefer_json: Whether to prefer JSON encoding over binary (default: False)
        """
        self.prefer_json = prefer_json
        self._message_types = {}  # Message type name -> message class
        
        # Register all known message types
        self._register_message_types()
    
    def _register_message_types(self):
        """Register all known message types from ecps_pb2."""
        if ecps_pb2 is None:
            logger.warning("ecps_pb2 module not available, message types will be registered dynamically")
            return
        
        # Get all message classes from ecps_pb2
        for name in dir(ecps_pb2):
            if name.startswith("_"):
                continue
            
            # Get the attribute
            attr = getattr(ecps_pb2, name)
            
            # Check if it's a Protocol Buffers message class
            if isinstance(attr, type) and issubclass(attr, Message):
                self._message_types[name] = attr
                logger.debug(f"Registered message type: {name}")
    
    def get_message_class(self, message_type_name: str) -> Type[Message]:
        """
        Get the message class for a given type name.
        
        Args:
            message_type_name: Name of the message type
            
        Returns:
            message_class: Protocol Buffers message class
        """
        # Check if already registered
        if message_type_name in self._message_types:
            return self._message_types[message_type_name]
        
        # Try to dynamically import
        if ecps_pb2 is not None:
            if hasattr(ecps_pb2, message_type_name):
                message_class = getattr(ecps_pb2, message_type_name)
                self._message_types[message_type_name] = message_class
                return message_class
        
        raise ValueError(f"Unknown message type: {message_type_name}")
    
    def serialize(
        self,
        message: Message,
        use_json: Optional[bool] = None,
    ) -> bytes:
        """
        Serialize a Protocol Buffers message to bytes.
        
        Args:
            message: Protocol Buffers message
            use_json: Whether to use JSON encoding (overrides prefer_json)
            
        Returns:
            serialized: Serialized message as bytes
        """
        # Determine if we should use JSON
        use_json = use_json if use_json is not None else self.prefer_json
        
        if use_json:
            # Convert to JSON string
            json_str = json_format.MessageToJson(
                message,
                preserving_proto_field_name=True,
                including_default_value_fields=True,
            )
            return json_str.encode("utf-8")
        else:
            # Binary serialization
            return message.SerializeToString()
    
    def deserialize(
        self,
        data: bytes,
        message_type: Union[str, Type[Message]],
        use_json: Optional[bool] = None,
    ) -> Message:
        """
        Deserialize bytes to a Protocol Buffers message.
        
        Args:
            data: Serialized message as bytes
            message_type: Type of message to deserialize to (name or class)
            use_json: Whether the data is JSON-encoded (overrides prefer_json)
            
        Returns:
            message: Deserialized Protocol Buffers message
        """
        # Determine if we should use JSON
        use_json = use_json if use_json is not None else self.prefer_json
        
        # Get message class if string type name provided
        if isinstance(message_type, str):
            message_class = self.get_message_class(message_type)
        else:
            message_class = message_type
        
        # Create empty message
        message = message_class()
        
        if use_json:
            # Parse JSON
            json_str = data.decode("utf-8")
            json_format.Parse(json_str, message)
        else:
            # Parse binary
            message.ParseFromString(data)
        
        return message
    
    def get_message_type_name(self, message: Message) -> str:
        """
        Get the type name of a Protocol Buffers message.
        
        Args:
            message: Protocol Buffers message
            
        Returns:
            type_name: Name of the message type
        """
        return type(message).__name__
    
    def is_valid_message(self, message: Any) -> bool:
        """
        Check if an object is a valid Protocol Buffers message.
        
        Args:
            message: Object to check
            
        Returns:
            is_valid: Whether the object is a valid Protocol Buffers message
        """
        return isinstance(message, Message)