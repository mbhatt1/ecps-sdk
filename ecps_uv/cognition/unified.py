"""
Unified ECPS Protocol (UEP) handler for ECPS.

This module provides a single unified API that consolidates ALL ECPS protocols:
- Model Context Protocol (MCP) for AI prompts
- Memory Exchange Protocol (MEP) for memory storage/retrieval
- Event Action Protocol (EAP) for actuation/actions
- Latent Tensor Protocol (LTP) for perception data
- Agent-to-Agent (A2A) coordination
- Trust and security operations
- Telemetry and observability
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
from opentelemetry import trace

# Import message types
try:
    from ecps_uv.proto import ecps_pb2
except ImportError:
    # Dynamically generated protobuf modules might not be available at import time
    ecps_pb2 = None

logger = logging.getLogger("ecps_uv.cognition.unified")

# Maximum sizes
MAX_PROMPT_SIZE = 16 * 1024  # 16 KiB
MAX_ACTION_SIZE = 64 * 1024  # 64 KiB
MAX_TENSOR_SIZE = 16 * 1024 * 1024  # 16 MiB

# UEP operation types - consolidating all protocols
UEP_OPERATION_PROMPT = "prompt"                    # MCP
UEP_OPERATION_MEMORY_PUT = "memory_put"           # MEP
UEP_OPERATION_MEMORY_QUERY = "memory_query"       # MEP
UEP_OPERATION_MEMORY_DELETE = "memory_delete"     # MEP
UEP_OPERATION_ACTION = "action"                    # EAP
UEP_OPERATION_PERCEPTION = "perception"           # LTP
UEP_OPERATION_COORDINATE = "coordinate"           # A2A
UEP_OPERATION_TRUST = "trust"                     # Trust/Security
UEP_OPERATION_TELEMETRY = "telemetry"            # Observability


class UnifiedStorage:
    """
    Unified storage backend that handles all data types.
    """
    
    def __init__(self, max_size: int = 10000):
        """Initialize unified storage."""
        self.max_size = max_size
        
        # Separate stores for different data types
        self.memory_embeddings = []  # (tensor, metadata) tuples
        self.perception_data = {}    # frame_id -> tensor data
        self.action_history = []     # action records
        self.coordination_state = {} # agent coordination state
        self.trust_credentials = {}  # identity and trust data
        self.telemetry_data = []     # telemetry records
    
    async def store(self, data_type: str, key: str, data: Any, metadata: Optional[Dict] = None) -> bool:
        """Store data of any type."""
        try:
            if data_type == "memory":
                if len(self.memory_embeddings) >= self.max_size:
                    self.memory_embeddings.pop(0)  # LRU
                self.memory_embeddings.append((data, metadata or {}))
                
            elif data_type == "perception":
                self.perception_data[key] = {"data": data, "metadata": metadata or {}}
                
            elif data_type == "action":
                if len(self.action_history) >= self.max_size:
                    self.action_history.pop(0)  # LRU
                self.action_history.append({"key": key, "data": data, "metadata": metadata or {}})
                
            elif data_type == "coordination":
                self.coordination_state[key] = {"data": data, "metadata": metadata or {}}
                
            elif data_type == "trust":
                self.trust_credentials[key] = {"data": data, "metadata": metadata or {}}
                
            elif data_type == "telemetry":
                if len(self.telemetry_data) >= self.max_size:
                    self.telemetry_data.pop(0)  # LRU
                self.telemetry_data.append({"key": key, "data": data, "metadata": metadata or {}})
                
            return True
        except Exception as e:
            logger.error(f"Error storing {data_type} data: {e}")
            return False
    
    async def query(self, data_type: str, query_params: Dict) -> List[Any]:
        """Query data of any type."""
        try:
            if data_type == "memory":
                return await self._query_memory(query_params)
            elif data_type == "perception":
                return await self._query_perception(query_params)
            elif data_type == "action":
                return await self._query_actions(query_params)
            elif data_type == "coordination":
                return await self._query_coordination(query_params)
            elif data_type == "trust":
                return await self._query_trust(query_params)
            elif data_type == "telemetry":
                return await self._query_telemetry(query_params)
            else:
                return []
        except Exception as e:
            logger.error(f"Error querying {data_type} data: {e}")
            return []
    
    async def _query_memory(self, params: Dict) -> List[Any]:
        """Query memory embeddings with similarity search."""
        query_tensor = params.get("query_tensor")
        k = params.get("k", 10)
        min_sim = params.get("min_sim", 0.7)
        
        if query_tensor is None:
            return []
        
        results = []
        query_norm = np.linalg.norm(query_tensor)
        if query_norm > 0:
            query_tensor = query_tensor / query_norm
        
        for tensor, metadata in self.memory_embeddings:
            tensor_norm = np.linalg.norm(tensor)
            if tensor_norm > 0:
                normalized_tensor = tensor / tensor_norm
                similarity = np.dot(query_tensor.flatten(), normalized_tensor.flatten())
                if similarity >= min_sim:
                    results.append((tensor, metadata, similarity))
        
        results.sort(key=lambda x: x[2], reverse=True)
        return results[:k]
    
    async def _query_perception(self, params: Dict) -> List[Any]:
        """Query perception data."""
        frame_id = params.get("frame_id")
        if frame_id:
            return [self.perception_data.get(frame_id)]
        return list(self.perception_data.values())
    
    async def _query_actions(self, params: Dict) -> List[Any]:
        """Query action history."""
        action_type = params.get("action_type")
        limit = params.get("limit", 100)
        
        results = self.action_history
        if action_type:
            results = [a for a in results if a.get("metadata", {}).get("action_type") == action_type]
        
        return results[-limit:]
    
    async def _query_coordination(self, params: Dict) -> List[Any]:
        """Query coordination state."""
        agent_id = params.get("agent_id")
        if agent_id:
            return [self.coordination_state.get(agent_id)]
        return list(self.coordination_state.values())
    
    async def _query_trust(self, params: Dict) -> List[Any]:
        """Query trust credentials."""
        identity = params.get("identity")
        if identity:
            return [self.trust_credentials.get(identity)]
        return list(self.trust_credentials.values())
    
    async def _query_telemetry(self, params: Dict) -> List[Any]:
        """Query telemetry data."""
        metric_type = params.get("metric_type")
        limit = params.get("limit", 100)
        
        results = self.telemetry_data
        if metric_type:
            results = [t for t in results if t.get("metadata", {}).get("metric_type") == metric_type]
        
        return results[-limit:]


class UEPHandler:
    """
    Unified ECPS Protocol (UEP) handler.
    
    This handler provides a single API that consolidates ALL ECPS protocols:
    - MCP, MEP, EAP, LTP, A2A, Trust, and Telemetry operations
    """
    
    def __init__(
        self,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
        storage_backend: Optional[Any] = None,
        trust_manager: Optional[Any] = None,
    ):
        """
        Initialize the UEP handler.
        
        Args:
            transport: Transport layer to use for sending/receiving messages
            serializer: Serializer to use for message encoding/decoding
            telemetry: Telemetry provider for observability (optional)
            storage_backend: Backend for storing data (default: unified in-memory)
            trust_manager: Trust manager for security operations (optional)
        """
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
        self.storage = storage_backend or UnifiedStorage()
        self.trust_manager = trust_manager
        
        # Default configuration
        self.service_name = "UnifiedECPSService"
        self.topic = "uep"
        
        # Component handlers (lazy-loaded)
        self._mcp_handler = None
        self._mep_client = None
        self._eap_handler = None
        self._ltp_handler = None
        self._a2a_coordinator = None
        self._trust_handler = None
    
    def _get_message_classes(self):
        """Get all message classes from ecps_pb2."""
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        result = {}
        message_types = ["MCP", "LTP", "QueryReq", "Ack", "EAP", "A2A", "Trust"]
        
        for msg_type in message_types:
            if hasattr(ecps_pb2, msg_type):
                result[msg_type] = getattr(ecps_pb2, msg_type)
        
        return result
    
    # ========== UNIFIED OPERATIONS ==========
    
    async def send_prompt(
        self,
        prompt: str,
        message_id: Optional[str] = None,
        tool_json: Optional[bytes] = None,
        meta: Optional[Dict[str, str]] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send a prompt to AI agents (MCP operation)."""
        return await self._execute_operation(
            UEP_OPERATION_PROMPT,
            {
                "prompt": prompt,
                "message_id": message_id,
                "tool_json": tool_json,
                "meta": meta or {}
            },
            qos
        )
    
    async def store_memory(
        self,
        tensor_zstd: bytes,
        shape: List[int],
        dtype: str,
        frame_id: str,
        timestamp_ns: int,
        qos: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """Store a memory embedding (MEP operation)."""
        result = await self._execute_operation(
            UEP_OPERATION_MEMORY_PUT,
            {
                "tensor_zstd": tensor_zstd,
                "shape": shape,
                "dtype": dtype,
                "frame_id": frame_id,
                "timestamp_ns": timestamp_ns
            },
            qos
        )
        return True, result
    
    async def query_memory(
        self,
        query_embedding: Any,
        k: int = 10,
        min_sim: float = 0.7,
        qos: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """Query for similar embeddings (MEP operation)."""
        result = await self._execute_operation(
            UEP_OPERATION_MEMORY_QUERY,
            {
                "query_embedding": query_embedding,
                "k": k,
                "min_sim": min_sim
            },
            qos
        )
        return result if isinstance(result, list) else []
    
    async def send_action(
        self,
        action_type: str,
        action_data: Any,
        state_sha: bytes,
        meta: Optional[Dict[str, str]] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send an action command (EAP operation)."""
        return await self._execute_operation(
            UEP_OPERATION_ACTION,
            {
                "action_type": action_type,
                "action_data": action_data,
                "state_sha": state_sha,
                "meta": meta or {}
            },
            qos
        )
    
    async def send_perception(
        self,
        tensor_zstd: bytes,
        shape: List[int],
        dtype: str,
        frame_id: str,
        timestamp_ns: int,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send perception data (LTP operation)."""
        return await self._execute_operation(
            UEP_OPERATION_PERCEPTION,
            {
                "tensor_zstd": tensor_zstd,
                "shape": shape,
                "dtype": dtype,
                "frame_id": frame_id,
                "timestamp_ns": timestamp_ns
            },
            qos
        )
    
    async def coordinate_agents(
        self,
        coordination_type: str,
        agent_ids: List[str],
        coordination_data: Any,
        meta: Optional[Dict[str, str]] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Coordinate with other agents (A2A operation)."""
        return await self._execute_operation(
            UEP_OPERATION_COORDINATE,
            {
                "coordination_type": coordination_type,
                "agent_ids": agent_ids,
                "coordination_data": coordination_data,
                "meta": meta or {}
            },
            qos
        )
    
    async def manage_trust(
        self,
        trust_operation: str,
        identity: str,
        trust_data: Any,
        meta: Optional[Dict[str, str]] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Manage trust and security operations."""
        return await self._execute_operation(
            UEP_OPERATION_TRUST,
            {
                "trust_operation": trust_operation,
                "identity": identity,
                "trust_data": trust_data,
                "meta": meta or {}
            },
            qos
        )
    
    async def send_telemetry(
        self,
        metric_type: str,
        metric_data: Any,
        timestamp_ns: int,
        meta: Optional[Dict[str, str]] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Send telemetry data."""
        return await self._execute_operation(
            UEP_OPERATION_TELEMETRY,
            {
                "metric_type": metric_type,
                "metric_data": metric_data,
                "timestamp_ns": timestamp_ns,
                "meta": meta or {}
            },
            qos
        )
    
    # ========== CORE EXECUTION ENGINE ==========
    
    async def _execute_operation(
        self,
        operation: str,
        data: Dict[str, Any],
        qos: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Execute a unified operation."""
        # Generate message ID
        message_id = str(uuid.uuid4())
        
        # Create unified message wrapper
        classes = self._get_message_classes()
        MCP = classes.get("MCP")
        
        if not MCP:
            raise RuntimeError("MCP message class not available")
        
        # Create wrapper message
        wrapper = MCP()
        wrapper.spec = "uep/1.0"  # Unified ECPS Protocol version
        wrapper.id = message_id
        wrapper.prompt = f"UEP {operation} operation"
        
        # Serialize operation data as tool_json
        wrapper.tool_json = self.serializer.serialize(data)
        
        # Set metadata
        wrapper.meta["uep_operation"] = operation
        wrapper.meta["timestamp"] = str(int(time.time() * 1000000000))  # nanoseconds
        
        # Add operation-specific metadata
        if operation == UEP_OPERATION_PROMPT:
            wrapper.prompt = data.get("prompt", "")
            if data.get("tool_json"):
                wrapper.tool_json = data["tool_json"]
            wrapper.meta.update(data.get("meta", {}))
        
        # Create telemetry span
        span = None
        start_time = time.time()
        if self.telemetry:
            span = self.telemetry.create_span(
                f"uep.{operation}",
                kind=trace.SpanKind.CLIENT,
                attributes={
                    "operation": operation,
                    "message_id": message_id,
                    "data_size": len(wrapper.tool_json) if wrapper.tool_json else 0,
                },
            )
        
        try:
            # Store locally if applicable
            await self._store_locally(operation, message_id, data)
            
            # Send message
            await self.transport.publish(self.topic, wrapper, qos)
            
            # Process operation-specific logic
            result = await self._process_operation(operation, data)
            
            # Record metrics
            if self.telemetry:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_operation_latency(
                    operation,
                    latency_ms,
                    attributes={"success": True, "message_id": message_id}
                )
            
            return result or message_id
            
        except Exception as e:
            logger.error(f"Error executing {operation} operation: {e}")
            if span:
                span.record_exception(e)
            
            if self.telemetry:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_operation_latency(
                    operation,
                    latency_ms,
                    attributes={"success": False, "error": str(e)}
                )
            
            raise
        finally:
            if span:
                span.end()
    
    async def _store_locally(self, operation: str, message_id: str, data: Dict[str, Any]):
        """Store data locally based on operation type."""
        try:
            if operation == UEP_OPERATION_MEMORY_PUT:
                # Extract tensor and store
                from ecps_uv.perception.ltp import LTPHandler
                ltp_handler = LTPHandler(self.transport, self.serializer, self.telemetry)
                
                # Create LTP message from data
                classes = self._get_message_classes()
                LTP = classes.get("LTP")
                if LTP:
                    ltp_msg = LTP()
                    ltp_msg.tensor_zstd = data["tensor_zstd"]
                    ltp_msg.shape.extend(data["shape"])
                    ltp_msg.dtype = data["dtype"]
                    ltp_msg.frame_id = data["frame_id"]
                    ltp_msg.timestamp_ns = data["timestamp_ns"]
                    
                    tensor, metadata = ltp_handler.extract_tensor(ltp_msg)
                    await self.storage.store("memory", message_id, tensor, metadata)
            
            elif operation == UEP_OPERATION_PERCEPTION:
                await self.storage.store("perception", data["frame_id"], data)
            
            elif operation == UEP_OPERATION_ACTION:
                await self.storage.store("action", message_id, data)
            
            elif operation == UEP_OPERATION_COORDINATE:
                await self.storage.store("coordination", message_id, data)
            
            elif operation == UEP_OPERATION_TRUST:
                await self.storage.store("trust", data["identity"], data)
            
            elif operation == UEP_OPERATION_TELEMETRY:
                await self.storage.store("telemetry", message_id, data)
                
        except Exception as e:
            logger.warning(f"Failed to store {operation} data locally: {e}")
    
    async def _process_operation(self, operation: str, data: Dict[str, Any]) -> Any:
        """Process operation-specific logic."""
        if operation == UEP_OPERATION_MEMORY_QUERY:
            # Perform local query if possible
            query_params = {
                "query_tensor": data.get("query_embedding"),
                "k": data.get("k", 10),
                "min_sim": data.get("min_sim", 0.7)
            }
            return await self.storage.query("memory", query_params)
        
        return None
    
    # ========== UNIFIED LISTENING ==========
    
    async def listen(
        self,
        handlers: Dict[str, List[Callable]],
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Listen for UEP messages and route them based on operation type.
        
        Args:
            handlers: Dictionary mapping operation types to handler functions
            qos: Quality of Service parameters
        """
        classes = self._get_message_classes()
        MCP = classes.get("MCP")
        
        if not MCP:
            raise RuntimeError("MCP message class not available")
        
        async def unified_handler(wrapper_message):
            # Create telemetry span
            span = None
            if self.telemetry:
                operation = wrapper_message.meta.get("uep_operation", "unknown")
                span = self.telemetry.create_span(
                    f"uep.receive.{operation}",
                    kind=trace.SpanKind.CONSUMER,
                    attributes={
                        "topic": self.topic,
                        "message_id": wrapper_message.id,
                        "operation": operation,
                    },
                )
            
            try:
                # Extract operation type
                operation = wrapper_message.meta.get("uep_operation", UEP_OPERATION_PROMPT)
                
                # Deserialize operation data
                operation_data = None
                if wrapper_message.tool_json:
                    try:
                        operation_data = self.serializer.deserialize(wrapper_message.tool_json)
                    except Exception as e:
                        logger.error(f"Failed to deserialize operation data: {e}")
                
                # Route to appropriate handlers
                if operation in handlers:
                    for handler in handlers[operation]:
                        try:
                            await handler(wrapper_message, operation_data)
                        except Exception as e:
                            logger.error(f"Error in UEP handler for {operation}: {e}")
                            if span:
                                span.record_exception(e)
                else:
                    logger.warning(f"No handlers registered for operation: {operation}")
                    
            finally:
                if span:
                    span.end()
        
        # Subscribe to unified topic
        await self.transport.subscribe(self.topic, unified_handler, MCP, qos)
        logger.info(f"Listening for UEP messages on topic {self.topic}")
    
    # ========== UTILITY METHODS ==========
    
    def validate_message(self, wrapper_message) -> bool:
        """Validate a UEP message."""
        if not wrapper_message:
            return False
        
        if not wrapper_message.spec.startswith("uep/"):
            return False
        
        if not wrapper_message.id:
            return False
        
        if not wrapper_message.meta or "uep_operation" not in wrapper_message.meta:
            return False
        
        operation = wrapper_message.meta["uep_operation"]
        valid_operations = [
            UEP_OPERATION_PROMPT, UEP_OPERATION_MEMORY_PUT, UEP_OPERATION_MEMORY_QUERY,
            UEP_OPERATION_MEMORY_DELETE, UEP_OPERATION_ACTION, UEP_OPERATION_PERCEPTION,
            UEP_OPERATION_COORDINATE, UEP_OPERATION_TRUST, UEP_OPERATION_TELEMETRY
        ]
        
        return operation in valid_operations
    
    async def query_unified(
        self,
        data_type: str,
        query_params: Dict[str, Any],
    ) -> List[Any]:
        """Query any type of stored data."""
        return await self.storage.query(data_type, query_params)
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get unified statistics."""
        return {
            "memory_embeddings": len(self.storage.memory_embeddings),
            "perception_data": len(self.storage.perception_data),
            "action_history": len(self.storage.action_history),
            "coordination_state": len(self.storage.coordination_state),
            "trust_credentials": len(self.storage.trust_credentials),
            "telemetry_data": len(self.storage.telemetry_data),
        }
    
    async def close(self):
        """Close the UEP handler and release resources."""
        # Clear all storage
        if hasattr(self.storage, 'memory_embeddings'):
            self.storage.memory_embeddings.clear()
        if hasattr(self.storage, 'perception_data'):
            self.storage.perception_data.clear()
        if hasattr(self.storage, 'action_history'):
            self.storage.action_history.clear()
        if hasattr(self.storage, 'coordination_state'):
            self.storage.coordination_state.clear()
        if hasattr(self.storage, 'trust_credentials'):
            self.storage.trust_credentials.clear()
        if hasattr(self.storage, 'telemetry_data'):
            self.storage.telemetry_data.clear()
        
        logger.info("UEP handler closed")


# Backward compatibility aliases
UCPHandler = UEPHandler  # For transition period