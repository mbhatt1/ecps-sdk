"""
Memory Exchange Protocol (MEP) client and server for ECPS.

This module provides client and server implementations for MEP, which allows
AI agents to store and query latent embeddings in a distributed memory store.
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import numpy as np
from opentelemetry import trace

# Import MEP-related message types
try:
    from ecps_uv.proto import ecps_pb2
except ImportError:
    # Dynamically generated protobuf modules might not be available at import time
    ecps_pb2 = None

logger = logging.getLogger("ecps_uv.cognition.mep")


class InMemoryVectorStore:
    """
    In-memory vector store for MEP embeddings.
    
    This is a simple implementation that stores embeddings in memory and
    provides cosine similarity search.
    """
    
    def __init__(self, max_size: int = 10000):
        """
        Initialize the in-memory vector store.
        
        Args:
            max_size: Maximum number of embeddings to store
        """
        self.embeddings = []  # List of (tensor, metadata) tuples
        self.max_size = max_size
    
    async def put(self, tensor: np.ndarray, metadata: Dict[str, Any]) -> bool:
        """
        Store a tensor with metadata.
        
        Args:
            tensor: Tensor to store
            metadata: Metadata for the tensor
            
        Returns:
            success: Whether the operation was successful
        """
        # Check if we're at capacity
        if len(self.embeddings) >= self.max_size:
            # Remove oldest embedding (LRU policy)
            self.embeddings.pop(0)
        
        # Store embedding
        self.embeddings.append((tensor, metadata))
        
        return True
    
    async def query(
        self,
        query_tensor: np.ndarray,
        k: int = 10,
        min_sim: float = 0.7,
    ) -> List[Tuple[np.ndarray, Dict[str, Any], float]]:
        """
        Query for similar embeddings.
        
        Args:
            query_tensor: Query tensor
            k: Maximum number of embeddings to return
            min_sim: Minimum cosine similarity threshold
            
        Returns:
            results: List of (tensor, metadata, similarity) tuples
        """
        # Normalize query tensor
        query_norm = np.linalg.norm(query_tensor)
        if query_norm > 0:
            query_tensor = query_tensor / query_norm
        
        results = []
        
        # Calculate cosine similarity for each embedding
        for tensor, metadata in self.embeddings:
            # Normalize tensor
            tensor_norm = np.linalg.norm(tensor)
            if tensor_norm > 0:
                normalized_tensor = tensor / tensor_norm
            else:
                normalized_tensor = tensor
            
            # Calculate cosine similarity
            similarity = np.dot(query_tensor.flatten(), normalized_tensor.flatten())
            
            # Check if similarity meets threshold
            if similarity >= min_sim:
                results.append((tensor, metadata, similarity))
        
        # Sort by similarity (descending)
        results.sort(key=lambda x: x[2], reverse=True)
        
        # Return top k results
        return results[:k]


class MEPClient:
    """
    Client for Memory Exchange Protocol (MEP).
    
    This client allows AI agents to store and query memory embeddings.
    """
    
    def __init__(
        self,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
    ):
        """
        Initialize the MEP client.
        
        Args:
            transport: Transport layer to use for sending/receiving messages
            serializer: Serializer to use for message encoding/decoding
            telemetry: Telemetry provider for observability (optional)
        """
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
        
        # Default service name
        self.service_name = "MemoryStore"
    
    def _get_message_classes(self):
        """Get the MEP-related message classes from ecps_pb2."""
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        result = {}
        
        if hasattr(ecps_pb2, "LTP"):
            result["LTP"] = ecps_pb2.LTP
        else:
            raise AttributeError("LTP message type not found in ecps_pb2")
        
        if hasattr(ecps_pb2, "QueryReq"):
            result["QueryReq"] = ecps_pb2.QueryReq
        else:
            raise AttributeError("QueryReq message type not found in ecps_pb2")
        
        if hasattr(ecps_pb2, "Ack"):
            result["Ack"] = ecps_pb2.Ack
        else:
            raise AttributeError("Ack message type not found in ecps_pb2")
        
        return result
    
    async def put(
        self,
        tensor_zstd: bytes,
        shape: List[int],
        dtype: str,
        frame_id: str,
        timestamp_ns: int,
        qos: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Store a memory embedding.
        
        Args:
            tensor_zstd: zstd-compressed tensor data
            shape: Shape of the tensor (e.g., [B,L,D])
            dtype: Data type of tensor elements (e.g., "f32")
            frame_id: Reference coordinate frame
            timestamp_ns: Timestamp in nanoseconds since Unix epoch
            qos: Quality of Service parameters
            
        Returns:
            success: Whether the operation was successful
            message: Additional information about the operation
        """
        # Get message classes
        classes = self._get_message_classes()
        LTP = classes["LTP"]
        Ack = classes["Ack"]
        
        # Create LTP message
        ltp_message = LTP()
        ltp_message.spec = "ltp/0.9"
        ltp_message.tensor_zstd = tensor_zstd
        ltp_message.shape.extend(shape)
        ltp_message.dtype = dtype
        ltp_message.frame_id = frame_id
        ltp_message.timestamp_ns = timestamp_ns
        
        # Create a span if telemetry is available
        span = None
        start_time = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "mep.put",
                kind=trace.SpanKind.CLIENT,
                attributes={
                    "frame_id": frame_id,
                    "dtype": dtype,
                    "shape": str(shape),
                    "tensor_size": len(tensor_zstd),
                },
            )
            start_time = time.time()
        
        try:
            # Send request
            service = f"{self.service_name}.Put"
            response = await self.transport.request(service, ltp_message, qos=qos)
            
            # Record metrics if telemetry is available
            if self.telemetry and start_time:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_mep_query_latency(
                    latency_ms,
                    attributes={
                        "operation": "put",
                        "success": response.success,
                    },
                )
            
            return response.success, response.message
        except Exception as e:
            logger.error(f"Error in MEP Put: {e}")
            if span:
                span.record_exception(e)
            return False, str(e)
        finally:
            # End span if created
            if span:
                span.end()
    
    async def query(
        self,
        query_embedding: Any,
        k: int = 10,
        min_sim: float = 0.7,
        qos: Optional[Dict[str, Any]] = None,
    ) -> List[Any]:
        """
        Query for similar embeddings.
        
        Args:
            query_embedding: LTP message or components to construct one
            k: Maximum number of embeddings to return
            min_sim: Minimum cosine similarity threshold
            qos: Quality of Service parameters
            
        Returns:
            embeddings: List of matching embeddings (LTP messages)
        """
        # Get message classes
        classes = self._get_message_classes()
        LTP = classes["LTP"]
        QueryReq = classes["QueryReq"]
        
        # Create query request
        query_req = QueryReq()
        
        # Set query embedding
        if isinstance(query_embedding, LTP):
            query_req.query_embedding.CopyFrom(query_embedding)
        elif isinstance(query_embedding, dict):
            # Construct LTP from components
            query_req.query_embedding.spec = "ltp/0.9"
            query_req.query_embedding.tensor_zstd = query_embedding.get("tensor_zstd", b"")
            query_req.query_embedding.shape.extend(query_embedding.get("shape", []))
            query_req.query_embedding.dtype = query_embedding.get("dtype", "f32")
            query_req.query_embedding.frame_id = query_embedding.get("frame_id", "")
            query_req.query_embedding.timestamp_ns = query_embedding.get("timestamp_ns", 0)
        else:
            raise ValueError("query_embedding must be an LTP message or a dictionary")
        
        # Set other parameters
        query_req.k = k
        query_req.min_sim = min_sim
        
        # Create a span if telemetry is available
        span = None
        start_time = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "mep.query",
                kind=trace.SpanKind.CLIENT,
                attributes={
                    "k": k,
                    "min_sim": min_sim,
                    "frame_id": query_req.query_embedding.frame_id,
                    "dtype": query_req.query_embedding.dtype,
                    "shape": str(list(query_req.query_embedding.shape)),
                },
            )
            start_time = time.time()
        
        try:
            # Collect results
            results = []
            
            # Define handler for streamed responses
            async def handle_response(ltp_message):
                results.append(ltp_message)
            
            # Send streaming request
            service = f"{self.service_name}.Query"
            await self.transport.stream_request(service, query_req, handle_response, qos=qos)
            
            # Record metrics if telemetry is available
            if self.telemetry and start_time:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_mep_query_latency(
                    latency_ms,
                    attributes={
                        "operation": "query",
                        "k": k,
                        "min_sim": min_sim,
                        "results_count": len(results),
                    },
                )
            
            return results
        except Exception as e:
            logger.error(f"Error in MEP Query: {e}")
            if span:
                span.record_exception(e)
            return []
        finally:
            # End span if created
            if span:
                span.end()


class MEPServer:
    """
    Server for Memory Exchange Protocol (MEP).
    
    This server implements the MEP service for memory storage and retrieval.
    """
    
    def __init__(
        self,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
        storage_backend: Optional[Any] = None,
    ):
        """
        Initialize the MEP server.
        
        Args:
            transport: Transport layer to use for sending/receiving messages
            serializer: Serializer to use for message encoding/decoding
            telemetry: Telemetry provider for observability (optional)
            storage_backend: Backend for storing embeddings (default: in-memory)
        """
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
        self.storage = storage_backend or InMemoryVectorStore()
        
        # Default service name
        self.service_name = "MemoryStore"
    
    def _get_message_classes(self):
        """Get the MEP-related message classes from ecps_pb2."""
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        result = {}
        
        if hasattr(ecps_pb2, "LTP"):
            result["LTP"] = ecps_pb2.LTP
        else:
            raise AttributeError("LTP message type not found in ecps_pb2")
        
        if hasattr(ecps_pb2, "QueryReq"):
            result["QueryReq"] = ecps_pb2.QueryReq
        else:
            raise AttributeError("QueryReq message type not found in ecps_pb2")
        
        if hasattr(ecps_pb2, "Ack"):
            result["Ack"] = ecps_pb2.Ack
        else:
            raise AttributeError("Ack message type not found in ecps_pb2")
        
        return result
    
    async def start(self):
        """Start the MEP server."""
        # Get message classes
        classes = self._get_message_classes()
        LTP = classes["LTP"]
        QueryReq = classes["QueryReq"]
        Ack = classes["Ack"]
        
        # Register Put service
        await self.transport.register_service(
            f"{self.service_name}.Put",
            self._handle_put,
            LTP,
            Ack,
        )
        
        # Register Query service
        await self.transport.register_stream_service(
            f"{self.service_name}.Query",
            self._handle_query,
            QueryReq,
            LTP,
        )
        
        logger.info("MEP server started")
    
    async def stop(self):
        """Stop the MEP server."""
        # No explicit stop action needed for now
        logger.info("MEP server stopped")
    
    async def _handle_put(self, ltp_message):
        """
        Handle a Put request.
        
        Args:
            ltp_message: LTP message containing the embedding to store
            
        Returns:
            response: Ack message indicating success or failure
        """
        # Get message classes
        classes = self._get_message_classes()
        Ack = classes["Ack"]
        
        # Create a span if telemetry is available
        span = None
        start_time = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "mep.server.put",
                kind=trace.SpanKind.SERVER,
                attributes={
                    "frame_id": ltp_message.frame_id,
                    "dtype": ltp_message.dtype,
                    "shape": str(list(ltp_message.shape)),
                    "tensor_size": len(ltp_message.tensor_zstd),
                },
            )
            start_time = time.time()
        
        try:
            # Extract tensor from LTP message
            from ecps_uv.perception.ltp import LTPHandler
            
            # Create temporary LTP handler
            ltp_handler = LTPHandler(self.transport, self.serializer, self.telemetry)
            
            # Extract tensor and metadata
            tensor, metadata = ltp_handler.extract_tensor(ltp_message)
            
            # Store in backend
            success = await self.storage.put(tensor, metadata)
            
            # Record metrics if telemetry is available
            if self.telemetry and start_time:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_mep_query_latency(
                    latency_ms,
                    attributes={
                        "operation": "put",
                        "success": success,
                    },
                )
            
            # Create response
            response = Ack()
            response.success = success
            response.message = "Embedding stored successfully" if success else "Failed to store embedding"
            
            return response
        except Exception as e:
            logger.error(f"Error handling MEP Put: {e}")
            if span:
                span.record_exception(e)
            
            # Create error response
            response = Ack()
            response.success = False
            response.message = str(e)
            
            return response
        finally:
            # End span if created
            if span:
                span.end()
    
    async def _handle_query(self, query_req, publish_response):
        """
        Handle a Query request.
        
        Args:
            query_req: QueryReq message containing the query parameters
            publish_response: Function to publish responses
        """
        # Get message classes
        classes = self._get_message_classes()
        LTP = classes["LTP"]
        
        # Extract query parameters
        query_embedding = query_req.query_embedding
        k = query_req.k
        min_sim = query_req.min_sim
        
        # Create a span if telemetry is available
        span = None
        start_time = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "mep.server.query",
                kind=trace.SpanKind.SERVER,
                attributes={
                    "k": k,
                    "min_sim": min_sim,
                    "frame_id": query_embedding.frame_id,
                    "dtype": query_embedding.dtype,
                    "shape": str(list(query_embedding.shape)),
                },
            )
            start_time = time.time()
        
        try:
            # Extract tensor from LTP message
            from ecps_uv.perception.ltp import LTPHandler
            
            # Create temporary LTP handler
            ltp_handler = LTPHandler(self.transport, self.serializer, self.telemetry)
            
            # Extract query tensor and metadata
            query_tensor, _ = ltp_handler.extract_tensor(query_embedding)
            
            # Query backend
            results = await self.storage.query(query_tensor, k, min_sim)
            
            # Record metrics if telemetry is available
            if self.telemetry and start_time:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_mep_query_latency(
                    latency_ms,
                    attributes={
                        "operation": "query",
                        "k": k,
                        "min_sim": min_sim,
                        "results_count": len(results),
                    },
                )
            
            # Send each result as a separate LTP message
            for i, (tensor, metadata, similarity) in enumerate(results):
                # Create LTP message from tensor and metadata
                ltp_message = ltp_handler.create_ltp_message(
                    tensor,
                    metadata.get("frame_id", ""),
                    metadata.get("timestamp_ns", 0),
                )
                
                # Add similarity as metadata
                if not hasattr(ltp_message, "meta"):
                    # Add meta field if not present (this assumes LTP has a meta field)
                    # If not, consider adding similarity as a separate field or metadata in transport
                    pass
                
                # Publish response
                is_final = (i == len(results) - 1)
                await publish_response(ltp_message, is_final)
        except Exception as e:
            logger.error(f"Error handling MEP Query: {e}")
            if span:
                span.record_exception(e)
        finally:
            # End span if created
            if span:
                span.end()