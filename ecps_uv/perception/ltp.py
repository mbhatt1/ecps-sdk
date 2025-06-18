"""
Latent Tensor Protocol (LTP) handler for ECPS.

This module provides handling for LTP messages, which transport compressed
N-dimensional arrays (tensors) representing latent embeddings or processed
features derived from raw sensor data.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import zstandard as zstd

# Import LTP message type
try:
    from ecps_uv.proto import ecps_pb2
except ImportError:
    # Dynamically generated protobuf modules might not be available at import time
    ecps_pb2 = None

logger = logging.getLogger("ecps_uv.perception.ltp")


class LTPHandler:
    """
    Handler for Latent Tensor Protocol (LTP) messages.
    
    This handler provides functionality for creating, sending, receiving,
    and processing LTP messages, which transport compressed tensors.
    """
    
    def __init__(
        self,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
        compression_level: int = 3,
        max_size_bytes: int = 1024 * 1024,  # 1 MiB
    ):
        """
        Initialize the LTP handler.
        
        Args:
            transport: Transport layer to use for sending/receiving messages
            serializer: Serializer to use for message encoding/decoding
            telemetry: Telemetry provider for observability (optional)
            compression_level: zstd compression level (1-22, higher = better compression but slower)
            max_size_bytes: Maximum size of LTP frames in bytes (default: 1 MiB)
        """
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
        self.compression_level = compression_level
        self.max_size_bytes = max_size_bytes
        
        # Create zstd compressor and decompressor
        self.compressor = zstd.ZstdCompressor(level=compression_level)
        self.decompressor = zstd.ZstdDecompressor()
        
        # Map of numpy dtypes to LTP dtype strings
        self.dtype_mapping = {
            np.float32: "f32",
            np.float16: "f16",
            np.float64: "f64",
            np.uint8: "u8",
            np.uint16: "u16",
            np.uint32: "u32",
            np.uint64: "u64",
            np.int8: "i8",
            np.int16: "i16",
            np.int32: "i32",
            np.int64: "i64",
            np.bool_: "bool",
        }
        
        # Inverse mapping
        self.dtype_inverse_mapping = {
            "f32": np.float32,
            "f16": np.float16,
            "f64": np.float64,
            "u8": np.uint8,
            "u16": np.uint16,
            "u32": np.uint32,
            "u64": np.uint64,
            "i8": np.int8,
            "i16": np.int16,
            "i32": np.int32,
            "i64": np.int64,
            "bool": np.bool_,
        }
    
    def _get_ltp_message_class(self):
        """Get the LTP message class from ecps_pb2."""
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        if hasattr(ecps_pb2, "LTP"):
            return ecps_pb2.LTP
        
        raise AttributeError("LTP message type not found in ecps_pb2")
    
    def _get_dtype_string(self, dtype):
        """Convert numpy dtype to LTP dtype string."""
        if dtype in self.dtype_mapping:
            return self.dtype_mapping[dtype]
        
        # Try to match by name
        dtype_type = np.dtype(dtype).type
        if dtype_type in self.dtype_mapping:
            return self.dtype_mapping[dtype_type]
        
        raise ValueError(f"Unsupported dtype: {dtype}")
    
    def _get_numpy_dtype(self, dtype_str):
        """Convert LTP dtype string to numpy dtype."""
        if dtype_str in self.dtype_inverse_mapping:
            return self.dtype_inverse_mapping[dtype_str]
        
        raise ValueError(f"Unsupported dtype string: {dtype_str}")
    
    def create_ltp_message(
        self,
        tensor: np.ndarray,
        frame_id: str,
        timestamp_ns: Optional[int] = None,
    ) -> Any:
        """
        Create an LTP message from a numpy array.
        
        Args:
            tensor: Numpy array to encode
            frame_id: Reference coordinate frame
            timestamp_ns: Timestamp in nanoseconds since Unix epoch (default: current time)
            
        Returns:
            ltp_message: LTP message
        """
        # Get current timestamp if not provided
        if timestamp_ns is None:
            timestamp_ns = int(time.time_ns())
        
        # Get dtype string
        dtype_str = self._get_dtype_string(tensor.dtype)
        
        # Compress tensor
        tensor_bytes = tensor.tobytes()
        compressed_tensor = self.compressor.compress(tensor_bytes)
        
        # Check size
        if len(compressed_tensor) > self.max_size_bytes:
            logger.warning(
                f"Compressed tensor size ({len(compressed_tensor)} bytes) exceeds max size "
                f"({self.max_size_bytes} bytes)"
            )
        
        # Create LTP message
        LTP = self._get_ltp_message_class()
        ltp_message = LTP()
        
        # Calculate checksum
        checksum = self.calculate_checksum(compressed_tensor)
        
        # Create frame header
        header = self.create_frame_header(
            message_type=1,  # DATA
            payload_length=len(compressed_tensor),
            checksum=checksum,
            metadata={
                "frame_id": frame_id,
                "dtype": dtype_str,
                "timestamp": str(timestamp_ns),
            }
        )
        
        # Set fields
        ltp_message.spec = "ltp/0.9"
        ltp_message.header.CopyFrom(header)
        ltp_message.tensor_zstd = compressed_tensor
        ltp_message.shape.extend(tensor.shape)
        ltp_message.dtype = dtype_str
        ltp_message.frame_id = frame_id
        ltp_message.timestamp_ns = timestamp_ns
        ltp_message.compression_level = self.compression_level
        ltp_message.original_size = len(tensor_bytes)
        
        # Add attributes
        ltp_message.attributes["compression_ratio"] = str(
            len(tensor_bytes) / len(compressed_tensor) if len(compressed_tensor) > 0 else 0
        )
        ltp_message.attributes["tensor_elements"] = str(tensor.size)
        
        # Record metrics if telemetry is available
        if self.telemetry:
            self.telemetry.record_ltp_frame_size(
                len(compressed_tensor),
                attributes={
                    "frame_id": frame_id,
                    "dtype": dtype_str,
                    "shape": str(tensor.shape),
                    "original_size": len(tensor_bytes),
                    "compression_ratio": len(tensor_bytes) / len(compressed_tensor) if len(compressed_tensor) > 0 else 0,
                },
            )
        
        return ltp_message
    
    def extract_tensor(self, ltp_message) -> Tuple[np.ndarray, Dict[str, Any]]:
        """
        Extract a numpy array from an LTP message.
        
        Args:
            ltp_message: LTP message
            
        Returns:
            tensor: Extracted numpy array
            metadata: Metadata from the LTP message
        """
        # Get dtype
        dtype = self._get_numpy_dtype(ltp_message.dtype)
        
        # Get shape
        shape = tuple(ltp_message.shape)
        
        # Decompress tensor
        compressed_tensor = ltp_message.tensor_zstd
        tensor_bytes = self.decompressor.decompress(compressed_tensor)
        
        # Convert to numpy array
        tensor = np.frombuffer(tensor_bytes, dtype=dtype).reshape(shape)
        
        # Extract metadata
        metadata = {
            "frame_id": ltp_message.frame_id,
            "timestamp_ns": ltp_message.timestamp_ns,
            "dtype": ltp_message.dtype,
            "shape": shape,
        }
        
        return tensor, metadata
    
    async def send(
        self,
        topic: str,
        tensor: np.ndarray,
        frame_id: str,
        timestamp_ns: Optional[int] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Send a tensor as an LTP message.
        
        Args:
            topic: Topic to publish to
            tensor: Numpy array to send
            frame_id: Reference coordinate frame
            timestamp_ns: Timestamp in nanoseconds since Unix epoch (default: current time)
            qos: Quality of Service parameters
            
        Returns:
            message_id: ID of the sent message
        """
        # Create LTP message
        ltp_message = self.create_ltp_message(tensor, frame_id, timestamp_ns)
        
        # Create a span if telemetry is available
        span = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "ltp.send",
                kind=trace.SpanKind.PRODUCER,
                attributes={
                    "topic": topic,
                    "frame_id": frame_id,
                    "dtype": ltp_message.dtype,
                    "shape": str(tuple(ltp_message.shape)),
                    "timestamp_ns": ltp_message.timestamp_ns,
                },
            )
        
        try:
            # Publish message
            await self.transport.publish(topic, ltp_message, qos)
            
            # Return message ID (if available)
            message_id = ltp_message.id if hasattr(ltp_message, "id") else None
            return message_id
        finally:
            # End span if created
            if span:
                span.end()
    
    async def receive(
        self,
        topic: str,
        handler: callable,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Subscribe to LTP messages and process them.
        
        Args:
            topic: Topic to subscribe to
            handler: Callback function to handle received tensors and metadata
            qos: Quality of Service parameters
        """
        # Get LTP message class
        LTP = self._get_ltp_message_class()
        
        # Define message handler
        async def message_handler(ltp_message):
            # Create a span if telemetry is available
            span = None
            if self.telemetry:
                span = self.telemetry.create_span(
                    "ltp.receive",
                    kind=trace.SpanKind.CONSUMER,
                    attributes={
                        "topic": topic,
                        "frame_id": ltp_message.frame_id,
                        "dtype": ltp_message.dtype,
                        "shape": str(tuple(ltp_message.shape)),
                        "timestamp_ns": ltp_message.timestamp_ns,
                    },
                )
            
            try:
                # Extract tensor and metadata
                tensor, metadata = self.extract_tensor(ltp_message)
                
                # Call user handler
                await handler(tensor, metadata)
            except Exception as e:
                logger.error(f"Error handling LTP message: {e}")
                # Record exception in span if available
                if span:
                    span.record_exception(e)
                raise
            finally:
                # End span if created
                if span:
                    span.end()
        
        # Subscribe to topic
        await self.transport.subscribe(topic, message_handler, LTP, qos)
        
        logger.debug(f"Subscribed to LTP messages on topic {topic}")
    
    def split_large_tensor(
        self,
        tensor: np.ndarray,
        max_size: Optional[int] = None,
        axis: int = 0,
    ) -> List[np.ndarray]:
        """
        Split a large tensor into smaller chunks that fit within size limits.
        
        Args:
            tensor: Large numpy array to split
            max_size: Maximum size in bytes (default: self.max_size_bytes)
            axis: Axis along which to split the tensor
            
        Returns:
            chunks: List of smaller tensor chunks
        """
        max_size = max_size or self.max_size_bytes
        
        # Estimate compression ratio (conservative)
        sample_size = min(1024 * 1024, tensor.nbytes)
        if sample_size < tensor.nbytes:
            sample = tensor.flatten()[:sample_size // tensor.itemsize].tobytes()
        else:
            sample = tensor.tobytes()
        
        compressed_sample = self.compressor.compress(sample)
        compression_ratio = len(sample) / len(compressed_sample)
        
        # Estimate max chunk size in original bytes
        max_chunk_bytes = max_size * compression_ratio * 0.9  # Add safety margin
        
        # Calculate number of elements per chunk
        bytes_per_element = tensor.itemsize
        elements_per_chunk = int(max_chunk_bytes // bytes_per_element)
        
        # If tensor is already small enough, return as is
        if tensor.size <= elements_per_chunk:
            return [tensor]
        
        # Calculate chunk size along the specified axis
        total_elements = tensor.shape[axis]
        elements_per_chunk_along_axis = max(1, elements_per_chunk // (tensor.size // total_elements))
        
        # Split tensor
        chunks = []
        for i in range(0, total_elements, elements_per_chunk_along_axis):
            # Create slice for the chunk
            slices = [slice(None)] * tensor.ndim
            slices[axis] = slice(i, min(i + elements_per_chunk_along_axis, total_elements))
            
            # Extract chunk
            chunk = tensor[tuple(slices)]
            chunks.append(chunk)
        
        return chunks
    def create_frame_header(
        self,
        message_type: int,
        payload_length: int,
        sequence_number: int = 0,
        total_chunks: int = 0,
        chunk_index: int = 0,
        checksum: bytes = b"",
        metadata: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        Create an LTP frame header.
        
        Args:
            message_type: Message type (1=DATA, 2=ACK, 3=CHUNK_START, 4=CHUNK_END)
            payload_length: Length of payload in bytes
            sequence_number: Sequence number for ordering
            total_chunks: Total number of chunks (0 if not chunked)
            chunk_index: Current chunk index (0-based)
            checksum: CRC32 checksum of payload
            metadata: Additional metadata
            
        Returns:
            LTPFrameHeader message
        """
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        header = ecps_pb2.LTPFrameHeader()
        header.version = 1  # Current LTP version
        header.message_type = message_type
        header.payload_length = payload_length
        header.sequence_number = sequence_number
        header.total_chunks = total_chunks
        header.chunk_index = chunk_index
        header.checksum = checksum
        
        if metadata:
            for key, value in metadata.items():
                header.metadata[key] = value
        
        return header
    
    def calculate_checksum(self, data: bytes) -> bytes:
        """Calculate CRC32 checksum of data."""
        import zlib
        crc = zlib.crc32(data) & 0xffffffff
        return crc.to_bytes(4, 'big')
    
    def create_chunked_messages(
        self,
        tensor: np.ndarray,
        frame_id: str,
        timestamp_ns: Optional[int] = None,
        max_chunk_size: Optional[int] = None,
    ) -> List[Any]:
        """
        Create chunked LTP messages for large tensors.
        
        Args:
            tensor: Numpy array to encode
            frame_id: Reference coordinate frame
            timestamp_ns: Timestamp in nanoseconds since Unix epoch
            max_chunk_size: Maximum size per chunk (default: self.max_size_bytes)
            
        Returns:
            List of LTP chunk messages
        """
        max_chunk_size = max_chunk_size or self.max_size_bytes
        
        # Get current timestamp if not provided
        if timestamp_ns is None:
            timestamp_ns = int(time.time_ns())
        
        # Get dtype string
        dtype_str = self._get_dtype_string(tensor.dtype)
        
        # Compress tensor
        tensor_bytes = tensor.tobytes()
        compressed_tensor = self.compressor.compress(tensor_bytes)
        
        # Check if chunking is needed
        if len(compressed_tensor) <= max_chunk_size:
            # Single message, no chunking needed
            ltp_message = self.create_ltp_message(tensor, frame_id, timestamp_ns)
            return [ltp_message]
        
        # Split compressed data into chunks
        chunks = []
        chunk_size = max_chunk_size - 1024  # Reserve space for headers
        total_chunks = (len(compressed_tensor) + chunk_size - 1) // chunk_size
        
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        for i in range(total_chunks):
            start_idx = i * chunk_size
            end_idx = min(start_idx + chunk_size, len(compressed_tensor))
            chunk_data = compressed_tensor[start_idx:end_idx]
            
            # Calculate checksum
            checksum = self.calculate_checksum(chunk_data)
            
            # Create frame header
            message_type = 3 if i == 0 else (4 if i == total_chunks - 1 else 1)  # CHUNK_START, CHUNK_END, or DATA
            header = self.create_frame_header(
                message_type=message_type,
                payload_length=len(chunk_data),
                sequence_number=i,
                total_chunks=total_chunks,
                chunk_index=i,
                checksum=checksum,
                metadata={
                    "frame_id": frame_id,
                    "dtype": dtype_str,
                    "shape": str(tensor.shape),
                    "timestamp_ns": str(timestamp_ns),
                    "original_size": str(len(tensor_bytes)),
                    "compression_level": str(self.compression_level),
                }
            )
            
            # Create chunk message
            chunk_msg = ecps_pb2.LTPChunk()
            chunk_msg.header.CopyFrom(header)
            chunk_msg.chunk_data = chunk_data
            chunk_msg.is_final = (i == total_chunks - 1)
            
            chunks.append(chunk_msg)
        
        return chunks
    
    async def send_chunked(
        self,
        topic: str,
        tensor: np.ndarray,
        frame_id: str,
        timestamp_ns: Optional[int] = None,
        qos: Optional[Dict[str, Any]] = None,
    ) -> List[str]:
        """
        Send a tensor as chunked LTP messages if needed.
        
        Args:
            topic: Topic to publish to
            tensor: Numpy array to send
            frame_id: Reference coordinate frame
            timestamp_ns: Timestamp in nanoseconds since Unix epoch
            qos: Quality of Service parameters
            
        Returns:
            List of message IDs for sent chunks
        """
        # Create chunked messages
        chunks = self.create_chunked_messages(tensor, frame_id, timestamp_ns)
        
        message_ids = []
        
        # Send each chunk
        for i, chunk in enumerate(chunks):
            # Create a span if telemetry is available
            span = None
            if self.telemetry:
                span = self.telemetry.create_span(
                    "ltp.send_chunk",
                    kind=trace.SpanKind.PRODUCER,
                    attributes={
                        "topic": topic,
                        "chunk_index": i,
                        "total_chunks": len(chunks),
                        "frame_id": frame_id,
                        "is_final": chunk.is_final,
                    },
                )
            
            try:
                # Publish chunk
                await self.transport.publish(topic, chunk, qos)
                
                # Generate message ID
                message_id = f"{frame_id}_{timestamp_ns}_{i}"
                message_ids.append(message_id)
                
            finally:
                # End span if created
                if span:
                    span.end()
        
        return message_ids
    
    async def receive_chunked(
        self,
        topic: str,
        handler: callable,
        qos: Optional[Dict[str, Any]] = None,
    ):
        """
        Subscribe to chunked LTP messages and reassemble them.
        
        Args:
            topic: Topic to subscribe to
            handler: Callback function to handle reassembled tensors and metadata
            qos: Quality of Service parameters
        """
        # Storage for partial chunks
        chunk_storage = {}  # sequence_number -> {chunks: dict, metadata: dict}
        
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        # Define chunk handler
        async def chunk_handler(chunk_msg):
            header = chunk_msg.header
            sequence_num = header.sequence_number
            chunk_index = header.chunk_index
            total_chunks = header.total_chunks
            
            # Initialize storage for this sequence if needed
            if sequence_num not in chunk_storage:
                chunk_storage[sequence_num] = {
                    "chunks": {},
                    "metadata": dict(header.metadata),
                    "total_chunks": total_chunks,
                }
            
            # Store this chunk
            chunk_storage[sequence_num]["chunks"][chunk_index] = chunk_msg.chunk_data
            
            # Check if we have all chunks
            stored_chunks = chunk_storage[sequence_num]["chunks"]
            if len(stored_chunks) == total_chunks:
                # Reassemble tensor
                try:
                    # Concatenate chunks in order
                    compressed_data = b""
                    for i in range(total_chunks):
                        if i not in stored_chunks:
                            logger.error(f"Missing chunk {i} for sequence {sequence_num}")
                            return
                        compressed_data += stored_chunks[i]
                    
                    # Decompress tensor
                    tensor_bytes = self.decompressor.decompress(compressed_data)
                    
                    # Get metadata
                    metadata = chunk_storage[sequence_num]["metadata"]
                    dtype_str = metadata.get("dtype", "f32")
                    shape_str = metadata.get("shape", "[]")
                    frame_id = metadata.get("frame_id", "")
                    timestamp_ns = int(metadata.get("timestamp_ns", "0"))
                    
                    # Parse shape
                    import ast
                    shape = tuple(ast.literal_eval(shape_str))
                    
                    # Convert to numpy array
                    dtype = self._get_numpy_dtype(dtype_str)
                    tensor = np.frombuffer(tensor_bytes, dtype=dtype).reshape(shape)
                    
                    # Create metadata dict
                    tensor_metadata = {
                        "frame_id": frame_id,
                        "timestamp_ns": timestamp_ns,
                        "dtype": dtype_str,
                        "shape": shape,
                        "reassembled": True,
                        "total_chunks": total_chunks,
                    }
                    
                    # Call user handler
                    await handler(tensor, tensor_metadata)
                    
                except Exception as e:
                    logger.error(f"Error reassembling chunked tensor: {e}")
                finally:
                    # Clean up storage
                    del chunk_storage[sequence_num]
        
        # Subscribe to topic
        await self.transport.subscribe(topic, chunk_handler, ecps_pb2.LTPChunk, qos)
        
        logger.debug(f"Subscribed to chunked LTP messages on topic {topic}")