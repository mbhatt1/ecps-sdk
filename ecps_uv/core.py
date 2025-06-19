"""
Core implementation of the ECPS-UV SDK.

This module provides the main client and server classes, as well as configuration 
handling for different ECPS conformance profiles.
"""

import asyncio
import logging
import uuid
from typing import Dict, Optional, Type, Union, List, Callable, Any

import uv
from ecps_uv.qos_constants import get_profile_qos, validate_timing_budget, TimingBudgets

# Set up logging
logger = logging.getLogger("ecps_uv")


class ECPSConfig:
    """Configuration for ECPS client and server components."""
    
    def __init__(
        self,
        profile: str = "standard",
        transport_type: str = "dds",
        serialization_format: str = "protobuf",
        observability_enabled: bool = True,
        transport_config: Optional[Dict[str, Any]] = None,
        otlp_endpoint: Optional[str] = None,
        log_level: int = logging.INFO,
        identity_forwarding_enabled: bool = True,
        session_duration_hours: int = 8,
    ):
        """
        Initialize ECPS configuration.
        
        Args:
            profile: ECPS conformance profile ("edge-lite", "standard", "cloud-fleet")
            transport_type: Transport layer to use ("dds", "grpc", "mqtt")
            serialization_format: Serialization format ("protobuf", "json")
            observability_enabled: Whether to enable OpenTelemetry observability
            transport_config: Additional transport-specific configuration
            otlp_endpoint: OpenTelemetry endpoint URL
            log_level: Logging level
            identity_forwarding_enabled: Whether to use identity forwarding by default
            session_duration_hours: Default session duration for identity contexts
        """
        self.profile = profile.lower()
        self.transport_type = transport_type.lower()
        self.serialization_format = serialization_format.lower()
        self.observability_enabled = observability_enabled
        self.transport_config = transport_config or {}
        self.otlp_endpoint = otlp_endpoint
        self.log_level = log_level
        self.identity_forwarding_enabled = identity_forwarding_enabled
        self.session_duration_hours = session_duration_hours
        
        # Set up logging
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
        
        # Validate configuration based on profile
        self._validate_config()
    
    def _validate_config(self):
        """Validate configuration based on selected profile."""
        # Edge-Lite profile restrictions
        if self.profile == "edge-lite":
            if self.transport_type not in ["dds"]:
                logger.warning(
                    f"Edge-Lite profile typically only supports DDS transport, not {self.transport_type}."
                )
            if self.observability_enabled:
                logger.warning(
                    "Edge-Lite profile typically does not include observability layer (L4)."
                )
        
        # Standard profile requirements
        elif self.profile == "standard":
            if self.transport_type not in ["dds", "grpc"]:
                logger.warning(
                    f"Standard profile typically uses DDS or gRPC transport, not {self.transport_type}."
                )
        
        # Cloud-Fleet profile requirements
        elif self.profile == "cloud-fleet":
            pass  # All transport options are valid for Cloud-Fleet
        
        else:
            logger.warning(f"Unknown profile: {self.profile}")


class EdgeLiteProfile(ECPSConfig):
    """Edge-Lite profile configuration."""
    
    def __init__(
        self,
        transport_config: Optional[Dict[str, Any]] = None,
        log_level: int = logging.INFO,
    ):
        """Initialize Edge-Lite profile configuration."""
        super().__init__(
            profile="edge-lite",
            transport_type="dds",
            serialization_format="protobuf",
            observability_enabled=False,
            transport_config=transport_config,
            log_level=log_level,
            identity_forwarding_enabled=True,  # Enable by default
            session_duration_hours=4,  # Shorter sessions for edge devices
        )


class StandardProfile(ECPSConfig):
    """Standard profile configuration."""
    
    def __init__(
        self,
        transport_type: str = "dds",
        transport_config: Optional[Dict[str, Any]] = None,
        otlp_endpoint: Optional[str] = None,
        log_level: int = logging.INFO,
    ):
        """Initialize Standard profile configuration."""
        super().__init__(
            profile="standard",
            transport_type=transport_type,
            serialization_format="protobuf",
            observability_enabled=True,
            transport_config=transport_config,
            otlp_endpoint=otlp_endpoint,
            log_level=log_level,
            identity_forwarding_enabled=True,  # Enable by default
            session_duration_hours=8,  # Standard session duration
        )


class CloudFleetProfile(ECPSConfig):
    """Cloud-Fleet profile configuration."""
    
    def __init__(
        self,
        transport_type: str = "grpc",
        transport_config: Optional[Dict[str, Any]] = None,
        otlp_endpoint: Optional[str] = None,
        log_level: int = logging.INFO,
    ):
        """Initialize Cloud-Fleet profile configuration."""
        super().__init__(
            profile="cloud-fleet",
            transport_type=transport_type,
            serialization_format="protobuf",
            observability_enabled=True,
            transport_config=transport_config,
            otlp_endpoint=otlp_endpoint,
            log_level=log_level,
            identity_forwarding_enabled=True,  # Enable by default
            session_duration_hours=12,  # Longer sessions for cloud environments
        )


class ECPSClient:
    """
    Main ECPS client implementation using UV for asynchronous I/O.
    
    This client can be used to:
    - Send MCP messages to AI agents
    - Store and query memory embeddings using MEP
    - Send action commands using EAP
    """
    
    def __init__(self, config: ECPSConfig):
        """
        Initialize ECPS client.
        
        Args:
            config: ECPS configuration
        """
        self.config = config
        self.transport = None
        self.serializer = None
        self.telemetry = None
        self.loop = None
        self.identity_forwarding_manager = None
        self.identity_context = None
        
        # Initialize components based on configuration
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize components based on configuration."""
        # Import all components here to avoid circular imports
        from ecps_uv.transport import DDSTransport, GRPCTransport, MQTTTransport
        from ecps_uv.serialization import ProtobufSerializer
        from ecps_uv.observability import ECPSTelemetry
        from ecps_uv.trust.trust import create_default_trust_provider
        from ecps_uv.trust.identity import create_default_identity_provider
        from ecps_uv.trust.identity_forwarding import create_default_identity_forwarding_manager
        from ecps_uv.trust.secure_transport import SecureTransport
        
        # Create the UV-powered event loop
        self.loop = uv.Loop.default()
        
        # Initialize serializer
        self.serializer = ProtobufSerializer()
        
        # Initialize transport
        if self.config.transport_type == "dds":
            self.transport = DDSTransport(
                serializer=self.serializer,
                config=self.config.transport_config,
                loop=self.loop,
            )
        elif self.config.transport_type == "grpc":
            self.transport = GRPCTransport(
                serializer=self.serializer,
                config=self.config.transport_config,
                loop=self.loop,
            )
        elif self.config.transport_type == "mqtt":
            self.transport = MQTTTransport(
                serializer=self.serializer,
                config=self.config.transport_config,
                loop=self.loop,
            )
        else:
            raise ValueError(f"Unsupported transport type: {self.config.transport_type}")
        
        # Initialize identity forwarding by default if enabled
        if self.config.identity_forwarding_enabled:
            # Create trust and identity providers
            trust_provider = create_default_trust_provider()
            identity_store, identity_provider = create_default_identity_provider()
            
            # Create identity forwarding manager
            self.identity_forwarding_manager = create_default_identity_forwarding_manager(
                identity_provider, trust_provider
            )
            
            # Wrap transport with secure transport using identity forwarding
            self.transport = SecureTransport(
                transport=self.transport,
                trust_provider=trust_provider,
                identity_forwarding_manager=self.identity_forwarding_manager,
            )
        
        # Initialize telemetry if enabled
        if self.config.observability_enabled:
            self.telemetry = ECPSTelemetry(
                otlp_endpoint=self.config.otlp_endpoint,
                service_name="ecps-client",
                loop=self.loop,
            )
        
        # Initialize unified protocol handler (consolidates all protocols)
        from ecps_uv.cognition.unified import UEPHandler
        
        self.uep_handler = UEPHandler(
            self.transport,
            self.serializer,
            self.telemetry
        )
# ========== IDENTITY FORWARDING METHODS ==========
    
    async def establish_identity(
        self, 
        identity_id: str, 
        credential: str, 
        capabilities: Optional[set] = None
    ):
        """
        Establish an identity context for this client (enables identity forwarding).
        
        This method authenticates once and creates a session that can be forwarded
        with all subsequent requests, eliminating the need for per-request signing.
        
        Args:
            identity_id: Identity to authenticate
            credential: Authentication credential
            capabilities: Set of capabilities to grant
            
        Returns:
            bool: True if identity was established successfully
        """
        if not self.config.identity_forwarding_enabled:
            logger.warning("Identity forwarding is disabled in configuration")
            return False
            
        if not self.identity_forwarding_manager:
            logger.error("Identity forwarding manager not initialized")
            return False
        
        from datetime import timedelta
        
        try:
            # Establish identity context
            self.identity_context = await self.identity_forwarding_manager.establish_identity_context(
                identity_id=identity_id,
                credential=credential,
                capabilities=capabilities or {"read", "write", "coordinate"},
                session_duration=timedelta(hours=self.config.session_duration_hours),
            )
            
            if self.identity_context:
                # Set identity context on secure transport
                if hasattr(self.transport, 'set_identity_context'):
                    self.transport.set_identity_context(self.identity_context)
                
                logger.info(f"Identity context established for {identity_id}")
                logger.info(f"Session expires: {self.identity_context.expires_at}")
                return True
            else:
                logger.error("Failed to establish identity context")
                return False
                
        except Exception as e:
            logger.error(f"Error establishing identity: {e}")
            return False
    
    def get_identity_status(self) -> Dict[str, Any]:
        """
        Get the current identity context status.
        
        Returns:
            Dict containing identity status information
        """
        if not self.identity_context:
            return {"authenticated": False, "reason": "No identity context"}
        
        if self.identity_context.is_expired:
            return {"authenticated": False, "reason": "Identity context expired"}
        
        return {
            "authenticated": True,
            "identity_id": self.identity_context.identity.id,
            "identity_name": self.identity_context.identity.name,
            "session_id": self.identity_context.session_id,
            "expires_at": self.identity_context.expires_at.isoformat(),
            "time_remaining": str(self.identity_context.time_remaining),
            "capabilities": list(self.identity_context.capabilities),
        }
    
    async def refresh_identity(self, additional_hours: int = None) -> bool:
        """
        Refresh the current identity context to extend its lifetime.
        
        Args:
            additional_hours: Additional hours to extend (defaults to config value)
            
        Returns:
            bool: True if refresh was successful
        """
        if not self.identity_context:
            logger.error("No identity context to refresh")
            return False
        
        if not self.identity_forwarding_manager:
            logger.error("Identity forwarding manager not available")
            return False
        
        from datetime import timedelta
        
        hours = additional_hours or self.config.session_duration_hours
        additional_duration = timedelta(hours=hours)
        
        success = self.identity_forwarding_manager.refresh_context(
            self.identity_context.session_id,
            additional_duration=additional_duration,
        )
        
        if success:
            logger.info(f"Identity context refreshed for {hours} hours")
        else:
            logger.error("Failed to refresh identity context")
        
        return success
    
    async def revoke_identity(self) -> bool:
        """
        Revoke the current identity context.
        
        Returns:
            bool: True if revocation was successful
        """
        if not self.identity_context:
            return True  # Already no identity
        
        if not self.identity_forwarding_manager:
            logger.error("Identity forwarding manager not available")
            return False
        
        success = self.identity_forwarding_manager.revoke_context(
            self.identity_context.session_id
        )
        
        if success:
            logger.info("Identity context revoked")
            self.identity_context = None
        else:
            logger.error("Failed to revoke identity context")
        
        return success
    
    async def send_mcp(self, prompt: str, tool_json: Optional[bytes] = None, meta: Optional[Dict[str, str]] = None):
        """
        Send a Model Context Protocol (MCP) message.
        
        Args:
            prompt: The prompt to send (≤16 KiB UTF-8)
            tool_json: Optional JSON blob representing tool schema
            meta: Optional metadata key-value pairs
            
        Returns:
            message_id: Unique ID of the sent message
        """
        from ecps_uv.cognition import MCPHandler
        
        # Generate a unique ID for this message
        message_id = str(uuid.uuid4())
        
        # Create and send the MCP message
        mcp_handler = MCPHandler(self.transport, self.serializer, self.telemetry)
        await mcp_handler.send(prompt, message_id, tool_json, meta)
        
        return message_id
    
    async def store_memory(self, tensor_zstd: bytes, shape: List[int], dtype: str, frame_id: str, timestamp_ns: int):
        """
        Store a memory embedding using Memory Exchange Protocol (MEP).
        
        Args:
            tensor_zstd: zstd-compressed tensor data
            shape: Shape of the tensor (e.g., [B,L,D])
            dtype: Data type of tensor elements (e.g., "f32")
            frame_id: Reference coordinate frame
            timestamp_ns: Timestamp in nanoseconds since Unix epoch
            
        Returns:
            success: Whether the operation was successful
            message: Additional information about the operation
        """
        from ecps_uv.cognition import MEPClient
        
        mep_client = MEPClient(self.transport, self.serializer, self.telemetry)
        return await mep_client.put(tensor_zstd, shape, dtype, frame_id, timestamp_ns)
    
    async def query_memory(self, query_embedding, k: int = 10, min_sim: float = 0.7):
        """
        Query memory embeddings using Memory Exchange Protocol (MEP).
        
        Args:
            query_embedding: LTP message or components to construct one
            k: Maximum number of embeddings to return
            min_sim: Minimum cosine similarity threshold
            
        Returns:
            embeddings: List of matching embeddings
        """
        from ecps_uv.cognition import MEPClient
        
        mep_client = MEPClient(self.transport, self.serializer, self.telemetry)
        return await mep_client.query(query_embedding, k, min_sim)
    
    async def send_action(self, action_type: str, action_data: Any, state_sha: bytes, meta: Optional[Dict[str, str]] = None):
        """
        Send an Embodied Action Protocol (EAP) message.
        
        Args:
            action_type: Type of action ("set_pose", "gripper", "cloud", "sim")
            action_data: Action-specific data
            state_sha: SHA-256 hash of perceptual snapshot
            meta: Optional metadata key-value pairs
            
        Returns:
            message_id: Unique ID of the sent action
        """
        from ecps_uv.actuation import EAPHandler
        
        # Generate a unique ID for this action
        message_id = str(uuid.uuid4())
        
        eap_handler = EAPHandler(self.transport, self.serializer, self.telemetry)
        await eap_handler.send(action_type, action_data, message_id, state_sha, meta)
        
        return message_id
    
    # ========== UNIFIED API METHODS ==========
    
    async def send_unified(self, operation: str, **kwargs):
        """
        Send any type of ECPS message using the unified API.
        
        Args:
            operation: Type of operation (prompt, memory_put, memory_query, action, etc.)
            **kwargs: Operation-specific parameters
            
        Returns:
            result: Operation result (varies by operation type)
        """
        if operation == "prompt":
            return await self.uep_handler.send_prompt(
                kwargs.get("prompt", ""),
                kwargs.get("message_id"),
                kwargs.get("tool_json"),
                kwargs.get("meta"),
                kwargs.get("qos")
            )
        elif operation == "memory_put":
            return await self.uep_handler.store_memory(
                kwargs.get("tensor_zstd", b""),
                kwargs.get("shape", []),
                kwargs.get("dtype", "f32"),
                kwargs.get("frame_id", ""),
                kwargs.get("timestamp_ns", 0),
                kwargs.get("qos")
            )
        elif operation == "memory_query":
            return await self.uep_handler.query_memory(
                kwargs.get("query_embedding"),
                kwargs.get("k", 10),
                kwargs.get("min_sim", 0.7),
                kwargs.get("qos")
            )
        elif operation == "action":
            return await self.uep_handler.send_action(
                kwargs.get("action_type", ""),
                kwargs.get("action_data"),
                kwargs.get("state_sha", b""),
                kwargs.get("meta"),
                kwargs.get("qos")
            )
        elif operation == "perception":
            return await self.uep_handler.send_perception(
                kwargs.get("tensor_zstd", b""),
                kwargs.get("shape", []),
                kwargs.get("dtype", "f32"),
                kwargs.get("frame_id", ""),
                kwargs.get("timestamp_ns", 0),
                kwargs.get("qos")
            )
        elif operation == "coordinate":
            return await self.uep_handler.coordinate_agents(
                kwargs.get("coordination_type", ""),
                kwargs.get("agent_ids", []),
                kwargs.get("coordination_data"),
                kwargs.get("meta"),
                kwargs.get("qos")
            )
        elif operation == "trust":
            return await self.uep_handler.manage_trust(
                kwargs.get("trust_operation", ""),
                kwargs.get("identity", ""),
                kwargs.get("trust_data"),
                kwargs.get("meta"),
                kwargs.get("qos")
            )
        elif operation == "telemetry":
            return await self.uep_handler.send_telemetry(
                kwargs.get("metric_type", ""),
                kwargs.get("metric_data"),
                kwargs.get("timestamp_ns", 0),
                kwargs.get("meta"),
                kwargs.get("qos")
            )
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    async def listen_unified(self, handlers: Dict[str, List[Callable]], qos: Optional[Dict[str, Any]] = None):
        """
        Listen for all types of ECPS messages using the unified API.
        
        Args:
            handlers: Dictionary mapping operation types to handler functions
            qos: Quality of Service parameters
        """
        await self.uep_handler.listen(handlers, qos)
    
    async def query_unified(self, data_type: str, query_params: Dict[str, Any]) -> List[Any]:
        """
        Query any type of stored data using the unified API.
        
        Args:
            data_type: Type of data to query (memory, perception, action, etc.)
            query_params: Query parameters
            
        Returns:
            results: Query results
        """
        return await self.uep_handler.query_unified(data_type, query_params)
    
    async def get_unified_stats(self) -> Dict[str, Any]:
        """Get unified statistics for all data types."""
        return await self.uep_handler.get_stats()

    async def close(self):
        """Close the client and release resources."""
        if hasattr(self, 'uep_handler') and self.uep_handler:
            await self.uep_handler.close()
            
        if self.transport:
            await self.transport.close()
        
        if self.telemetry:
            await self.telemetry.shutdown()


class ECPSServer:
    """
    Main ECPS server implementation using UV for asynchronous I/O.
    
    This server can:
    - Receive and process MCP messages
    - Implement MEP for memory storage and retrieval
    - Receive and execute EAP action commands
    """
    
    def __init__(self, config: ECPSConfig):
        """
        Initialize ECPS server.
        
        Args:
            config: ECPS configuration
        """
        self.config = config
        self.transport = None
        self.serializer = None
        self.telemetry = None
        self.loop = None
        
        # Handlers for different message types
        self.mcp_handlers = []
        self.eap_handlers = []
        
        # MEP service if enabled
        self.mep_service = None
        
        # Initialize components based on configuration
        self._initialize_components()
    
    def _initialize_components(self):
        """Initialize components based on configuration."""
        # Import all components here to avoid circular imports
        from ecps_uv.transport import DDSTransport, GRPCTransport, MQTTTransport
        from ecps_uv.serialization import ProtobufSerializer
        from ecps_uv.observability import ECPSTelemetry
        
        # Create the UV-powered event loop
        self.loop = uv.Loop.default()
        
        # Initialize serializer
        self.serializer = ProtobufSerializer()
        
        # Initialize transport
        if self.config.transport_type == "dds":
            self.transport = DDSTransport(
                serializer=self.serializer,
                config=self.config.transport_config,
                loop=self.loop,
                is_server=True,
            )
        elif self.config.transport_type == "grpc":
            self.transport = GRPCTransport(
                serializer=self.serializer,
                config=self.config.transport_config,
                loop=self.loop,
                is_server=True,
            )
        elif self.config.transport_type == "mqtt":
            self.transport = MQTTTransport(
                serializer=self.serializer,
                config=self.config.transport_config,
                loop=self.loop,
                is_server=True,
            )
        else:
            raise ValueError(f"Unsupported transport type: {self.config.transport_type}")
        
        # Initialize telemetry if enabled
        if self.config.observability_enabled:
            self.telemetry = ECPSTelemetry(
                otlp_endpoint=self.config.otlp_endpoint,
                service_name="ecps-server",
                loop=self.loop,
            )
    
    def on_mcp(self, handler: Callable):
        """
        Register a handler for MCP messages.
        
        Args:
            handler: Callback function to handle MCP messages
        """
        self.mcp_handlers.append(handler)
    
    def on_eap(self, handler: Callable):
        """
        Register a handler for EAP messages.
        
        Args:
            handler: Callback function to handle EAP messages
        """
        self.eap_handlers.append(handler)
    
    def start_mep_service(self, storage_backend=None):
        """
        Start the MEP service for memory storage and retrieval.
        
        Args:
            storage_backend: Backend for storing embeddings (default: in-memory)
        """
        from ecps_uv.cognition import MEPServer
        
        self.mep_service = MEPServer(
            self.transport,
            self.serializer,
            self.telemetry,
            storage_backend=storage_backend,
        )
    
    async def start(self):
        """Start the server and begin listening for messages."""
        # Start the transport
        await self.transport.start()
        
        # Start the MEP service if initialized
        if self.mep_service:
            await self.mep_service.start()
        
        # Register handlers for different message types
        from ecps_uv.cognition import MCPHandler
        from ecps_uv.actuation import EAPHandler
        
        # Set up MCP handling
        mcp_handler = MCPHandler(self.transport, self.serializer, self.telemetry)
        await mcp_handler.listen(self.mcp_handlers)
        
        # Set up EAP handling
        eap_handler = EAPHandler(self.transport, self.serializer, self.telemetry)
        await eap_handler.listen(self.eap_handlers)
    
    async def close(self):
        """Stop the server and release resources."""
        # Stop the MEP service if running
        if self.mep_service:
            await self.mep_service.stop()
        
        # Close the transport
        if self.transport:
            await self.transport.close()
        
        # Shutdown telemetry
        if self.telemetry:
            await self.telemetry.shutdown()