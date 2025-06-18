"""
Quality of Service (QoS) Constants and Timing Budgets for ECPS-UV SDK.

This module defines hard real-time numbers and QoS parameters to ensure
consistent behavior across different implementations and conformance profiles.
"""

from typing import Dict, Any
from enum import Enum


class QoSLevel(Enum):
    """QoS levels for different message types."""
    BEST_EFFORT = 0
    RELIABLE = 1
    PERSISTENT = 2


class TimingBudgets:
    """
    Hard real-time timing budgets for each ECPS layer.
    
    These constants define maximum acceptable latencies and jitter
    for different operations across the ECPS stack.
    """
    
    # L0 Physical Layer - Hardware interface timing
    PHYSICAL_MAX_LATENCY_MS = 1.0  # 1ms max for hardware I/O
    PHYSICAL_MAX_JITTER_MS = 0.1   # 100μs max jitter
    
    # L1 Data Link Layer - Frame transmission timing
    DATALINK_MAX_LATENCY_MS = 5.0  # 5ms max for frame transmission
    DATALINK_MAX_JITTER_MS = 0.5   # 500μs max jitter
    
    # L2 Network Layer - Routing and forwarding
    NETWORK_MAX_LATENCY_MS = 10.0  # 10ms max for routing
    NETWORK_MAX_JITTER_MS = 1.0    # 1ms max jitter
    
    # L3 Transport Layer - End-to-end delivery
    TRANSPORT_MAX_LATENCY_MS = 50.0   # 50ms max for transport
    TRANSPORT_MAX_JITTER_MS = 5.0     # 5ms max jitter
    TRANSPORT_TIMEOUT_S = 30.0        # 30s default timeout
    
    # L4 Observability Layer - Telemetry collection
    OBSERVABILITY_MAX_LATENCY_MS = 100.0  # 100ms max for telemetry
    OBSERVABILITY_BATCH_INTERVAL_MS = 1000.0  # 1s batching interval
    
    # L5 Perception Layer (LTP) - Sensor data processing
    LTP_MAX_LATENCY_MS = 100.0     # 100ms max for perception
    LTP_MAX_JITTER_MS = 10.0       # 10ms max jitter
    LTP_FRAME_TIMEOUT_S = 5.0      # 5s timeout for frame processing
    
    # L6 Cognition Layer (MCP/MEP) - AI processing
    MCP_MAX_LATENCY_MS = 5000.0    # 5s max for AI inference
    MCP_MAX_JITTER_MS = 500.0      # 500ms max jitter
    MCP_REQUEST_TIMEOUT_S = 30.0   # 30s timeout for AI requests
    
    MEP_PUT_MAX_LATENCY_MS = 200.0    # 200ms max for memory store
    MEP_QUERY_MAX_LATENCY_MS = 1000.0 # 1s max for memory query
    MEP_MAX_JITTER_MS = 50.0          # 50ms max jitter
    
    # L7 Actuation Layer (EAP) - Robot control
    EAP_MAX_LATENCY_MS = 20.0      # 20ms max for actuation (critical)
    EAP_MAX_JITTER_MS = 2.0        # 2ms max jitter (very strict)
    EAP_SAFETY_TIMEOUT_S = 1.0     # 1s safety timeout
    
    # End-to-end timing budgets
    E2E_PERCEPTION_TO_ACTION_MS = 200.0  # 200ms perception to action
    E2E_COGNITION_LOOP_MS = 10000.0      # 10s full cognition loop


class QoSParameters:
    """
    QoS parameters for different message types and transport layers.
    """
    
    # Default QoS settings by message type
    DEFAULT_QOS = {
        "MCP": {
            "reliability": QoSLevel.RELIABLE,
            "max_latency_ms": TimingBudgets.MCP_MAX_LATENCY_MS,
            "max_jitter_ms": TimingBudgets.MCP_MAX_JITTER_MS,
            "timeout_s": TimingBudgets.MCP_REQUEST_TIMEOUT_S,
            "retry_count": 3,
            "priority": 5,  # Medium priority
        },
        "LTP": {
            "reliability": QoSLevel.BEST_EFFORT,
            "max_latency_ms": TimingBudgets.LTP_MAX_LATENCY_MS,
            "max_jitter_ms": TimingBudgets.LTP_MAX_JITTER_MS,
            "timeout_s": TimingBudgets.LTP_FRAME_TIMEOUT_S,
            "retry_count": 1,
            "priority": 7,  # High priority for sensor data
        },
        "MEP_PUT": {
            "reliability": QoSLevel.RELIABLE,
            "max_latency_ms": TimingBudgets.MEP_PUT_MAX_LATENCY_MS,
            "max_jitter_ms": TimingBudgets.MEP_MAX_JITTER_MS,
            "timeout_s": 10.0,
            "retry_count": 2,
            "priority": 4,  # Medium-low priority
        },
        "MEP_QUERY": {
            "reliability": QoSLevel.RELIABLE,
            "max_latency_ms": TimingBudgets.MEP_QUERY_MAX_LATENCY_MS,
            "max_jitter_ms": TimingBudgets.MEP_MAX_JITTER_MS,
            "timeout_s": 15.0,
            "retry_count": 2,
            "priority": 6,  # Medium-high priority
        },
        "EAP": {
            "reliability": QoSLevel.RELIABLE,
            "max_latency_ms": TimingBudgets.EAP_MAX_LATENCY_MS,
            "max_jitter_ms": TimingBudgets.EAP_MAX_JITTER_MS,
            "timeout_s": TimingBudgets.EAP_SAFETY_TIMEOUT_S,
            "retry_count": 0,  # No retries for safety-critical actions
            "priority": 10,  # Highest priority
        },
    }
    
    # Transport-specific QoS mappings
    TRANSPORT_QOS_MAPPING = {
        "dds": {
            QoSLevel.BEST_EFFORT: {"reliability": "BEST_EFFORT", "durability": "VOLATILE"},
            QoSLevel.RELIABLE: {"reliability": "RELIABLE", "durability": "TRANSIENT_LOCAL"},
            QoSLevel.PERSISTENT: {"reliability": "RELIABLE", "durability": "PERSISTENT"},
        },
        "grpc": {
            QoSLevel.BEST_EFFORT: {"timeout": 5.0},
            QoSLevel.RELIABLE: {"timeout": 30.0, "retry_policy": "exponential_backoff"},
            QoSLevel.PERSISTENT: {"timeout": 60.0, "retry_policy": "exponential_backoff"},
        },
        "mqtt": {
            QoSLevel.BEST_EFFORT: {"qos": 0},
            QoSLevel.RELIABLE: {"qos": 1},
            QoSLevel.PERSISTENT: {"qos": 2},
        },
    }


class ConformanceProfiles:
    """
    QoS requirements for different ECPS conformance profiles.
    """
    
    EDGE_LITE = {
        "max_message_size_bytes": 64 * 1024,  # 64KB
        "max_concurrent_connections": 10,
        "supported_transports": ["dds"],
        "timing_multiplier": 2.0,  # Relaxed timing for edge devices
        "observability_enabled": False,
        "qos_overrides": {
            "MCP": {"max_latency_ms": TimingBudgets.MCP_MAX_LATENCY_MS * 2},
            "LTP": {"max_latency_ms": TimingBudgets.LTP_MAX_LATENCY_MS * 2},
        }
    }
    
    STANDARD = {
        "max_message_size_bytes": 1024 * 1024,  # 1MB
        "max_concurrent_connections": 100,
        "supported_transports": ["dds", "grpc"],
        "timing_multiplier": 1.0,  # Standard timing
        "observability_enabled": True,
        "qos_overrides": {}
    }
    
    CLOUD_FLEET = {
        "max_message_size_bytes": 16 * 1024 * 1024,  # 16MB
        "max_concurrent_connections": 1000,
        "supported_transports": ["dds", "grpc", "mqtt"],
        "timing_multiplier": 0.8,  # Tighter timing for cloud
        "observability_enabled": True,
        "qos_overrides": {
            "MCP": {"max_latency_ms": TimingBudgets.MCP_MAX_LATENCY_MS * 0.8},
            "MEP_QUERY": {"max_latency_ms": TimingBudgets.MEP_QUERY_MAX_LATENCY_MS * 0.8},
        }
    }


def get_qos_for_message_type(message_type: str, transport: str = "dds") -> Dict[str, Any]:
    """
    Get QoS parameters for a specific message type and transport.
    
    Args:
        message_type: Type of message ("MCP", "LTP", "MEP_PUT", "MEP_QUERY", "EAP")
        transport: Transport layer ("dds", "grpc", "mqtt")
        
    Returns:
        QoS parameters dictionary
    """
    if message_type not in QoSParameters.DEFAULT_QOS:
        raise ValueError(f"Unknown message type: {message_type}")
    
    # Get base QoS parameters
    qos = QoSParameters.DEFAULT_QOS[message_type].copy()
    
    # Apply transport-specific mappings
    if transport in QoSParameters.TRANSPORT_QOS_MAPPING:
        reliability_level = qos["reliability"]
        transport_qos = QoSParameters.TRANSPORT_QOS_MAPPING[transport].get(reliability_level, {})
        qos.update(transport_qos)
    
    return qos


def get_profile_qos(profile: str, message_type: str, transport: str = "dds") -> Dict[str, Any]:
    """
    Get QoS parameters for a specific conformance profile.
    
    Args:
        profile: Conformance profile ("edge-lite", "standard", "cloud-fleet")
        message_type: Type of message
        transport: Transport layer
        
    Returns:
        QoS parameters dictionary with profile-specific overrides
    """
    # Get base QoS
    qos = get_qos_for_message_type(message_type, transport)
    
    # Get profile configuration
    profile_config = None
    if profile == "edge-lite":
        profile_config = ConformanceProfiles.EDGE_LITE
    elif profile == "standard":
        profile_config = ConformanceProfiles.STANDARD
    elif profile == "cloud-fleet":
        profile_config = ConformanceProfiles.CLOUD_FLEET
    else:
        raise ValueError(f"Unknown profile: {profile}")
    
    # Apply timing multiplier
    timing_multiplier = profile_config["timing_multiplier"]
    if "max_latency_ms" in qos:
        qos["max_latency_ms"] *= timing_multiplier
    if "max_jitter_ms" in qos:
        qos["max_jitter_ms"] *= timing_multiplier
    if "timeout_s" in qos:
        qos["timeout_s"] *= timing_multiplier
    
    # Apply profile-specific overrides
    overrides = profile_config.get("qos_overrides", {}).get(message_type, {})
    qos.update(overrides)
    
    return qos


def validate_timing_budget(actual_latency_ms: float, message_type: str, profile: str = "standard") -> bool:
    """
    Validate if actual latency meets timing budget requirements.
    
    Args:
        actual_latency_ms: Measured latency in milliseconds
        message_type: Type of message
        profile: Conformance profile
        
    Returns:
        True if timing budget is met, False otherwise
    """
    qos = get_profile_qos(profile, message_type)
    max_latency = qos.get("max_latency_ms", float('inf'))
    
    return actual_latency_ms <= max_latency