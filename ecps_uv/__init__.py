"""
ECPS-UV: UV-based Python SDK for the Embodied Cognition Protocol Stack (ECPS)

This package provides a complete implementation of the ECPS v1.0 specification
using UV for high-performance asynchronous I/O.

The SDK is organized according to the ECPS layered model:
- L2: Transport (DDS/RTPS, gRPC/HTTP-2, MQTT 5)
- L3: Serialization & Event Envelope (Protocol Buffers, CloudEvents 1.0)
- L4: Observability (OpenTelemetry)
- L5: Perception Data (ROS 2 sensor_msgs/*, LTP)
- L6: Cognition (MCP, MEP)
- L7: Actuation (EAP)

ECPS allows for different conformance profiles:
- Edge-Lite Profile
- Standard Profile
- Cloud-Fleet Profile
"""

__version__ = "0.1.0"

# Core components
from ecps_uv.core import ECPSClient, ECPSServer, ECPSConfig

# Transport Layer (L2)
from ecps_uv.transport import DDSTransport, GRPCTransport, MQTTTransport

# Serialization Layer (L3)
from ecps_uv.serialization import ProtobufSerializer, CloudEventsWrapper

# Observability Layer (L4)
from ecps_uv.observability import ECPSTelemetry

# Perception Data Layer (L5)
from ecps_uv.perception import LTPHandler

# Cognition Layer (L6)
from ecps_uv.cognition import MCPHandler, MEPClient, MEPServer

# Actuation Layer (L7)
from ecps_uv.actuation import EAPHandler

# Profiles
from ecps_uv.core import EdgeLiteProfile, StandardProfile, CloudFleetProfile