"""
Cognition Layer (L6) for ECPS.

This package provides components for the Cognition Layer, including:
- Unified ECPS Protocol (UEP) consolidating ALL ECPS protocols into a single API
- Model Context Protocol (MCP) for delivering prompts to AI agents (legacy)
- Memory Exchange Protocol (MEP) for storing and querying memory embeddings (legacy)

The UEP handler consolidates:
- MCP (Model Context Protocol) for AI prompts
- MEP (Memory Exchange Protocol) for memory storage/retrieval
- EAP (Event Action Protocol) for actuation/actions
- LTP (Latent Tensor Protocol) for perception data
- A2A coordination for agent-to-agent communication
- Trust and security operations
- Telemetry and observability
"""

from ecps_uv.cognition.unified import UEPHandler, UCPHandler  # UCPHandler is alias for backward compatibility
from ecps_uv.cognition.mcp import MCPHandler
from ecps_uv.cognition.mep import MEPClient, MEPServer

__all__ = ["UEPHandler", "UCPHandler", "MCPHandler", "MEPClient", "MEPServer"]