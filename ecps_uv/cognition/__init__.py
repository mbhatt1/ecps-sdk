"""
Cognition Layer (L6) for ECPS.

This package provides components for the Cognition Layer, including:
- Model Context Protocol (MCP) for delivering prompts to AI agents
- Memory Exchange Protocol (MEP) for storing and querying memory embeddings
"""

from ecps_uv.cognition.mcp import MCPHandler
from ecps_uv.cognition.mep import MEPClient, MEPServer

__all__ = ["MCPHandler", "MEPClient", "MEPServer"]