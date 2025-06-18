"""
Agent-to-Agent (A2A) Coordination Layer for ECPS-UV SDK.

This module provides coordination capabilities for multi-agent systems,
including swarm coordination, task distribution, and consensus mechanisms.
"""

from .a2a_coordinator import A2ACoordinator
from .swarm_manager import SwarmManager
from .consensus import ConsensusProtocol
from .task_distributor import TaskDistributor

__all__ = [
    "A2ACoordinator",
    "SwarmManager", 
    "ConsensusProtocol",
    "TaskDistributor",
]