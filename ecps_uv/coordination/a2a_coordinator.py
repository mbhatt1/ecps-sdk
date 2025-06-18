"""
Agent-to-Agent (A2A) Coordinator for ECPS-UV SDK.

This module provides the main coordination interface for multi-agent systems,
enabling agents to discover, communicate, and coordinate with each other.
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Callable
from enum import Enum

from ecps_uv.qos_constants import get_qos_for_message_type, TimingBudgets

logger = logging.getLogger("ecps_uv.coordination.a2a")


class AgentRole(Enum):
    """Roles that agents can take in coordination."""
    LEADER = "leader"
    FOLLOWER = "follower"
    COORDINATOR = "coordinator"
    WORKER = "worker"
    OBSERVER = "observer"


class CoordinationState(Enum):
    """States of coordination process."""
    DISCOVERING = "discovering"
    FORMING = "forming"
    COORDINATING = "coordinating"
    EXECUTING = "executing"
    COMPLETED = "completed"
    FAILED = "failed"


class AgentInfo:
    """Information about an agent in the coordination system."""
    
    def __init__(
        self,
        agent_id: str,
        role: AgentRole,
        capabilities: List[str],
        location: Optional[Dict[str, float]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.agent_id = agent_id
        self.role = role
        self.capabilities = capabilities
        self.location = location or {}
        self.metadata = metadata or {}
        self.last_seen = time.time()
        self.status = "active"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "agent_id": self.agent_id,
            "role": self.role.value,
            "capabilities": self.capabilities,
            "location": self.location,
            "metadata": self.metadata,
            "last_seen": self.last_seen,
            "status": self.status,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentInfo":
        """Create from dictionary."""
        agent = cls(
            agent_id=data["agent_id"],
            role=AgentRole(data["role"]),
            capabilities=data["capabilities"],
            location=data.get("location"),
            metadata=data.get("metadata"),
        )
        agent.last_seen = data.get("last_seen", time.time())
        agent.status = data.get("status", "active")
        return agent


class CoordinationTask:
    """A task that requires coordination between multiple agents."""
    
    def __init__(
        self,
        task_id: str,
        task_type: str,
        required_capabilities: List[str],
        priority: int = 5,
        deadline: Optional[float] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ):
        self.task_id = task_id
        self.task_type = task_type
        self.required_capabilities = required_capabilities
        self.priority = priority
        self.deadline = deadline
        self.parameters = parameters or {}
        self.created_at = time.time()
        self.assigned_agents: Set[str] = set()
        self.state = CoordinationState.DISCOVERING
        self.result: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "required_capabilities": self.required_capabilities,
            "priority": self.priority,
            "deadline": self.deadline,
            "parameters": self.parameters,
            "created_at": self.created_at,
            "assigned_agents": list(self.assigned_agents),
            "state": self.state.value,
            "result": self.result,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CoordinationTask":
        """Create from dictionary."""
        task = cls(
            task_id=data["task_id"],
            task_type=data["task_type"],
            required_capabilities=data["required_capabilities"],
            priority=data.get("priority", 5),
            deadline=data.get("deadline"),
            parameters=data.get("parameters"),
        )
        task.created_at = data.get("created_at", time.time())
        task.assigned_agents = set(data.get("assigned_agents", []))
        task.state = CoordinationState(data.get("state", "discovering"))
        task.result = data.get("result")
        return task


class A2ACoordinator:
    """
    Main coordinator for Agent-to-Agent communication and coordination.
    
    This class manages agent discovery, task coordination, and communication
    between multiple agents in a distributed system.
    """
    
    def __init__(
        self,
        agent_id: str,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
        role: AgentRole = AgentRole.WORKER,
        capabilities: Optional[List[str]] = None,
    ):
        """
        Initialize the A2A coordinator.
        
        Args:
            agent_id: Unique identifier for this agent
            transport: Transport layer for communication
            serializer: Serializer for message encoding/decoding
            telemetry: Telemetry provider for observability
            role: Role of this agent in coordination
            capabilities: List of capabilities this agent provides
        """
        self.agent_id = agent_id
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
        self.role = role
        self.capabilities = capabilities or []
        
        # Agent registry
        self.known_agents: Dict[str, AgentInfo] = {}
        self.agent_info = AgentInfo(agent_id, role, self.capabilities)
        
        # Task management
        self.active_tasks: Dict[str, CoordinationTask] = {}
        self.task_handlers: Dict[str, Callable] = {}
        
        # Coordination state
        self.coordination_groups: Dict[str, Set[str]] = {}  # group_id -> agent_ids
        self.is_running = False
        
        # Configuration
        self.discovery_interval = 30.0  # seconds
        self.heartbeat_interval = 10.0  # seconds
        self.agent_timeout = 60.0  # seconds
        
        # Topics for communication
        self.discovery_topic = "a2a/discovery"
        self.heartbeat_topic = "a2a/heartbeat"
        self.coordination_topic = "a2a/coordination"
        self.task_topic = "a2a/tasks"
    
    async def start(self):
        """Start the A2A coordinator."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Subscribe to coordination topics
        await self._setup_subscriptions()
        
        # Start background tasks
        asyncio.create_task(self._discovery_loop())
        asyncio.create_task(self._heartbeat_loop())
        asyncio.create_task(self._cleanup_loop())
        
        # Announce presence
        await self._announce_presence()
        
        logger.info(f"A2A Coordinator started for agent {self.agent_id}")
    
    async def stop(self):
        """Stop the A2A coordinator."""
        self.is_running = False
        
        # Send departure message
        await self._announce_departure()
        
        logger.info(f"A2A Coordinator stopped for agent {self.agent_id}")
    
    async def _setup_subscriptions(self):
        """Set up subscriptions to coordination topics."""
        # Discovery messages
        await self.transport.subscribe(
            self.discovery_topic,
            self._handle_discovery_message,
            dict,  # Generic message type
            get_qos_for_message_type("MCP", "mqtt")
        )
        
        # Heartbeat messages
        await self.transport.subscribe(
            self.heartbeat_topic,
            self._handle_heartbeat_message,
            dict,
            get_qos_for_message_type("LTP", "mqtt")
        )
        
        # Coordination messages
        await self.transport.subscribe(
            self.coordination_topic,
            self._handle_coordination_message,
            dict,
            get_qos_for_message_type("MCP", "mqtt")
        )
        
        # Task messages
        await self.transport.subscribe(
            self.task_topic,
            self._handle_task_message,
            dict,
            get_qos_for_message_type("MCP", "mqtt")
        )
    
    async def _discovery_loop(self):
        """Periodic discovery of other agents."""
        while self.is_running:
            try:
                await self._announce_presence()
                await asyncio.sleep(self.discovery_interval)
            except Exception as e:
                logger.error(f"Error in discovery loop: {e}")
                await asyncio.sleep(5.0)
    
    async def _heartbeat_loop(self):
        """Periodic heartbeat to maintain presence."""
        while self.is_running:
            try:
                await self._send_heartbeat()
                await asyncio.sleep(self.heartbeat_interval)
            except Exception as e:
                logger.error(f"Error in heartbeat loop: {e}")
                await asyncio.sleep(5.0)
    
    async def _cleanup_loop(self):
        """Periodic cleanup of stale agents and tasks."""
        while self.is_running:
            try:
                current_time = time.time()
                
                # Remove stale agents
                stale_agents = [
                    agent_id for agent_id, agent_info in self.known_agents.items()
                    if current_time - agent_info.last_seen > self.agent_timeout
                ]
                
                for agent_id in stale_agents:
                    logger.info(f"Removing stale agent: {agent_id}")
                    del self.known_agents[agent_id]
                
                # Check for expired tasks
                expired_tasks = [
                    task_id for task_id, task in self.active_tasks.items()
                    if task.deadline and current_time > task.deadline
                ]
                
                for task_id in expired_tasks:
                    logger.warning(f"Task {task_id} expired")
                    task = self.active_tasks[task_id]
                    task.state = CoordinationState.FAILED
                    await self._notify_task_completion(task)
                
                await asyncio.sleep(30.0)  # Cleanup every 30 seconds
                
            except Exception as e:
                logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(5.0)
    
    async def _announce_presence(self):
        """Announce this agent's presence to other agents."""
        message = {
            "type": "discovery",
            "agent_info": self.agent_info.to_dict(),
            "timestamp": time.time(),
        }
        
        await self.transport.publish(
            self.discovery_topic,
            message,
            get_qos_for_message_type("MCP", "mqtt")
        )
    
    async def _announce_departure(self):
        """Announce this agent's departure."""
        message = {
            "type": "departure",
            "agent_id": self.agent_id,
            "timestamp": time.time(),
        }
        
        await self.transport.publish(
            self.discovery_topic,
            message,
            get_qos_for_message_type("MCP", "mqtt")
        )
    
    async def _send_heartbeat(self):
        """Send heartbeat to maintain presence."""
        message = {
            "type": "heartbeat",
            "agent_id": self.agent_id,
            "status": "active",
            "timestamp": time.time(),
        }
        
        await self.transport.publish(
            self.heartbeat_topic,
            message,
            get_qos_for_message_type("LTP", "mqtt")
        )
    
    async def _handle_discovery_message(self, message: Dict[str, Any]):
        """Handle discovery messages from other agents."""
        try:
            msg_type = message.get("type")
            
            if msg_type == "discovery":
                agent_data = message.get("agent_info", {})
                agent_info = AgentInfo.from_dict(agent_data)
                
                # Don't add ourselves
                if agent_info.agent_id != self.agent_id:
                    self.known_agents[agent_info.agent_id] = agent_info
                    logger.debug(f"Discovered agent: {agent_info.agent_id}")
            
            elif msg_type == "departure":
                agent_id = message.get("agent_id")
                if agent_id and agent_id in self.known_agents:
                    del self.known_agents[agent_id]
                    logger.debug(f"Agent departed: {agent_id}")
                    
        except Exception as e:
            logger.error(f"Error handling discovery message: {e}")
    
    async def _handle_heartbeat_message(self, message: Dict[str, Any]):
        """Handle heartbeat messages from other agents."""
        try:
            agent_id = message.get("agent_id")
            if agent_id and agent_id in self.known_agents:
                self.known_agents[agent_id].last_seen = time.time()
                self.known_agents[agent_id].status = message.get("status", "active")
                
        except Exception as e:
            logger.error(f"Error handling heartbeat message: {e}")
    
    async def _handle_coordination_message(self, message: Dict[str, Any]):
        """Handle coordination messages."""
        try:
            msg_type = message.get("type")
            
            if msg_type == "task_proposal":
                await self._handle_task_proposal(message)
            elif msg_type == "task_acceptance":
                await self._handle_task_acceptance(message)
            elif msg_type == "task_rejection":
                await self._handle_task_rejection(message)
            elif msg_type == "coordination_request":
                await self._handle_coordination_request(message)
                
        except Exception as e:
            logger.error(f"Error handling coordination message: {e}")
    
    async def _handle_task_message(self, message: Dict[str, Any]):
        """Handle task-related messages."""
        try:
            msg_type = message.get("type")
            
            if msg_type == "task_assignment":
                await self._handle_task_assignment(message)
            elif msg_type == "task_update":
                await self._handle_task_update(message)
            elif msg_type == "task_completion":
                await self._handle_task_completion(message)
                
        except Exception as e:
            logger.error(f"Error handling task message: {e}")
    
    async def create_coordination_task(
        self,
        task_type: str,
        required_capabilities: List[str],
        priority: int = 5,
        deadline: Optional[float] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Create a new coordination task.
        
        Args:
            task_type: Type of task to coordinate
            required_capabilities: Capabilities required for the task
            priority: Task priority (1-10, higher is more important)
            deadline: Optional deadline timestamp
            parameters: Task-specific parameters
            
        Returns:
            Task ID
        """
        task_id = str(uuid.uuid4())
        task = CoordinationTask(
            task_id=task_id,
            task_type=task_type,
            required_capabilities=required_capabilities,
            priority=priority,
            deadline=deadline,
            parameters=parameters,
        )
        
        self.active_tasks[task_id] = task
        
        # Find suitable agents
        suitable_agents = self._find_suitable_agents(required_capabilities)
        
        if not suitable_agents:
            logger.warning(f"No suitable agents found for task {task_id}")
            task.state = CoordinationState.FAILED
            return task_id
        
        # Send task proposals
        await self._send_task_proposals(task, suitable_agents)
        
        return task_id
    
    def _find_suitable_agents(self, required_capabilities: List[str]) -> List[str]:
        """Find agents that have the required capabilities."""
        suitable_agents = []
        
        for agent_id, agent_info in self.known_agents.items():
            if agent_info.status == "active":
                # Check if agent has all required capabilities
                if all(cap in agent_info.capabilities for cap in required_capabilities):
                    suitable_agents.append(agent_id)
        
        return suitable_agents
    
    async def _send_task_proposals(self, task: CoordinationTask, agent_ids: List[str]):
        """Send task proposals to suitable agents."""
        message = {
            "type": "task_proposal",
            "task": task.to_dict(),
            "proposer": self.agent_id,
            "timestamp": time.time(),
        }
        
        for agent_id in agent_ids:
            # Send to specific agent
            agent_topic = f"{self.coordination_topic}/{agent_id}"
            await self.transport.publish(
                agent_topic,
                message,
                get_qos_for_message_type("MCP", "mqtt")
            )
    
    async def _handle_task_proposal(self, message: Dict[str, Any]):
        """Handle incoming task proposals."""
        task_data = message.get("task", {})
        task = CoordinationTask.from_dict(task_data)
        proposer = message.get("proposer")
        
        # Check if we can handle this task
        can_handle = all(cap in self.capabilities for cap in task.required_capabilities)
        
        response_type = "task_acceptance" if can_handle else "task_rejection"
        response = {
            "type": response_type,
            "task_id": task.task_id,
            "agent_id": self.agent_id,
            "timestamp": time.time(),
        }
        
        if can_handle:
            response["estimated_duration"] = self._estimate_task_duration(task)
        
        # Send response back to proposer
        proposer_topic = f"{self.coordination_topic}/{proposer}"
        await self.transport.publish(
            proposer_topic,
            response,
            get_qos_for_message_type("MCP", "mqtt")
        )
    
    def _estimate_task_duration(self, task: CoordinationTask) -> float:
        """Estimate how long a task will take to complete."""
        # Simple estimation based on task type
        base_duration = {
            "navigation": 30.0,
            "manipulation": 60.0,
            "perception": 10.0,
            "communication": 5.0,
        }.get(task.task_type, 30.0)
        
        # Adjust based on complexity
        complexity_factor = len(task.required_capabilities) * 0.5
        return base_duration * (1.0 + complexity_factor)
    
    async def _handle_task_acceptance(self, message: Dict[str, Any]):
        """Handle task acceptance from agents."""
        task_id = message.get("task_id")
        agent_id = message.get("agent_id")
        
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            task.assigned_agents.add(agent_id)
            
            # If we have enough agents, start coordination
            if len(task.assigned_agents) >= len(task.required_capabilities):
                task.state = CoordinationState.FORMING
                await self._start_task_coordination(task)
    
    async def _handle_task_rejection(self, message: Dict[str, Any]):
        """Handle task rejection from agents."""
        task_id = message.get("task_id")
        
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            # Could implement fallback strategies here
            logger.debug(f"Task {task_id} rejected by agent {message.get('agent_id')}")
    
    async def _start_task_coordination(self, task: CoordinationTask):
        """Start coordinating the execution of a task."""
        task.state = CoordinationState.COORDINATING
        
        # Send coordination instructions to assigned agents
        coordination_message = {
            "type": "task_assignment",
            "task": task.to_dict(),
            "coordinator": self.agent_id,
            "timestamp": time.time(),
        }
        
        for agent_id in task.assigned_agents:
            agent_topic = f"{self.task_topic}/{agent_id}"
            await self.transport.publish(
                agent_topic,
                coordination_message,
                get_qos_for_message_type("MCP", "mqtt")
            )
        
        task.state = CoordinationState.EXECUTING
    
    async def _handle_task_assignment(self, message: Dict[str, Any]):
        """Handle task assignment from coordinator."""
        task_data = message.get("task", {})
        task = CoordinationTask.from_dict(task_data)
        coordinator = message.get("coordinator")
        
        # Execute the task if we have a handler
        if task.task_type in self.task_handlers:
            handler = self.task_handlers[task.task_type]
            try:
                result = await handler(task)
                
                # Send completion notification
                completion_message = {
                    "type": "task_completion",
                    "task_id": task.task_id,
                    "agent_id": self.agent_id,
                    "result": result,
                    "success": True,
                    "timestamp": time.time(),
                }
                
            except Exception as e:
                logger.error(f"Error executing task {task.task_id}: {e}")
                completion_message = {
                    "type": "task_completion",
                    "task_id": task.task_id,
                    "agent_id": self.agent_id,
                    "error": str(e),
                    "success": False,
                    "timestamp": time.time(),
                }
            
            # Send to coordinator
            coordinator_topic = f"{self.task_topic}/{coordinator}"
            await self.transport.publish(
                coordinator_topic,
                completion_message,
                get_qos_for_message_type("MCP", "mqtt")
            )
    
    async def _handle_task_completion(self, message: Dict[str, Any]):
        """Handle task completion notifications."""
        task_id = message.get("task_id")
        agent_id = message.get("agent_id")
        success = message.get("success", False)
        
        if task_id in self.active_tasks:
            task = self.active_tasks[task_id]
            
            if success:
                result = message.get("result")
                if not task.result:
                    task.result = {}
                task.result[agent_id] = result
                
                # Check if all agents have completed
                if len(task.result) >= len(task.assigned_agents):
                    task.state = CoordinationState.COMPLETED
                    await self._notify_task_completion(task)
            else:
                error = message.get("error")
                logger.error(f"Task {task_id} failed on agent {agent_id}: {error}")
                task.state = CoordinationState.FAILED
                await self._notify_task_completion(task)
    
    async def _notify_task_completion(self, task: CoordinationTask):
        """Notify about task completion."""
        logger.info(f"Task {task.task_id} completed with state: {task.state}")
        
        # Could send notifications to interested parties
        # For now, just log the completion
        
        # Clean up completed task
        if task.task_id in self.active_tasks:
            del self.active_tasks[task.task_id]
    
    def register_task_handler(self, task_type: str, handler: Callable):
        """Register a handler for a specific task type."""
        self.task_handlers[task_type] = handler
        
        # Add capability if not already present
        if task_type not in self.capabilities:
            self.capabilities.append(task_type)
            self.agent_info.capabilities = self.capabilities
    
    def get_known_agents(self) -> Dict[str, AgentInfo]:
        """Get all known agents."""
        return self.known_agents.copy()
    
    def get_active_tasks(self) -> Dict[str, CoordinationTask]:
        """Get all active tasks."""
        return self.active_tasks.copy()
    
    async def _handle_coordination_request(self, message: Dict[str, Any]):
        """Handle general coordination requests."""
        # Placeholder for future coordination protocols
        pass