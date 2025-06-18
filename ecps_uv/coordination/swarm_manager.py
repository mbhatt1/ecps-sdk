"""
Swarm Manager for ECPS-UV SDK.

This module provides swarm coordination capabilities for multi-robot systems,
including formation control, task allocation, and collective behavior.
"""

import asyncio
import logging
import math
import time
from typing import Any, Dict, List, Optional, Tuple, Set
from enum import Enum
from dataclasses import dataclass

from .a2a_coordinator import A2ACoordinator, AgentInfo, CoordinationTask, AgentRole

logger = logging.getLogger("ecps_uv.coordination.swarm")


class SwarmFormation(Enum):
    """Types of swarm formations."""
    LINE = "line"
    CIRCLE = "circle"
    GRID = "grid"
    TRIANGLE = "triangle"
    DIAMOND = "diamond"
    CUSTOM = "custom"


class SwarmBehavior(Enum):
    """Types of swarm behaviors."""
    FOLLOW_LEADER = "follow_leader"
    FLOCKING = "flocking"
    COVERAGE = "coverage"
    SEARCH_PATTERN = "search_pattern"
    FORMATION_KEEPING = "formation_keeping"


@dataclass
class Position:
    """3D position representation."""
    x: float
    y: float
    z: float = 0.0
    
    def distance_to(self, other: "Position") -> float:
        """Calculate Euclidean distance to another position."""
        return math.sqrt(
            (self.x - other.x) ** 2 +
            (self.y - other.y) ** 2 +
            (self.z - other.z) ** 2
        )
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to dictionary."""
        return {"x": self.x, "y": self.y, "z": self.z}
    
    @classmethod
    def from_dict(cls, data: Dict[str, float]) -> "Position":
        """Create from dictionary."""
        return cls(data["x"], data["y"], data.get("z", 0.0))


@dataclass
class SwarmAgent:
    """Extended agent information for swarm coordination."""
    agent_id: str
    position: Position
    velocity: Position
    role: AgentRole
    capabilities: List[str]
    formation_position: Optional[Position] = None
    target_position: Optional[Position] = None
    last_update: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "position": self.position.to_dict(),
            "velocity": self.velocity.to_dict(),
            "role": self.role.value,
            "capabilities": self.capabilities,
            "formation_position": self.formation_position.to_dict() if self.formation_position else None,
            "target_position": self.target_position.to_dict() if self.target_position else None,
            "last_update": self.last_update,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SwarmAgent":
        """Create from dictionary."""
        return cls(
            agent_id=data["agent_id"],
            position=Position.from_dict(data["position"]),
            velocity=Position.from_dict(data["velocity"]),
            role=AgentRole(data["role"]),
            capabilities=data["capabilities"],
            formation_position=Position.from_dict(data["formation_position"]) if data.get("formation_position") else None,
            target_position=Position.from_dict(data["target_position"]) if data.get("target_position") else None,
            last_update=data.get("last_update", time.time()),
        )


class SwarmManager:
    """
    Manager for swarm coordination and collective behavior.
    
    This class provides high-level coordination for multi-robot swarms,
    including formation control, task allocation, and collective behaviors.
    """
    
    def __init__(
        self,
        coordinator: A2ACoordinator,
        agent_id: str,
        initial_position: Position,
        is_leader: bool = False,
    ):
        """
        Initialize the swarm manager.
        
        Args:
            coordinator: A2A coordinator instance
            agent_id: Unique identifier for this agent
            initial_position: Initial position of this agent
            is_leader: Whether this agent is the swarm leader
        """
        self.coordinator = coordinator
        self.agent_id = agent_id
        self.is_leader = is_leader
        
        # Swarm state
        self.swarm_agents: Dict[str, SwarmAgent] = {}
        self.current_formation = SwarmFormation.CIRCLE
        self.current_behavior = SwarmBehavior.FORMATION_KEEPING
        self.formation_center = initial_position
        self.formation_scale = 5.0  # meters
        
        # This agent's state
        self.my_agent = SwarmAgent(
            agent_id=agent_id,
            position=initial_position,
            velocity=Position(0, 0, 0),
            role=AgentRole.LEADER if is_leader else AgentRole.FOLLOWER,
            capabilities=coordinator.capabilities,
            last_update=time.time(),
        )
        self.swarm_agents[agent_id] = self.my_agent
        
        # Swarm parameters
        self.max_velocity = 2.0  # m/s
        self.separation_distance = 2.0  # meters
        self.cohesion_radius = 10.0  # meters
        self.alignment_radius = 5.0  # meters
        
        # Control parameters
        self.separation_weight = 2.0
        self.cohesion_weight = 1.0
        self.alignment_weight = 1.5
        self.formation_weight = 3.0
        
        # Task management
        self.swarm_tasks: Dict[str, CoordinationTask] = {}
        
        # Register swarm-specific task handlers
        self._register_swarm_handlers()
    
    def _register_swarm_handlers(self):
        """Register handlers for swarm-specific tasks."""
        self.coordinator.register_task_handler("swarm_formation", self._handle_formation_task)
        self.coordinator.register_task_handler("swarm_movement", self._handle_movement_task)
        self.coordinator.register_task_handler("swarm_search", self._handle_search_task)
        self.coordinator.register_task_handler("swarm_coverage", self._handle_coverage_task)
    
    async def start(self):
        """Start the swarm manager."""
        # Start background tasks
        asyncio.create_task(self._swarm_control_loop())
        asyncio.create_task(self._position_broadcast_loop())
        
        # Subscribe to swarm-specific topics
        await self._setup_swarm_subscriptions()
        
        logger.info(f"Swarm manager started for agent {self.agent_id}")
    
    async def _setup_swarm_subscriptions(self):
        """Set up subscriptions for swarm coordination."""
        # Position updates
        await self.coordinator.transport.subscribe(
            "swarm/positions",
            self._handle_position_update,
            dict,
        )
        
        # Formation commands
        await self.coordinator.transport.subscribe(
            "swarm/formation",
            self._handle_formation_command,
            dict,
        )
        
        # Swarm commands
        await self.coordinator.transport.subscribe(
            "swarm/commands",
            self._handle_swarm_command,
            dict,
        )
    
    async def _swarm_control_loop(self):
        """Main control loop for swarm behavior."""
        while self.coordinator.is_running:
            try:
                # Update agent positions from known agents
                self._update_agent_positions()
                
                # Calculate desired velocity based on current behavior
                desired_velocity = self._calculate_desired_velocity()
                
                # Apply velocity limits
                desired_velocity = self._limit_velocity(desired_velocity)
                
                # Update position
                dt = 0.1  # 100ms update rate
                self.my_agent.position.x += desired_velocity.x * dt
                self.my_agent.position.y += desired_velocity.y * dt
                self.my_agent.position.z += desired_velocity.z * dt
                self.my_agent.velocity = desired_velocity
                self.my_agent.last_update = time.time()
                
                await asyncio.sleep(dt)
                
            except Exception as e:
                logger.error(f"Error in swarm control loop: {e}")
                await asyncio.sleep(1.0)
    
    async def _position_broadcast_loop(self):
        """Broadcast position updates to other agents."""
        while self.coordinator.is_running:
            try:
                # Broadcast position
                message = {
                    "type": "position_update",
                    "agent": self.my_agent.to_dict(),
                    "timestamp": time.time(),
                }
                
                await self.coordinator.transport.publish(
                    "swarm/positions",
                    message,
                )
                
                await asyncio.sleep(0.5)  # 2Hz broadcast rate
                
            except Exception as e:
                logger.error(f"Error in position broadcast loop: {e}")
                await asyncio.sleep(1.0)
    
    def _update_agent_positions(self):
        """Update agent positions from A2A coordinator."""
        for agent_id, agent_info in self.coordinator.known_agents.items():
            if agent_id != self.agent_id and "position" in agent_info.metadata:
                pos_data = agent_info.metadata["position"]
                position = Position.from_dict(pos_data)
                
                if agent_id in self.swarm_agents:
                    self.swarm_agents[agent_id].position = position
                    self.swarm_agents[agent_id].last_update = time.time()
                else:
                    # Create new swarm agent
                    self.swarm_agents[agent_id] = SwarmAgent(
                        agent_id=agent_id,
                        position=position,
                        velocity=Position(0, 0, 0),
                        role=AgentRole.FOLLOWER,
                        capabilities=agent_info.capabilities,
                        last_update=time.time(),
                    )
    
    def _calculate_desired_velocity(self) -> Position:
        """Calculate desired velocity based on current swarm behavior."""
        if self.current_behavior == SwarmBehavior.FORMATION_KEEPING:
            return self._calculate_formation_velocity()
        elif self.current_behavior == SwarmBehavior.FLOCKING:
            return self._calculate_flocking_velocity()
        elif self.current_behavior == SwarmBehavior.FOLLOW_LEADER:
            return self._calculate_follow_leader_velocity()
        else:
            return Position(0, 0, 0)
    
    def _calculate_formation_velocity(self) -> Position:
        """Calculate velocity to maintain formation."""
        if not self.my_agent.formation_position:
            self._assign_formation_positions()
        
        if self.my_agent.formation_position:
            # Move towards formation position
            dx = self.my_agent.formation_position.x - self.my_agent.position.x
            dy = self.my_agent.formation_position.y - self.my_agent.position.y
            dz = self.my_agent.formation_position.z - self.my_agent.position.z
            
            # Proportional control
            kp = 1.0
            return Position(dx * kp, dy * kp, dz * kp)
        
        return Position(0, 0, 0)
    
    def _calculate_flocking_velocity(self) -> Position:
        """Calculate velocity using flocking algorithm (boids)."""
        separation = self._calculate_separation()
        cohesion = self._calculate_cohesion()
        alignment = self._calculate_alignment()
        
        # Combine forces
        velocity = Position(
            separation.x * self.separation_weight +
            cohesion.x * self.cohesion_weight +
            alignment.x * self.alignment_weight,
            
            separation.y * self.separation_weight +
            cohesion.y * self.cohesion_weight +
            alignment.y * self.alignment_weight,
            
            separation.z * self.separation_weight +
            cohesion.z * self.cohesion_weight +
            alignment.z * self.alignment_weight,
        )
        
        return velocity
    
    def _calculate_separation(self) -> Position:
        """Calculate separation force to avoid crowding."""
        force = Position(0, 0, 0)
        count = 0
        
        for agent in self.swarm_agents.values():
            if agent.agent_id != self.agent_id:
                distance = self.my_agent.position.distance_to(agent.position)
                if 0 < distance < self.separation_distance:
                    # Calculate repulsion force
                    dx = self.my_agent.position.x - agent.position.x
                    dy = self.my_agent.position.y - agent.position.y
                    dz = self.my_agent.position.z - agent.position.z
                    
                    # Normalize and weight by distance
                    if distance > 0:
                        force.x += dx / distance
                        force.y += dy / distance
                        force.z += dz / distance
                        count += 1
        
        if count > 0:
            force.x /= count
            force.y /= count
            force.z /= count
        
        return force
    
    def _calculate_cohesion(self) -> Position:
        """Calculate cohesion force to move towards center of mass."""
        center = Position(0, 0, 0)
        count = 0
        
        for agent in self.swarm_agents.values():
            if agent.agent_id != self.agent_id:
                distance = self.my_agent.position.distance_to(agent.position)
                if distance < self.cohesion_radius:
                    center.x += agent.position.x
                    center.y += agent.position.y
                    center.z += agent.position.z
                    count += 1
        
        if count > 0:
            center.x /= count
            center.y /= count
            center.z /= count
            
            # Move towards center
            return Position(
                center.x - self.my_agent.position.x,
                center.y - self.my_agent.position.y,
                center.z - self.my_agent.position.z,
            )
        
        return Position(0, 0, 0)
    
    def _calculate_alignment(self) -> Position:
        """Calculate alignment force to match velocity of neighbors."""
        avg_velocity = Position(0, 0, 0)
        count = 0
        
        for agent in self.swarm_agents.values():
            if agent.agent_id != self.agent_id:
                distance = self.my_agent.position.distance_to(agent.position)
                if distance < self.alignment_radius:
                    avg_velocity.x += agent.velocity.x
                    avg_velocity.y += agent.velocity.y
                    avg_velocity.z += agent.velocity.z
                    count += 1
        
        if count > 0:
            avg_velocity.x /= count
            avg_velocity.y /= count
            avg_velocity.z /= count
        
        return avg_velocity
    
    def _calculate_follow_leader_velocity(self) -> Position:
        """Calculate velocity to follow the swarm leader."""
        leader = self._find_leader()
        if leader and leader.agent_id != self.agent_id:
            # Move towards leader with offset
            offset_distance = 3.0  # meters behind leader
            
            dx = leader.position.x - self.my_agent.position.x
            dy = leader.position.y - self.my_agent.position.y
            
            # Maintain offset distance
            distance = math.sqrt(dx*dx + dy*dy)
            if distance > offset_distance:
                return Position(dx * 0.5, dy * 0.5, 0)
        
        return Position(0, 0, 0)
    
    def _find_leader(self) -> Optional[SwarmAgent]:
        """Find the swarm leader."""
        for agent in self.swarm_agents.values():
            if agent.role == AgentRole.LEADER:
                return agent
        return None
    
    def _limit_velocity(self, velocity: Position) -> Position:
        """Limit velocity to maximum allowed."""
        magnitude = math.sqrt(velocity.x**2 + velocity.y**2 + velocity.z**2)
        if magnitude > self.max_velocity:
            scale = self.max_velocity / magnitude
            return Position(
                velocity.x * scale,
                velocity.y * scale,
                velocity.z * scale,
            )
        return velocity
    
    def _assign_formation_positions(self):
        """Assign formation positions to all agents."""
        agents = list(self.swarm_agents.values())
        n_agents = len(agents)
        
        if self.current_formation == SwarmFormation.CIRCLE:
            self._assign_circle_formation(agents, n_agents)
        elif self.current_formation == SwarmFormation.LINE:
            self._assign_line_formation(agents, n_agents)
        elif self.current_formation == SwarmFormation.GRID:
            self._assign_grid_formation(agents, n_agents)
    
    def _assign_circle_formation(self, agents: List[SwarmAgent], n_agents: int):
        """Assign positions in a circular formation."""
        for i, agent in enumerate(agents):
            angle = 2 * math.pi * i / n_agents
            x = self.formation_center.x + self.formation_scale * math.cos(angle)
            y = self.formation_center.y + self.formation_scale * math.sin(angle)
            z = self.formation_center.z
            
            agent.formation_position = Position(x, y, z)
    
    def _assign_line_formation(self, agents: List[SwarmAgent], n_agents: int):
        """Assign positions in a line formation."""
        spacing = self.formation_scale / max(1, n_agents - 1)
        start_x = self.formation_center.x - self.formation_scale / 2
        
        for i, agent in enumerate(agents):
            x = start_x + i * spacing
            y = self.formation_center.y
            z = self.formation_center.z
            
            agent.formation_position = Position(x, y, z)
    
    def _assign_grid_formation(self, agents: List[SwarmAgent], n_agents: int):
        """Assign positions in a grid formation."""
        grid_size = math.ceil(math.sqrt(n_agents))
        spacing = self.formation_scale / max(1, grid_size - 1)
        start_x = self.formation_center.x - self.formation_scale / 2
        start_y = self.formation_center.y - self.formation_scale / 2
        
        for i, agent in enumerate(agents):
            row = i // grid_size
            col = i % grid_size
            
            x = start_x + col * spacing
            y = start_y + row * spacing
            z = self.formation_center.z
            
            agent.formation_position = Position(x, y, z)
    
    async def _handle_position_update(self, message: Dict[str, Any]):
        """Handle position updates from other agents."""
        try:
            if message.get("type") == "position_update":
                agent_data = message.get("agent", {})
                agent = SwarmAgent.from_dict(agent_data)
                
                if agent.agent_id != self.agent_id:
                    self.swarm_agents[agent.agent_id] = agent
                    
        except Exception as e:
            logger.error(f"Error handling position update: {e}")
    
    async def _handle_formation_command(self, message: Dict[str, Any]):
        """Handle formation change commands."""
        try:
            formation_type = message.get("formation")
            if formation_type:
                self.current_formation = SwarmFormation(formation_type)
                self.formation_center = Position.from_dict(message.get("center", self.formation_center.to_dict()))
                self.formation_scale = message.get("scale", self.formation_scale)
                
                # Reassign formation positions
                self._assign_formation_positions()
                
                logger.info(f"Formation changed to {self.current_formation}")
                
        except Exception as e:
            logger.error(f"Error handling formation command: {e}")
    
    async def _handle_swarm_command(self, message: Dict[str, Any]):
        """Handle general swarm commands."""
        try:
            command = message.get("command")
            
            if command == "change_behavior":
                behavior = message.get("behavior")
                if behavior:
                    self.current_behavior = SwarmBehavior(behavior)
                    logger.info(f"Behavior changed to {self.current_behavior}")
            
            elif command == "move_formation":
                new_center = message.get("center")
                if new_center:
                    self.formation_center = Position.from_dict(new_center)
                    self._assign_formation_positions()
                    
        except Exception as e:
            logger.error(f"Error handling swarm command: {e}")
    
    async def change_formation(self, formation: SwarmFormation, center: Position, scale: float = 5.0):
        """Change the swarm formation."""
        if self.is_leader:
            message = {
                "type": "formation_command",
                "formation": formation.value,
                "center": center.to_dict(),
                "scale": scale,
                "timestamp": time.time(),
            }
            
            await self.coordinator.transport.publish("swarm/formation", message)
    
    async def change_behavior(self, behavior: SwarmBehavior):
        """Change the swarm behavior."""
        if self.is_leader:
            message = {
                "type": "swarm_command",
                "command": "change_behavior",
                "behavior": behavior.value,
                "timestamp": time.time(),
            }
            
            await self.coordinator.transport.publish("swarm/commands", message)
    
    async def move_formation(self, new_center: Position):
        """Move the formation to a new center position."""
        if self.is_leader:
            message = {
                "type": "swarm_command",
                "command": "move_formation",
                "center": new_center.to_dict(),
                "timestamp": time.time(),
            }
            
            await self.coordinator.transport.publish("swarm/commands", message)
    
    # Task handlers
    async def _handle_formation_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle formation change task."""
        params = task.parameters
        formation = SwarmFormation(params.get("formation", "circle"))
        center = Position.from_dict(params.get("center", {"x": 0, "y": 0, "z": 0}))
        scale = params.get("scale", 5.0)
        
        await self.change_formation(formation, center, scale)
        
        return {"status": "formation_changed", "formation": formation.value}
    
    async def _handle_movement_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle movement task."""
        params = task.parameters
        target = Position.from_dict(params.get("target", {"x": 0, "y": 0, "z": 0}))
        
        await self.move_formation(target)
        
        return {"status": "movement_started", "target": target.to_dict()}
    
    async def _handle_search_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle search pattern task."""
        # Implement search pattern behavior
        await self.change_behavior(SwarmBehavior.SEARCH_PATTERN)
        
        return {"status": "search_started"}
    
    async def _handle_coverage_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle area coverage task."""
        # Implement coverage behavior
        await self.change_behavior(SwarmBehavior.COVERAGE)
        
        return {"status": "coverage_started"}
    
    def get_swarm_status(self) -> Dict[str, Any]:
        """Get current swarm status."""
        return {
            "agent_id": self.agent_id,
            "is_leader": self.is_leader,
            "formation": self.current_formation.value,
            "behavior": self.current_behavior.value,
            "formation_center": self.formation_center.to_dict(),
            "formation_scale": self.formation_scale,
            "agent_count": len(self.swarm_agents),
            "agents": {aid: agent.to_dict() for aid, agent in self.swarm_agents.items()},
        }