"""
Task Distributor for ECPS-UV SDK.

This module provides task distribution and load balancing capabilities
for multi-agent systems, including task scheduling and resource allocation.
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple
from enum import Enum
from dataclasses import dataclass
from heapq import heappush, heappop

from .a2a_coordinator import AgentInfo, CoordinationTask, AgentRole

logger = logging.getLogger("ecps_uv.coordination.task_distributor")


class TaskPriority(Enum):
    """Task priority levels."""
    CRITICAL = 1
    HIGH = 2
    NORMAL = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SchedulingStrategy(Enum):
    """Task scheduling strategies."""
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    CAPABILITY_BASED = "capability_based"
    PRIORITY_FIRST = "priority_first"
    DEADLINE_FIRST = "deadline_first"


@dataclass
class TaskAssignment:
    """Task assignment to an agent."""
    task_id: str
    agent_id: str
    assigned_at: float
    estimated_duration: float
    actual_start_time: Optional[float] = None
    actual_end_time: Optional[float] = None
    status: TaskStatus = TaskStatus.ASSIGNED
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "agent_id": self.agent_id,
            "assigned_at": self.assigned_at,
            "estimated_duration": self.estimated_duration,
            "actual_start_time": self.actual_start_time,
            "actual_end_time": self.actual_end_time,
            "status": self.status.value,
            "result": self.result,
            "error": self.error,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskAssignment":
        """Create from dictionary."""
        assignment = cls(
            task_id=data["task_id"],
            agent_id=data["agent_id"],
            assigned_at=data["assigned_at"],
            estimated_duration=data["estimated_duration"],
            actual_start_time=data.get("actual_start_time"),
            actual_end_time=data.get("actual_end_time"),
            status=TaskStatus(data.get("status", "assigned")),
            result=data.get("result"),
            error=data.get("error"),
        )
        return assignment


@dataclass
class AgentLoad:
    """Agent workload information."""
    agent_id: str
    current_tasks: int
    total_estimated_time: float
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_update: float = 0.0
    
    def load_score(self) -> float:
        """Calculate overall load score (0.0 = no load, 1.0 = fully loaded)."""
        task_load = min(self.current_tasks / 10.0, 1.0)  # Assume max 10 concurrent tasks
        time_load = min(self.total_estimated_time / 3600.0, 1.0)  # Assume max 1 hour queue
        resource_load = (self.cpu_usage + self.memory_usage) / 2.0
        
        return (task_load + time_load + resource_load) / 3.0


class TaskQueue:
    """Priority queue for tasks."""
    
    def __init__(self):
        self._queue = []
        self._index = 0
    
    def put(self, task: CoordinationTask, priority: int):
        """Add task to queue with priority."""
        heappush(self._queue, (priority, self._index, task))
        self._index += 1
    
    def get(self) -> Optional[CoordinationTask]:
        """Get highest priority task."""
        if self._queue:
            _, _, task = heappop(self._queue)
            return task
        return None
    
    def empty(self) -> bool:
        """Check if queue is empty."""
        return len(self._queue) == 0
    
    def size(self) -> int:
        """Get queue size."""
        return len(self._queue)
    
    def peek(self) -> Optional[CoordinationTask]:
        """Peek at highest priority task without removing."""
        if self._queue:
            return self._queue[0][2]
        return None


class TaskDistributor:
    """
    Distributed task scheduler and load balancer.
    
    This class manages task distribution across multiple agents,
    providing load balancing, priority scheduling, and resource optimization.
    """
    
    def __init__(
        self,
        coordinator: Any,  # A2ACoordinator
        strategy: SchedulingStrategy = SchedulingStrategy.CAPABILITY_BASED,
        max_tasks_per_agent: int = 5,
        load_balance_interval: float = 30.0,
    ):
        """
        Initialize the task distributor.
        
        Args:
            coordinator: A2A coordinator instance
            strategy: Scheduling strategy to use
            max_tasks_per_agent: Maximum concurrent tasks per agent
            load_balance_interval: Interval for load balancing in seconds
        """
        self.coordinator = coordinator
        self.strategy = strategy
        self.max_tasks_per_agent = max_tasks_per_agent
        self.load_balance_interval = load_balance_interval
        
        # Task management
        self.task_queue = TaskQueue()
        self.active_assignments: Dict[str, TaskAssignment] = {}  # task_id -> assignment
        self.agent_assignments: Dict[str, Set[str]] = {}  # agent_id -> set of task_ids
        self.completed_tasks: Dict[str, TaskAssignment] = {}
        
        # Agent load tracking
        self.agent_loads: Dict[str, AgentLoad] = {}
        
        # Scheduling state
        self.round_robin_index = 0
        self.is_running = False
        
        # Performance metrics
        self.total_tasks_processed = 0
        self.total_processing_time = 0.0
        self.failed_tasks = 0
        
        # Task type performance history
        self.task_performance: Dict[str, List[float]] = {}  # task_type -> [durations]
    
    async def start(self):
        """Start the task distributor."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Start background tasks
        asyncio.create_task(self._scheduling_loop())
        asyncio.create_task(self._load_monitoring_loop())
        asyncio.create_task(self._load_balancing_loop())
        
        # Subscribe to task-related messages
        await self._setup_subscriptions()
        
        logger.info("Task distributor started")
    
    async def stop(self):
        """Stop the task distributor."""
        self.is_running = False
        logger.info("Task distributor stopped")
    
    async def _setup_subscriptions(self):
        """Set up subscriptions for task distribution."""
        # Task status updates
        await self.coordinator.transport.subscribe(
            "tasks/status",
            self._handle_task_status_update,
            dict,
        )
        
        # Agent load updates
        await self.coordinator.transport.subscribe(
            "agents/load",
            self._handle_agent_load_update,
            dict,
        )
    
    async def _scheduling_loop(self):
        """Main scheduling loop."""
        while self.is_running:
            try:
                # Process pending tasks
                while not self.task_queue.empty():
                    task = self.task_queue.get()
                    if task:
                        await self._schedule_task(task)
                
                await asyncio.sleep(1.0)  # Check every second
                
            except Exception as e:
                logger.error(f"Error in scheduling loop: {e}")
                await asyncio.sleep(5.0)
    
    async def _load_monitoring_loop(self):
        """Monitor agent loads."""
        while self.is_running:
            try:
                await self._update_agent_loads()
                await asyncio.sleep(10.0)  # Update every 10 seconds
                
            except Exception as e:
                logger.error(f"Error in load monitoring loop: {e}")
                await asyncio.sleep(5.0)
    
    async def _load_balancing_loop(self):
        """Periodic load balancing."""
        while self.is_running:
            try:
                await self._rebalance_tasks()
                await asyncio.sleep(self.load_balance_interval)
                
            except Exception as e:
                logger.error(f"Error in load balancing loop: {e}")
                await asyncio.sleep(5.0)
    
    async def submit_task(
        self,
        task: CoordinationTask,
        priority: TaskPriority = TaskPriority.NORMAL,
    ) -> str:
        """
        Submit a task for distribution.
        
        Args:
            task: Task to submit
            priority: Task priority
            
        Returns:
            Task ID
        """
        # Add to queue with priority
        priority_value = priority.value
        
        # Adjust priority based on deadline
        if task.deadline:
            time_to_deadline = task.deadline - time.time()
            if time_to_deadline < 300:  # Less than 5 minutes
                priority_value = min(priority_value - 1, 1)  # Increase priority
        
        self.task_queue.put(task, priority_value)
        
        logger.info(f"Task {task.task_id} submitted with priority {priority.name}")
        return task.task_id
    
    async def _schedule_task(self, task: CoordinationTask):
        """Schedule a task to an appropriate agent."""
        # Find suitable agents
        suitable_agents = self._find_suitable_agents(task)
        
        if not suitable_agents:
            logger.warning(f"No suitable agents found for task {task.task_id}")
            return
        
        # Select best agent based on strategy
        selected_agent = self._select_agent(task, suitable_agents)
        
        if not selected_agent:
            logger.warning(f"No agent selected for task {task.task_id}")
            return
        
        # Estimate task duration
        estimated_duration = self._estimate_task_duration(task)
        
        # Create assignment
        assignment = TaskAssignment(
            task_id=task.task_id,
            agent_id=selected_agent,
            assigned_at=time.time(),
            estimated_duration=estimated_duration,
        )
        
        # Track assignment
        self.active_assignments[task.task_id] = assignment
        
        if selected_agent not in self.agent_assignments:
            self.agent_assignments[selected_agent] = set()
        self.agent_assignments[selected_agent].add(task.task_id)
        
        # Send task to agent
        await self._send_task_to_agent(task, selected_agent)
        
        logger.info(f"Task {task.task_id} assigned to agent {selected_agent}")
    
    def _find_suitable_agents(self, task: CoordinationTask) -> List[str]:
        """Find agents that can handle the task."""
        suitable_agents = []
        
        for agent_id, agent_info in self.coordinator.known_agents.items():
            # Check capabilities
            if all(cap in agent_info.capabilities for cap in task.required_capabilities):
                # Check load
                current_tasks = len(self.agent_assignments.get(agent_id, set()))
                if current_tasks < self.max_tasks_per_agent:
                    suitable_agents.append(agent_id)
        
        return suitable_agents
    
    def _select_agent(self, task: CoordinationTask, suitable_agents: List[str]) -> Optional[str]:
        """Select the best agent for the task based on strategy."""
        if not suitable_agents:
            return None
        
        if self.strategy == SchedulingStrategy.ROUND_ROBIN:
            return self._select_round_robin(suitable_agents)
        elif self.strategy == SchedulingStrategy.LEAST_LOADED:
            return self._select_least_loaded(suitable_agents)
        elif self.strategy == SchedulingStrategy.CAPABILITY_BASED:
            return self._select_capability_based(task, suitable_agents)
        else:
            return suitable_agents[0]  # Default to first suitable agent
    
    def _select_round_robin(self, suitable_agents: List[str]) -> str:
        """Select agent using round-robin strategy."""
        agent = suitable_agents[self.round_robin_index % len(suitable_agents)]
        self.round_robin_index += 1
        return agent
    
    def _select_least_loaded(self, suitable_agents: List[str]) -> str:
        """Select the least loaded agent."""
        best_agent = suitable_agents[0]
        best_load = float('inf')
        
        for agent_id in suitable_agents:
            if agent_id in self.agent_loads:
                load = self.agent_loads[agent_id].load_score()
            else:
                load = 0.0  # Unknown load, assume low
            
            if load < best_load:
                best_load = load
                best_agent = agent_id
        
        return best_agent
    
    def _select_capability_based(self, task: CoordinationTask, suitable_agents: List[str]) -> str:
        """Select agent based on capability match and performance history."""
        best_agent = suitable_agents[0]
        best_score = -1.0
        
        for agent_id in suitable_agents:
            score = 0.0
            
            # Score based on capability overlap
            agent_info = self.coordinator.known_agents.get(agent_id)
            if agent_info:
                capability_overlap = len(set(task.required_capabilities) & set(agent_info.capabilities))
                total_capabilities = len(agent_info.capabilities)
                if total_capabilities > 0:
                    score += capability_overlap / total_capabilities
            
            # Score based on historical performance for this task type
            if task.task_type in self.task_performance:
                avg_duration = sum(self.task_performance[task.task_type]) / len(self.task_performance[task.task_type])
                estimated_duration = self._estimate_task_duration(task)
                if estimated_duration > 0:
                    performance_score = min(avg_duration / estimated_duration, 2.0)  # Cap at 2x
                    score += performance_score
            
            # Score based on current load (inverse)
            if agent_id in self.agent_loads:
                load_score = 1.0 - self.agent_loads[agent_id].load_score()
                score += load_score
            else:
                score += 1.0  # Unknown load, assume good
            
            if score > best_score:
                best_score = score
                best_agent = agent_id
        
        return best_agent
    
    def _estimate_task_duration(self, task: CoordinationTask) -> float:
        """Estimate task duration based on type and historical data."""
        # Base estimates by task type
        base_estimates = {
            "navigation": 30.0,
            "manipulation": 60.0,
            "perception": 10.0,
            "communication": 5.0,
            "computation": 20.0,
        }
        
        base_duration = base_estimates.get(task.task_type, 30.0)
        
        # Adjust based on historical performance
        if task.task_type in self.task_performance:
            historical_durations = self.task_performance[task.task_type]
            if historical_durations:
                avg_duration = sum(historical_durations) / len(historical_durations)
                # Weighted average of base estimate and historical data
                base_duration = (base_duration + avg_duration * 2) / 3
        
        # Adjust based on complexity (number of required capabilities)
        complexity_factor = 1.0 + (len(task.required_capabilities) - 1) * 0.2
        
        return base_duration * complexity_factor
    
    async def _send_task_to_agent(self, task: CoordinationTask, agent_id: str):
        """Send task assignment to agent."""
        message = {
            "type": "task_assignment",
            "task": task.to_dict(),
            "assigned_by": self.coordinator.agent_id,
            "timestamp": time.time(),
        }
        
        await self.coordinator.transport.publish(
            f"tasks/assign/{agent_id}",
            message,
        )
    
    async def _update_agent_loads(self):
        """Update agent load information."""
        current_time = time.time()
        
        for agent_id in self.coordinator.known_agents:
            # Count current tasks
            current_tasks = len(self.agent_assignments.get(agent_id, set()))
            
            # Calculate total estimated time
            total_time = 0.0
            for task_id in self.agent_assignments.get(agent_id, set()):
                if task_id in self.active_assignments:
                    assignment = self.active_assignments[task_id]
                    remaining_time = assignment.estimated_duration
                    if assignment.actual_start_time:
                        elapsed = current_time - assignment.actual_start_time
                        remaining_time = max(0, assignment.estimated_duration - elapsed)
                    total_time += remaining_time
            
            # Update or create load info
            if agent_id not in self.agent_loads:
                self.agent_loads[agent_id] = AgentLoad(
                    agent_id=agent_id,
                    current_tasks=current_tasks,
                    total_estimated_time=total_time,
                    last_update=current_time,
                )
            else:
                load = self.agent_loads[agent_id]
                load.current_tasks = current_tasks
                load.total_estimated_time = total_time
                load.last_update = current_time
    
    async def _rebalance_tasks(self):
        """Rebalance tasks across agents if needed."""
        if len(self.agent_loads) < 2:
            return  # Need at least 2 agents for rebalancing
        
        # Find overloaded and underloaded agents
        overloaded_agents = []
        underloaded_agents = []
        
        avg_load = sum(load.load_score() for load in self.agent_loads.values()) / len(self.agent_loads)
        
        for agent_id, load in self.agent_loads.items():
            if load.load_score() > avg_load * 1.5:  # 50% above average
                overloaded_agents.append(agent_id)
            elif load.load_score() < avg_load * 0.5:  # 50% below average
                underloaded_agents.append(agent_id)
        
        # Rebalance if needed
        if overloaded_agents and underloaded_agents:
            logger.info(f"Rebalancing tasks: {len(overloaded_agents)} overloaded, {len(underloaded_agents)} underloaded")
            
            # Real implementation: move tasks from overloaded to underloaded agents
            tasks_moved = 0
            
            for overloaded_agent in overloaded_agents:
                if not underloaded_agents:
                    break
                    
                # Get tasks from overloaded agent
                agent_tasks = [task for task in self.pending_tasks.values()
                              if task.assigned_agent == overloaded_agent]
                
                # Sort tasks by priority (move lower priority tasks first)
                agent_tasks.sort(key=lambda t: t.priority)
                
                # Calculate how many tasks to move
                current_load = len(agent_tasks)
                target_load = self.max_tasks_per_agent
                tasks_to_move = min(current_load - target_load, len(agent_tasks) // 2)
                
                for i in range(tasks_to_move):
                    if not underloaded_agents:
                        break
                        
                    task = agent_tasks[i]
                    
                    # Find best underloaded agent for this task
                    best_agent = None
                    best_score = float('-inf')
                    
                    for underloaded_agent in underloaded_agents:
                        # Calculate assignment score based on agent capabilities
                        score = self._calculate_assignment_score(task, underloaded_agent)
                        if score > best_score:
                            best_score = score
                            best_agent = underloaded_agent
                    
                    if best_agent:
                        # Move the task
                        old_agent = task.assigned_agent
                        task.assigned_agent = best_agent
                        task.status = "reassigned"
                        
                        logger.info(f"Moved task {task.id} from {old_agent} to {best_agent}")
                        tasks_moved += 1
                        
                        # Update agent loads
                        current_underloaded_load = len([t for t in self.pending_tasks.values()
                                                      if t.assigned_agent == best_agent])
                        if current_underloaded_load >= self.max_tasks_per_agent:
                            underloaded_agents.remove(best_agent)
                        
                        # Notify agents of the change
                        await self._notify_task_reassignment(task, old_agent, best_agent)
            
            logger.info(f"Task rebalancing completed: {tasks_moved} tasks moved")
    
    def _calculate_assignment_score(self, task: Task, agent_id: str) -> float:
        """Calculate how well suited an agent is for a task."""
        score = 0.0
        
        # Get agent capabilities
        agent_info = self.agents.get(agent_id, {})
        agent_capabilities = agent_info.get("capabilities", [])
        
        # Score based on capability match
        task_requirements = getattr(task, 'requirements', [])
        if task_requirements:
            matching_capabilities = set(agent_capabilities) & set(task_requirements)
            score += len(matching_capabilities) * 10
        
        # Score based on agent load (prefer less loaded agents)
        current_load = len([t for t in self.pending_tasks.values() if t.assigned_agent == agent_id])
        load_factor = 1.0 - (current_load / self.max_tasks_per_agent)
        score += load_factor * 5
        
        # Score based on agent performance history
        agent_performance = agent_info.get("performance_score", 0.5)
        score += agent_performance * 3
        
        return score
    
    async def _notify_task_reassignment(self, task: Task, old_agent: str, new_agent: str):
        """Notify agents about task reassignment."""
        try:
            # Notify old agent to stop working on the task
            old_agent_message = {
                "type": "task_revoked",
                "task_id": task.id,
                "reason": "load_balancing",
                "timestamp": time.time()
            }
            
            if self.transport:
                await self.transport.publish(
                    f"agent/{old_agent}/tasks",
                    old_agent_message,
                    {"qos": 1}
                )
            
            # Notify new agent about the task assignment
            new_agent_message = {
                "type": "task_assigned",
                "task": {
                    "id": task.id,
                    "type": task.type,
                    "priority": task.priority,
                    "data": task.data,
                    "requirements": getattr(task, 'requirements', [])
                },
                "timestamp": time.time()
            }
            
            if self.transport:
                await self.transport.publish(
                    f"agent/{new_agent}/tasks",
                    new_agent_message,
                    {"qos": 1}
                )
                
            logger.debug(f"Notified agents about task {task.id} reassignment: {old_agent} -> {new_agent}")
            
        except Exception as e:
            logger.error(f"Failed to notify agents about task reassignment: {e}")
    
    async def _handle_task_status_update(self, message: Dict[str, Any]):
        """Handle task status updates from agents."""
        try:
            task_id = message.get("task_id")
            status = message.get("status")
            agent_id = message.get("agent_id")
            
            if task_id in self.active_assignments:
                assignment = self.active_assignments[task_id]
                assignment.status = TaskStatus(status)
                
                if status == "running" and not assignment.actual_start_time:
                    assignment.actual_start_time = time.time()
                
                elif status in ["completed", "failed"]:
                    assignment.actual_end_time = time.time()
                    
                    if status == "completed":
                        assignment.result = message.get("result")
                        # Update performance history
                        if assignment.actual_start_time:
                            duration = assignment.actual_end_time - assignment.actual_start_time
                            task_type = message.get("task_type", "unknown")
                            if task_type not in self.task_performance:
                                self.task_performance[task_type] = []
                            self.task_performance[task_type].append(duration)
                            # Keep only recent history
                            if len(self.task_performance[task_type]) > 100:
                                self.task_performance[task_type] = self.task_performance[task_type][-50:]
                        
                        self.total_tasks_processed += 1
                        if assignment.actual_start_time:
                            self.total_processing_time += assignment.actual_end_time - assignment.actual_start_time
                    
                    elif status == "failed":
                        assignment.error = message.get("error")
                        self.failed_tasks += 1
                    
                    # Move to completed tasks
                    self.completed_tasks[task_id] = assignment
                    del self.active_assignments[task_id]
                    
                    # Remove from agent assignments
                    if agent_id in self.agent_assignments:
                        self.agent_assignments[agent_id].discard(task_id)
                
        except Exception as e:
            logger.error(f"Error handling task status update: {e}")
    
    async def _handle_agent_load_update(self, message: Dict[str, Any]):
        """Handle agent load updates."""
        try:
            agent_id = message.get("agent_id")
            if agent_id and agent_id in self.agent_loads:
                load = self.agent_loads[agent_id]
                load.cpu_usage = message.get("cpu_usage", load.cpu_usage)
                load.memory_usage = message.get("memory_usage", load.memory_usage)
                load.last_update = time.time()
                
        except Exception as e:
            logger.error(f"Error handling agent load update: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get task distribution statistics."""
        active_tasks = len(self.active_assignments)
        completed_tasks = len(self.completed_tasks)
        
        avg_processing_time = 0.0
        if self.total_tasks_processed > 0:
            avg_processing_time = self.total_processing_time / self.total_tasks_processed
        
        failure_rate = 0.0
        total_tasks = self.total_tasks_processed + self.failed_tasks
        if total_tasks > 0:
            failure_rate = self.failed_tasks / total_tasks
        
        return {
            "active_tasks": active_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": self.failed_tasks,
            "queued_tasks": self.task_queue.size(),
            "total_agents": len(self.agent_loads),
            "avg_processing_time": avg_processing_time,
            "failure_rate": failure_rate,
            "strategy": self.strategy.value,
        }
    
    def get_agent_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all agents."""
        status = {}
        
        for agent_id, load in self.agent_loads.items():
            status[agent_id] = {
                "current_tasks": load.current_tasks,
                "total_estimated_time": load.total_estimated_time,
                "load_score": load.load_score(),
                "cpu_usage": load.cpu_usage,
                "memory_usage": load.memory_usage,
                "last_update": load.last_update,
            }
        
        return status