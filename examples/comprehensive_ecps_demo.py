"""
Comprehensive ECPS-UV SDK Demo.

This example demonstrates all the major fixes implemented for the SDK architecture review:
1. QoS Constants and Timing Budgets
2. Enhanced LTP Wire Definition with chunking
3. Strong Consistency MEP implementation
4. Fixed gRPC and enhanced MQTT transports
5. A2A Coordination with swarm management

This demo shows a multi-agent robotic system coordinating tasks.
"""

import asyncio
import logging
import numpy as np
import time
from typing import Dict, Any

from ecps_uv.core import ECPSClient, ECPSServer, StandardProfile
from ecps_uv.qos_constants import get_profile_qos, validate_timing_budget, TimingBudgets
from ecps_uv.coordination import A2ACoordinator, SwarmManager, ConsensusProtocol, TaskDistributor
from ecps_uv.coordination.a2a_coordinator import AgentRole, CoordinationTask
from ecps_uv.coordination.swarm_manager import Position, SwarmFormation, SwarmBehavior
from ecps_uv.cognition.mep import DistributedVectorStore, ConsistencyModel

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RobotAgent:
    """A robot agent with ECPS capabilities."""
    
    def __init__(self, agent_id: str, position: Position, is_leader: bool = False):
        self.agent_id = agent_id
        self.position = position
        self.is_leader = is_leader
        
        # ECPS components
        self.config = StandardProfile(transport_type="mqtt")
        self.client = ECPSClient(self.config)
        self.server = ECPSServer(self.config)
        
        # A2A Coordination
        self.coordinator = A2ACoordinator(
            agent_id=agent_id,
            transport=self.client.transport,
            serializer=self.client.serializer,
            telemetry=self.client.telemetry,
            role=AgentRole.LEADER if is_leader else AgentRole.WORKER,
            capabilities=["navigation", "perception", "manipulation"],
        )
        
        # Swarm management
        self.swarm_manager = SwarmManager(
            coordinator=self.coordinator,
            agent_id=agent_id,
            initial_position=position,
            is_leader=is_leader,
        )
        
        # Consensus protocol
        self.consensus = ConsensusProtocol(
            node_id=agent_id,
            transport=self.client.transport,
            peer_nodes=set(),  # Will be populated later
        )
        
        # Task distributor (only for leader)
        self.task_distributor = None
        if is_leader:
            self.task_distributor = TaskDistributor(
                coordinator=self.coordinator,
                strategy=TaskDistributor.SchedulingStrategy.CAPABILITY_BASED,
            )
        
        # Distributed memory store
        self.memory_store = DistributedVectorStore(
            node_id=agent_id,
            max_size=1000,
            replication_factor=2,
        )
        
        # Performance tracking
        self.task_start_times = {}
        self.completed_tasks = 0
    
    async def start(self):
        """Start the robot agent."""
        logger.info(f"Starting robot agent {self.agent_id}")
        
        # Start ECPS components
        await self.client.transport.connect()
        await self.server.start()
        
        # Start coordination components
        await self.coordinator.start()
        await self.swarm_manager.start()
        await self.consensus.start()
        
        if self.task_distributor:
            await self.task_distributor.start()
        
        # Register task handlers
        self._register_task_handlers()
        
        # Start MEP service
        self.server.start_mep_service(storage_backend=self.memory_store)
        
        logger.info(f"Robot agent {self.agent_id} started successfully")
    
    def _register_task_handlers(self):
        """Register handlers for different task types."""
        self.coordinator.register_task_handler("navigation", self._handle_navigation_task)
        self.coordinator.register_task_handler("perception", self._handle_perception_task)
        self.coordinator.register_task_handler("manipulation", self._handle_manipulation_task)
    
    async def _handle_navigation_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle navigation task."""
        start_time = time.time()
        self.task_start_times[task.task_id] = start_time
        
        logger.info(f"Agent {self.agent_id} executing navigation task {task.task_id}")
        
        # Simulate navigation with QoS validation
        target = task.parameters.get("target", {"x": 0, "y": 0, "z": 0})
        
        # Check timing budget
        qos = get_profile_qos("standard", "EAP", "mqtt")
        max_latency = qos.get("max_latency_ms", TimingBudgets.EAP_MAX_LATENCY_MS)
        
        # Simulate navigation time
        navigation_time = 2.0  # 2 seconds
        await asyncio.sleep(navigation_time)
        
        # Validate timing
        actual_latency = (time.time() - start_time) * 1000  # Convert to ms
        timing_ok = validate_timing_budget(actual_latency, "EAP", "standard")
        
        # Update position
        new_position = Position(target["x"], target["y"], target["z"])
        self.swarm_manager.my_agent.position = new_position
        
        self.completed_tasks += 1
        
        return {
            "status": "completed",
            "new_position": new_position.to_dict(),
            "timing_budget_met": timing_ok,
            "actual_latency_ms": actual_latency,
        }
    
    async def _handle_perception_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle perception task with LTP demonstration."""
        start_time = time.time()
        self.task_start_times[task.task_id] = start_time
        
        logger.info(f"Agent {self.agent_id} executing perception task {task.task_id}")
        
        # Generate synthetic sensor data (large tensor)
        sensor_data = np.random.rand(100, 100, 3).astype(np.float32)  # RGB image
        
        # Use LTP to send sensor data with chunking if needed
        from ecps_uv.perception.ltp import LTPHandler
        
        ltp_handler = LTPHandler(
            transport=self.client.transport,
            serializer=self.client.serializer,
            telemetry=self.client.telemetry,
            max_size_bytes=64 * 1024,  # 64KB chunks
        )
        
        # Send chunked if large
        if sensor_data.nbytes > 64 * 1024:
            message_ids = await ltp_handler.send_chunked(
                topic="perception/sensor_data",
                tensor=sensor_data,
                frame_id="camera_1",
            )
            logger.info(f"Sent large sensor data in {len(message_ids)} chunks")
        else:
            message_id = await ltp_handler.send(
                topic="perception/sensor_data",
                tensor=sensor_data,
                frame_id="camera_1",
            )
            logger.info(f"Sent sensor data in single message: {message_id}")
        
        # Store perception result in distributed memory with strong consistency
        perception_embedding = np.random.rand(512).astype(np.float32)  # Feature vector
        
        success = await self.memory_store.put(
            tensor=perception_embedding,
            metadata={
                "task_id": task.task_id,
                "agent_id": self.agent_id,
                "timestamp_ns": int(time.time_ns()),
                "frame_id": "camera_1",
            },
            consistency=ConsistencyModel.STRONG,
        )
        
        actual_latency = (time.time() - start_time) * 1000
        timing_ok = validate_timing_budget(actual_latency, "LTP", "standard")
        
        self.completed_tasks += 1
        
        return {
            "status": "completed",
            "sensor_data_shape": sensor_data.shape,
            "embedding_stored": success,
            "timing_budget_met": timing_ok,
            "actual_latency_ms": actual_latency,
        }
    
    async def _handle_manipulation_task(self, task: CoordinationTask) -> Dict[str, Any]:
        """Handle manipulation task."""
        start_time = time.time()
        self.task_start_times[task.task_id] = start_time
        
        logger.info(f"Agent {self.agent_id} executing manipulation task {task.task_id}")
        
        # Simulate manipulation
        await asyncio.sleep(1.5)  # 1.5 seconds
        
        # Send EAP command
        action_data = {
            "gripper_command": "close",
            "force_limit": 10.0,
        }
        
        message_id = await self.client.send_action(
            action_type="gripper",
            action_data=action_data,
            state_sha=b"dummy_state_hash",
            meta={"safety": "stop_on_fail"},
        )
        
        actual_latency = (time.time() - start_time) * 1000
        timing_ok = validate_timing_budget(actual_latency, "EAP", "standard")
        
        self.completed_tasks += 1
        
        return {
            "status": "completed",
            "action_message_id": message_id,
            "timing_budget_met": timing_ok,
            "actual_latency_ms": actual_latency,
        }
    
    async def stop(self):
        """Stop the robot agent."""
        logger.info(f"Stopping robot agent {self.agent_id}")
        
        if self.task_distributor:
            await self.task_distributor.stop()
        
        await self.consensus.stop()
        await self.swarm_manager.stop()
        await self.coordinator.stop()
        await self.server.close()
        await self.client.close()


class MultiAgentDemo:
    """Demonstration of multi-agent coordination."""
    
    def __init__(self):
        self.agents = []
        self.leader_agent = None
    
    async def setup_agents(self, num_agents: int = 3):
        """Set up multiple robot agents."""
        logger.info(f"Setting up {num_agents} robot agents")
        
        # Create agents
        for i in range(num_agents):
            agent_id = f"robot_{i}"
            position = Position(i * 5.0, 0.0, 0.0)  # Space agents 5 meters apart
            is_leader = (i == 0)  # First agent is leader
            
            agent = RobotAgent(agent_id, position, is_leader)
            self.agents.append(agent)
            
            if is_leader:
                self.leader_agent = agent
        
        # Set up peer relationships for consensus
        agent_ids = [agent.agent_id for agent in self.agents]
        for agent in self.agents:
            peer_ids = set(agent_ids) - {agent.agent_id}
            agent.consensus.peer_nodes = peer_ids
        
        # Start all agents
        for agent in self.agents:
            await agent.start()
        
        # Wait for discovery
        await asyncio.sleep(5.0)
        
        logger.info("All agents started and discovered each other")
    
    async def demonstrate_swarm_coordination(self):
        """Demonstrate swarm coordination capabilities."""
        logger.info("=== Demonstrating Swarm Coordination ===")
        
        if not self.leader_agent:
            logger.error("No leader agent available")
            return
        
        # Change formation to circle
        center = Position(10.0, 10.0, 0.0)
        await self.leader_agent.swarm_manager.change_formation(
            SwarmFormation.CIRCLE,
            center,
            scale=8.0
        )
        
        logger.info("Changed formation to circle")
        await asyncio.sleep(3.0)
        
        # Change behavior to flocking
        await self.leader_agent.swarm_manager.change_behavior(SwarmBehavior.FLOCKING)
        logger.info("Changed behavior to flocking")
        await asyncio.sleep(3.0)
        
        # Move formation
        new_center = Position(20.0, 20.0, 0.0)
        await self.leader_agent.swarm_manager.move_formation(new_center)
        logger.info("Moved formation to new location")
        await asyncio.sleep(3.0)
    
    async def demonstrate_task_distribution(self):
        """Demonstrate task distribution and coordination."""
        logger.info("=== Demonstrating Task Distribution ===")
        
        if not self.leader_agent or not self.leader_agent.task_distributor:
            logger.error("No leader agent with task distributor available")
            return
        
        # Create various tasks
        tasks = [
            CoordinationTask(
                task_id="nav_001",
                task_type="navigation",
                required_capabilities=["navigation"],
                priority=5,
                parameters={"target": {"x": 15.0, "y": 15.0, "z": 0.0}},
            ),
            CoordinationTask(
                task_id="perc_001",
                task_type="perception",
                required_capabilities=["perception"],
                priority=7,
                parameters={"sensor_type": "camera"},
            ),
            CoordinationTask(
                task_id="manip_001",
                task_type="manipulation",
                required_capabilities=["manipulation"],
                priority=6,
                parameters={"object": "cube", "action": "pick"},
            ),
        ]
        
        # Submit tasks
        for task in tasks:
            await self.leader_agent.task_distributor.submit_task(task)
            logger.info(f"Submitted task {task.task_id}")
        
        # Wait for task completion
        await asyncio.sleep(10.0)
        
        # Show statistics
        stats = self.leader_agent.task_distributor.get_statistics()
        logger.info(f"Task distribution statistics: {stats}")
    
    async def demonstrate_consensus(self):
        """Demonstrate consensus protocol."""
        logger.info("=== Demonstrating Consensus Protocol ===")
        
        # Set up consensus callbacks
        async def on_leader_elected(leader_id: str, term: int):
            logger.info(f"Leader elected: {leader_id} for term {term}")
        
        async def on_command_applied(command: Dict[str, Any]):
            logger.info(f"Command applied: {command}")
        
        for agent in self.agents:
            agent.consensus.on_leader_elected = on_leader_elected
            agent.consensus.on_command_applied = on_command_applied
        
        # Wait for leader election
        await asyncio.sleep(5.0)
        
        # Propose a command through the leader
        for agent in self.agents:
            if agent.consensus.is_leader():
                success = await agent.consensus.propose_command({
                    "type": "formation_change",
                    "formation": "line",
                    "timestamp": time.time(),
                })
                if success:
                    logger.info("Successfully proposed formation change command")
                break
        
        await asyncio.sleep(3.0)
    
    async def demonstrate_memory_consistency(self):
        """Demonstrate distributed memory with strong consistency."""
        logger.info("=== Demonstrating Memory Consistency ===")
        
        # Store data with strong consistency from multiple agents
        for i, agent in enumerate(self.agents):
            embedding = np.random.rand(128).astype(np.float32)
            
            success = await agent.memory_store.put(
                tensor=embedding,
                metadata={
                    "agent_id": agent.agent_id,
                    "data_type": "test_embedding",
                    "index": i,
                    "timestamp_ns": int(time.time_ns()),
                },
                consistency=ConsistencyModel.STRONG,
            )
            
            logger.info(f"Agent {agent.agent_id} stored embedding with strong consistency: {success}")
        
        await asyncio.sleep(2.0)
        
        # Query from different agent
        query_embedding = np.random.rand(128).astype(np.float32)
        results = await self.agents[1].memory_store.query(
            query_tensor=query_embedding,
            k=5,
            min_sim=0.0,  # Low threshold to get results
            consistency=ConsistencyModel.STRONG,
        )
        
        logger.info(f"Query returned {len(results)} results with strong consistency")
    
    async def run_demo(self):
        """Run the complete demonstration."""
        try:
            logger.info("Starting Comprehensive ECPS-UV Demo")
            
            # Setup
            await self.setup_agents(3)
            
            # Run demonstrations
            await self.demonstrate_swarm_coordination()
            await self.demonstrate_task_distribution()
            await self.demonstrate_consensus()
            await self.demonstrate_memory_consistency()
            
            # Show final statistics
            logger.info("=== Final Statistics ===")
            for agent in self.agents:
                logger.info(f"Agent {agent.agent_id}: {agent.completed_tasks} tasks completed")
                
                if agent.task_distributor:
                    stats = agent.task_distributor.get_statistics()
                    logger.info(f"Task distributor stats: {stats}")
                
                consensus_status = agent.consensus.get_status()
                logger.info(f"Consensus status: {consensus_status}")
                
                swarm_status = agent.swarm_manager.get_swarm_status()
                logger.info(f"Swarm status: {swarm_status}")
            
            logger.info("Demo completed successfully!")
            
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            raise
        finally:
            # Cleanup
            for agent in self.agents:
                await agent.stop()


async def main():
    """Main demo function."""
    demo = MultiAgentDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())