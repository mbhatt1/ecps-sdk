"""
Consensus Protocol for ECPS-UV SDK.

This module provides consensus mechanisms for distributed decision making
in multi-agent systems, including leader election and distributed agreement.
"""

import asyncio
import logging
import time
import uuid
from typing import Any, Dict, List, Optional, Set
from enum import Enum

logger = logging.getLogger("ecps_uv.coordination.consensus")


class ConsensusState(Enum):
    """States in the consensus protocol."""
    FOLLOWER = "follower"
    CANDIDATE = "candidate"
    LEADER = "leader"


class ConsensusMessage:
    """Base class for consensus messages."""
    
    def __init__(self, msg_type: str, sender_id: str, term: int):
        self.msg_type = msg_type
        self.sender_id = sender_id
        self.term = term
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "msg_type": self.msg_type,
            "sender_id": self.sender_id,
            "term": self.term,
            "timestamp": self.timestamp,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ConsensusMessage":
        """Create from dictionary."""
        msg = cls(data["msg_type"], data["sender_id"], data["term"])
        msg.timestamp = data.get("timestamp", time.time())
        return msg


class VoteRequest(ConsensusMessage):
    """Vote request message for leader election."""
    
    def __init__(self, sender_id: str, term: int, last_log_index: int, last_log_term: int):
        super().__init__("vote_request", sender_id, term)
        self.last_log_index = last_log_index
        self.last_log_term = last_log_term
    
    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        data.update({
            "last_log_index": self.last_log_index,
            "last_log_term": self.last_log_term,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VoteRequest":
        msg = cls(
            data["sender_id"],
            data["term"],
            data["last_log_index"],
            data["last_log_term"]
        )
        msg.timestamp = data.get("timestamp", time.time())
        return msg


class VoteResponse(ConsensusMessage):
    """Vote response message."""
    
    def __init__(self, sender_id: str, term: int, vote_granted: bool):
        super().__init__("vote_response", sender_id, term)
        self.vote_granted = vote_granted
    
    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        data["vote_granted"] = self.vote_granted
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VoteResponse":
        msg = cls(data["sender_id"], data["term"], data["vote_granted"])
        msg.timestamp = data.get("timestamp", time.time())
        return msg


class Heartbeat(ConsensusMessage):
    """Heartbeat message from leader."""
    
    def __init__(self, sender_id: str, term: int, prev_log_index: int, prev_log_term: int, entries: List[Dict[str, Any]], leader_commit: int):
        super().__init__("heartbeat", sender_id, term)
        self.prev_log_index = prev_log_index
        self.prev_log_term = prev_log_term
        self.entries = entries
        self.leader_commit = leader_commit
    
    def to_dict(self) -> Dict[str, Any]:
        data = super().to_dict()
        data.update({
            "prev_log_index": self.prev_log_index,
            "prev_log_term": self.prev_log_term,
            "entries": self.entries,
            "leader_commit": self.leader_commit,
        })
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Heartbeat":
        msg = cls(
            data["sender_id"],
            data["term"],
            data["prev_log_index"],
            data["prev_log_term"],
            data["entries"],
            data["leader_commit"]
        )
        msg.timestamp = data.get("timestamp", time.time())
        return msg


class LogEntry:
    """Entry in the consensus log."""
    
    def __init__(self, term: int, index: int, command: Dict[str, Any]):
        self.term = term
        self.index = index
        self.command = command
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "term": self.term,
            "index": self.index,
            "command": self.command,
            "timestamp": self.timestamp,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogEntry":
        entry = cls(data["term"], data["index"], data["command"])
        entry.timestamp = data.get("timestamp", time.time())
        return entry


class ConsensusProtocol:
    """
    Raft-based consensus protocol for distributed coordination.
    
    This implementation provides leader election and log replication
    for achieving consensus in multi-agent systems.
    """
    
    def __init__(
        self,
        node_id: str,
        transport: Any,
        peer_nodes: Set[str],
        election_timeout_range: tuple = (150, 300),  # milliseconds
        heartbeat_interval: float = 50,  # milliseconds
    ):
        """
        Initialize the consensus protocol.
        
        Args:
            node_id: Unique identifier for this node
            transport: Transport layer for communication
            peer_nodes: Set of peer node IDs
            election_timeout_range: Range for election timeout (min, max) in ms
            heartbeat_interval: Heartbeat interval in ms
        """
        self.node_id = node_id
        self.transport = transport
        self.peer_nodes = peer_nodes.copy()
        self.election_timeout_range = election_timeout_range
        self.heartbeat_interval = heartbeat_interval / 1000.0  # Convert to seconds
        
        # Consensus state
        self.state = ConsensusState.FOLLOWER
        self.current_term = 0
        self.voted_for: Optional[str] = None
        self.log: List[LogEntry] = []
        self.commit_index = 0
        self.last_applied = 0
        
        # Leader state
        self.next_index: Dict[str, int] = {}
        self.match_index: Dict[str, int] = {}
        
        # Timing
        self.last_heartbeat = time.time()
        self.election_timeout = self._random_election_timeout()
        
        # Control
        self.is_running = False
        self.leader_id: Optional[str] = None
        
        # Callbacks
        self.on_leader_elected: Optional[callable] = None
        self.on_command_applied: Optional[callable] = None
    
    def _random_election_timeout(self) -> float:
        """Generate a random election timeout."""
        import random
        timeout_ms = random.randint(*self.election_timeout_range)
        return timeout_ms / 1000.0  # Convert to seconds
    
    async def start(self):
        """Start the consensus protocol."""
        if self.is_running:
            return
        
        self.is_running = True
        
        # Subscribe to consensus messages
        await self.transport.subscribe(
            f"consensus/{self.node_id}",
            self._handle_consensus_message,
            dict,
        )
        
        # Start background tasks
        asyncio.create_task(self._consensus_loop())
        
        logger.info(f"Consensus protocol started for node {self.node_id}")
    
    async def stop(self):
        """Stop the consensus protocol."""
        self.is_running = False
        logger.info(f"Consensus protocol stopped for node {self.node_id}")
    
    async def _consensus_loop(self):
        """Main consensus loop."""
        while self.is_running:
            try:
                current_time = time.time()
                
                if self.state == ConsensusState.LEADER:
                    # Send heartbeats
                    if current_time - self.last_heartbeat >= self.heartbeat_interval:
                        await self._send_heartbeats()
                        self.last_heartbeat = current_time
                
                elif self.state in [ConsensusState.FOLLOWER, ConsensusState.CANDIDATE]:
                    # Check for election timeout
                    if current_time - self.last_heartbeat >= self.election_timeout:
                        await self._start_election()
                
                await asyncio.sleep(0.01)  # 10ms loop
                
            except Exception as e:
                logger.error(f"Error in consensus loop: {e}")
                await asyncio.sleep(1.0)
    
    async def _start_election(self):
        """Start a new election."""
        self.state = ConsensusState.CANDIDATE
        self.current_term += 1
        self.voted_for = self.node_id
        self.last_heartbeat = time.time()
        self.election_timeout = self._random_election_timeout()
        
        logger.info(f"Starting election for term {self.current_term}")
        
        # Vote for ourselves
        votes_received = 1
        
        # Request votes from peers
        last_log_index = len(self.log) - 1 if self.log else -1
        last_log_term = self.log[-1].term if self.log else 0
        
        vote_request = VoteRequest(
            self.node_id,
            self.current_term,
            last_log_index,
            last_log_term
        )
        
        # Send vote requests to all peers
        for peer_id in self.peer_nodes:
            try:
                await self.transport.publish(
                    f"consensus/{peer_id}",
                    vote_request.to_dict()
                )
            except Exception as e:
                logger.warning(f"Failed to send vote request to {peer_id}: {e}")
        
        # Wait for votes (this is simplified - in a real implementation,
        # you'd track votes as they come in)
        await asyncio.sleep(0.1)  # Give time for responses
        
        # Check if we won the election
        majority = len(self.peer_nodes) // 2 + 1
        if votes_received >= majority:
            await self._become_leader()
        else:
            self.state = ConsensusState.FOLLOWER
            self.voted_for = None
    
    async def _become_leader(self):
        """Become the leader."""
        self.state = ConsensusState.LEADER
        self.leader_id = self.node_id
        
        # Initialize leader state
        next_index = len(self.log)
        for peer_id in self.peer_nodes:
            self.next_index[peer_id] = next_index
            self.match_index[peer_id] = 0
        
        logger.info(f"Became leader for term {self.current_term}")
        
        # Notify about leadership
        if self.on_leader_elected:
            await self.on_leader_elected(self.node_id, self.current_term)
        
        # Send initial heartbeats
        await self._send_heartbeats()
    
    async def _send_heartbeats(self):
        """Send heartbeats to all followers."""
        for peer_id in self.peer_nodes:
            prev_log_index = self.next_index[peer_id] - 1
            prev_log_term = 0
            if prev_log_index >= 0 and prev_log_index < len(self.log):
                prev_log_term = self.log[prev_log_index].term
            
            # Get entries to send (empty for heartbeat)
            entries = []
            
            heartbeat = Heartbeat(
                self.node_id,
                self.current_term,
                prev_log_index,
                prev_log_term,
                entries,
                self.commit_index
            )
            
            try:
                await self.transport.publish(
                    f"consensus/{peer_id}",
                    heartbeat.to_dict()
                )
            except Exception as e:
                logger.warning(f"Failed to send heartbeat to {peer_id}: {e}")
    
    async def _handle_consensus_message(self, message: Dict[str, Any]):
        """Handle incoming consensus messages."""
        try:
            msg_type = message.get("msg_type")
            
            if msg_type == "vote_request":
                await self._handle_vote_request(VoteRequest.from_dict(message))
            elif msg_type == "vote_response":
                await self._handle_vote_response(VoteResponse.from_dict(message))
            elif msg_type == "heartbeat":
                await self._handle_heartbeat(Heartbeat.from_dict(message))
                
        except Exception as e:
            logger.error(f"Error handling consensus message: {e}")
    
    async def _handle_vote_request(self, request: VoteRequest):
        """Handle vote request."""
        # Update term if necessary
        if request.term > self.current_term:
            self.current_term = request.term
            self.voted_for = None
            self.state = ConsensusState.FOLLOWER
        
        # Decide whether to grant vote
        vote_granted = False
        
        if (request.term == self.current_term and
            (self.voted_for is None or self.voted_for == request.sender_id)):
            
            # Check if candidate's log is at least as up-to-date as ours
            last_log_index = len(self.log) - 1 if self.log else -1
            last_log_term = self.log[-1].term if self.log else 0
            
            if (request.last_log_term > last_log_term or
                (request.last_log_term == last_log_term and request.last_log_index >= last_log_index)):
                vote_granted = True
                self.voted_for = request.sender_id
                self.last_heartbeat = time.time()  # Reset election timeout
        
        # Send vote response
        response = VoteResponse(self.node_id, self.current_term, vote_granted)
        
        try:
            await self.transport.publish(
                f"consensus/{request.sender_id}",
                response.to_dict()
            )
        except Exception as e:
            logger.warning(f"Failed to send vote response to {request.sender_id}: {e}")
    
    async def _handle_vote_response(self, response: VoteResponse):
        """Handle vote response."""
        if self.state != ConsensusState.CANDIDATE or response.term != self.current_term:
            return
        
        if response.vote_granted:
            # Count votes (simplified - in real implementation, track all votes)
            logger.debug(f"Received vote from {response.sender_id}")
    
    async def _handle_heartbeat(self, heartbeat: Heartbeat):
        """Handle heartbeat from leader."""
        # Update term if necessary
        if heartbeat.term > self.current_term:
            self.current_term = heartbeat.term
            self.voted_for = None
        
        if heartbeat.term == self.current_term:
            self.state = ConsensusState.FOLLOWER
            self.leader_id = heartbeat.sender_id
            self.last_heartbeat = time.time()
            self.election_timeout = self._random_election_timeout()
            
            # Process log entries (simplified)
            if heartbeat.entries:
                for entry_data in heartbeat.entries:
                    entry = LogEntry.from_dict(entry_data)
                    if entry.index < len(self.log):
                        self.log[entry.index] = entry
                    else:
                        self.log.append(entry)
            
            # Update commit index
            if heartbeat.leader_commit > self.commit_index:
                self.commit_index = min(heartbeat.leader_commit, len(self.log) - 1)
                await self._apply_committed_entries()
    
    async def _apply_committed_entries(self):
        """Apply committed log entries."""
        while self.last_applied < self.commit_index:
            self.last_applied += 1
            entry = self.log[self.last_applied]
            
            if self.on_command_applied:
                await self.on_command_applied(entry.command)
    
    async def propose_command(self, command: Dict[str, Any]) -> bool:
        """
        Propose a command for consensus.
        
        Args:
            command: Command to propose
            
        Returns:
            True if successfully proposed (only if leader)
        """
        if self.state != ConsensusState.LEADER:
            return False
        
        # Add to log
        entry = LogEntry(self.current_term, len(self.log), command)
        self.log.append(entry)
        
        logger.info(f"Proposed command: {command}")
        
        # Replicate to followers (simplified)
        await self._send_heartbeats()
        
        return True
    
    def is_leader(self) -> bool:
        """Check if this node is the current leader."""
        return self.state == ConsensusState.LEADER
    
    def get_leader_id(self) -> Optional[str]:
        """Get the current leader ID."""
        return self.leader_id
    
    def get_status(self) -> Dict[str, Any]:
        """Get current consensus status."""
        return {
            "node_id": self.node_id,
            "state": self.state.value,
            "current_term": self.current_term,
            "leader_id": self.leader_id,
            "log_length": len(self.log),
            "commit_index": self.commit_index,
            "last_applied": self.last_applied,
        }