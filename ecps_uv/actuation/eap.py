"""
Embodied Action Protocol (EAP) handler for ECPS.

This module provides handling for EAP messages, which encapsulate
high-level commands for robot actuation.
"""

import asyncio
import hashlib
import logging
import os
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Union

from opentelemetry import trace

# Import EAP message types
try:
    from ecps_uv.proto import ecps_pb2
except ImportError:
    # Dynamically generated protobuf modules might not be available at import time
    ecps_pb2 = None

logger = logging.getLogger("ecps_uv.actuation.eap")


class EAPHandler:
    """
    Handler for Embodied Action Protocol (EAP) messages.
    
    This handler provides functionality for creating, sending, receiving,
    and processing EAP messages, which encapsulate robot action commands.
    """
    
    def __init__(
        self,
        transport: Any,
        serializer: Any,
        telemetry: Optional[Any] = None,
        log_dir: Optional[str] = None,
    ):
        """
        Initialize the EAP handler.
        
        Args:
            transport: Transport layer to use for sending/receiving messages
            serializer: Serializer to use for message encoding/decoding
            telemetry: Telemetry provider for observability (optional)
            log_dir: Directory for action log files (default: current directory)
        """
        self.transport = transport
        self.serializer = serializer
        self.telemetry = telemetry
        self.log_dir = log_dir or os.getcwd()
        
        # Ensure log directory exists
        os.makedirs(self.log_dir, exist_ok=True)
        
        # Action log file handle
        self.log_file = None
        self.log_lock = asyncio.Lock()
    
    def _get_eap_message_class(self):
        """Get the EAP message class from ecps_pb2."""
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        if hasattr(ecps_pb2, "EAP"):
            return ecps_pb2.EAP
        
        raise AttributeError("EAP message type not found in ecps_pb2")
    
    def _get_action_class(self, action_type: str):
        """
        Get the class for a specific action type.
        
        Args:
            action_type: Type of action ("set_pose", "gripper", "cloud", "sim")
            
        Returns:
            action_class: Protocol Buffers class for the action
        """
        if ecps_pb2 is None:
            raise ImportError("ecps_pb2 module not available")
        
        # Map action type to class name
        class_mapping = {
            "set_pose": "RobotPose",
            "gripper": "GripperOp",
            "cloud": "CloudOp",
            "sim": "SimStep",
        }
        
        if action_type not in class_mapping:
            raise ValueError(f"Unknown action type: {action_type}")
        
        class_name = class_mapping[action_type]
        
        if hasattr(ecps_pb2, class_name):
            return getattr(ecps_pb2, class_name)
        
        raise AttributeError(f"{class_name} message type not found in ecps_pb2")
    
    def create_eap_message(
        self,
        action_type: str,
        action_data: Any,
        message_id: Optional[str] = None,
        state_sha: Optional[bytes] = None,
        meta: Optional[Dict[str, str]] = None,
    ) -> Any:
        """
        Create an EAP message.
        
        Args:
            action_type: Type of action ("set_pose", "gripper", "cloud", "sim")
            action_data: Action-specific data
            message_id: Unique ID for the message (optional, generated if not provided)
            state_sha: SHA-256 hash of perceptual snapshot (optional)
            meta: Optional metadata key-value pairs
            
        Returns:
            eap_message: EAP message
        """
        # Generate message ID if not provided
        if message_id is None:
            message_id = str(uuid.uuid4())
        
        # Generate state_sha if not provided
        if state_sha is None:
            # Create a dummy hash if no state snapshot is available
            # In production, this should be a hash of the actual perceptual state
            state_sha = hashlib.sha256(f"dummy_state_{time.time()}".encode()).digest()
        
        # Create EAP message
        EAP = self._get_eap_message_class()
        eap_message = EAP()
        
        # Set common fields
        eap_message.spec = "eap/0.1"
        eap_message.id = message_id
        eap_message.state_sha = state_sha
        
        # Set action-specific fields
        if isinstance(action_data, dict):
            # Convert dictionary to action message
            action_class = self._get_action_class(action_type)
            action = action_class()
            
            for key, value in action_data.items():
                if hasattr(action, key):
                    setattr(action, key, value)
            
            # Set action field
            if action_type == "set_pose":
                eap_message.set_pose.CopyFrom(action)
            elif action_type == "gripper":
                eap_message.gripper.CopyFrom(action)
            elif action_type == "cloud":
                eap_message.cloud.CopyFrom(action)
            elif action_type == "sim":
                eap_message.sim.CopyFrom(action)
        else:
            # Action data is already a protobuf message
            if action_type == "set_pose":
                eap_message.set_pose.CopyFrom(action_data)
            elif action_type == "gripper":
                eap_message.gripper.CopyFrom(action_data)
            elif action_type == "cloud":
                eap_message.cloud.CopyFrom(action_data)
            elif action_type == "sim":
                eap_message.sim.CopyFrom(action_data)
        
        # Set metadata
        if meta:
            for key, value in meta.items():
                eap_message.meta[key] = value
        
        return eap_message
    
    async def open_log_file(self, log_name: Optional[str] = None):
        """
        Open an action log file.
        
        Args:
            log_name: Name of the log file (default: "eap_{timestamp}.eaplog")
        """
        async with self.log_lock:
            # Close existing log file if open
            if self.log_file and not self.log_file.closed:
                self.log_file.close()
            
            # Generate log file name if not provided
            if log_name is None:
                timestamp = int(time.time())
                log_name = f"eap_{timestamp}.eaplog"
            
            # Ensure .eaplog extension
            if not log_name.endswith(".eaplog"):
                log_name += ".eaplog"
            
            # Open log file
            log_path = os.path.join(self.log_dir, log_name)
            self.log_file = open(log_path, "ab")
            
            logger.info(f"Opened EAP action log file: {log_path}")
    
    async def close_log_file(self):
        """Close the action log file."""
        async with self.log_lock:
            if self.log_file and not self.log_file.closed:
                self.log_file.close()
                self.log_file = None
                logger.info("Closed EAP action log file")
    
    async def log_action(self, eap_message):
        """
        Log an EAP action to the .eaplog file.
        
        Args:
            eap_message: EAP message to log
        """
        async with self.log_lock:
            # Ensure log file is open
            if not self.log_file or self.log_file.closed:
                await self.open_log_file()
            
            # Serialize message
            serialized = self.serializer.serialize(eap_message, use_json=False)
            
            # Write message size and message
            self.log_file.write(len(serialized).to_bytes(4, byteorder="little"))
            self.log_file.write(serialized)
            self.log_file.flush()
    
    async def send(
        self,
        action_type: str,
        action_data: Any,
        message_id: Optional[str] = None,
        state_sha: Optional[bytes] = None,
        meta: Optional[Dict[str, str]] = None,
        topic: str = "eap",
        qos: Optional[Dict[str, Any]] = None,
        log_action: bool = True,
    ) -> str:
        """
        Send an EAP message.
        
        Args:
            action_type: Type of action ("set_pose", "gripper", "cloud", "sim")
            action_data: Action-specific data
            message_id: Unique ID for the message (optional, generated if not provided)
            state_sha: SHA-256 hash of perceptual snapshot (optional)
            meta: Optional metadata key-value pairs
            topic: Topic to publish to (default: "eap")
            qos: Quality of Service parameters
            log_action: Whether to log the action to .eaplog file (default: True)
            
        Returns:
            message_id: ID of the sent message
        """
        # Create EAP message
        eap_message = self.create_eap_message(
            action_type,
            action_data,
            message_id,
            state_sha,
            meta,
        )
        
        # Create a span if telemetry is available
        span = None
        start_time = None
        if self.telemetry:
            span = self.telemetry.create_span(
                "eap.send",
                kind=trace.SpanKind.PRODUCER,
                attributes={
                    "topic": topic,
                    "message_id": eap_message.id,
                    "action_type": action_type,
                },
            )
            start_time = time.time()
        
        try:
            # Publish message
            await self.transport.publish(topic, eap_message, qos)
            
            # Log action if requested
            if log_action:
                await self.log_action(eap_message)
            
            # Record metrics if telemetry is available
            if self.telemetry and start_time:
                latency_ms = (time.time() - start_time) * 1000.0
                self.telemetry.record_eap_latency(
                    latency_ms,
                    attributes={
                        "action_type": action_type,
                    },
                )
            
            # Return message ID
            return eap_message.id
        except Exception as e:
            logger.error(f"Error sending EAP message: {e}")
            if span:
                span.record_exception(e)
            raise
        finally:
            # End span if created
            if span:
                span.end()
    
    async def listen(
        self,
        handlers: List[Callable],
        topic: str = "eap",
        qos: Optional[Dict[str, Any]] = None,
        log_actions: bool = True,
    ):
        """
        Listen for EAP messages and process them.
        
        Args:
            handlers: List of callback functions to handle received messages
            topic: Topic to subscribe to (default: "eap")
            qos: Quality of Service parameters
            log_actions: Whether to log received actions to .eaplog file (default: True)
        """
        # Get EAP message class
        EAP = self._get_eap_message_class()
        
        # Define message handler
        async def message_handler(eap_message):
            # Create a span if telemetry is available
            span = None
            start_time = None
            if self.telemetry:
                # Determine action type
                action_type = None
                if eap_message.HasField("set_pose"):
                    action_type = "set_pose"
                elif eap_message.HasField("gripper"):
                    action_type = "gripper"
                elif eap_message.HasField("cloud"):
                    action_type = "cloud"
                elif eap_message.HasField("sim"):
                    action_type = "sim"
                
                span = self.telemetry.create_span(
                    "eap.receive",
                    kind=trace.SpanKind.CONSUMER,
                    attributes={
                        "topic": topic,
                        "message_id": eap_message.id,
                        "action_type": action_type,
                    },
                )
                start_time = time.time()
            
            try:
                # Log action if requested
                if log_actions:
                    await self.log_action(eap_message)
                
                # Call all handlers
                for handler in handlers:
                    try:
                        await handler(eap_message)
                    except Exception as e:
                        logger.error(f"Error in EAP handler: {e}")
                        if span:
                            span.record_exception(e)
                
                # Record metrics if telemetry is available
                if self.telemetry and start_time:
                    latency_ms = (time.time() - start_time) * 1000.0
                    self.telemetry.record_eap_latency(
                        latency_ms,
                        attributes={
                            "action_type": action_type,
                        },
                    )
            finally:
                # End span if created
                if span:
                    span.end()
        
        # Subscribe to topic
        await self.transport.subscribe(topic, message_handler, EAP, qos)
        
        # Open log file if logging actions
        if log_actions:
            await self.open_log_file()
        
        logger.debug(f"Subscribed to EAP messages on topic {topic}")
    
    async def create_robot_pose(
        self,
        x: float,
        y: float,
        z: float,
        qw: float,
        qx: float,
        qy: float,
        qz: float,
    ) -> Any:
        """
        Create a RobotPose message.
        
        Args:
            x: X coordinate
            y: Y coordinate
            z: Z coordinate
            qw: Quaternion w component
            qx: Quaternion x component
            qy: Quaternion y component
            qz: Quaternion z component
            
        Returns:
            pose: RobotPose message
        """
        RobotPose = self._get_action_class("set_pose")
        pose = RobotPose()
        
        pose.x = x
        pose.y = y
        pose.z = z
        pose.qw = qw
        pose.qx = qx
        pose.qy = qy
        pose.qz = qz
        
        return pose
    
    async def create_gripper_op(
        self,
        command: Union[int, str],
        position: float = 0.0,
        force_limit: float = 0.0,
    ) -> Any:
        """
        Create a GripperOp message.
        
        Args:
            command: GripperCommand enum value or name ("OPEN", "CLOSE", "GRIP")
            position: Gripper position (0.0 = closed, 1.0 = open)
            force_limit: Force limit in Newtons
            
        Returns:
            gripper_op: GripperOp message
        """
        GripperOp = self._get_action_class("gripper")
        gripper_op = GripperOp()
        
        # Handle string command names
        if isinstance(command, str):
            if hasattr(GripperOp, "GripperCommand"):
                GripperCommand = GripperOp.GripperCommand
                if hasattr(GripperCommand, command):
                    command = getattr(GripperCommand, command)
                else:
                    raise ValueError(f"Unknown GripperCommand: {command}")
            else:
                raise AttributeError("GripperOp has no GripperCommand enum")
        
        gripper_op.command = command
        gripper_op.position = position
        gripper_op.force_limit = force_limit
        
        return gripper_op
    
    async def create_cloud_op(
        self,
        api_name: str,
        method_name: str,
        json_payload: bytes,
        requires_oauth2: bool = False,
    ) -> Any:
        """
        Create a CloudOp message.
        
        Args:
            api_name: Name of the API (e.g., "object_detection_service")
            method_name: Name of the method (e.g., "detect_objects")
            json_payload: JSON payload for the API call
            requires_oauth2: Whether OAuth 2 authentication is required
            
        Returns:
            cloud_op: CloudOp message
        """
        CloudOp = self._get_action_class("cloud")
        cloud_op = CloudOp()
        
        cloud_op.api_name = api_name
        cloud_op.method_name = method_name
        cloud_op.json_payload = json_payload
        cloud_op.requires_oauth2 = requires_oauth2
        
        return cloud_op
    
    async def create_sim_step(self, duration_s: float) -> Any:
        """
        Create a SimStep message.
        
        Args:
            duration_s: Simulation step duration in seconds
            
        Returns:
            sim_step: SimStep message
        """
        SimStep = self._get_action_class("sim")
        sim_step = SimStep()
        
        sim_step.duration_s = duration_s
        
        return sim_step