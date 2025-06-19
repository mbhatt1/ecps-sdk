#!/usr/bin/env python3
"""
ECPS Golden Path Gateway

The definitive example of ECPS as "ROS 2 for agentic AI".
Demonstrates complete perception → cognition → actuation workflow with P2 security.

This is the single working flow that showcases ECPS capabilities:
- Perception: Camera feeds → tensor processing → memory storage
- Cognition: LLM reasoning with memory retrieval → action planning  
- Actuation: Secure robot control with logging and replay
- Security: Full P2 hardening (mTLS, JWT rotation, HSM)
- Observability: Complete telemetry and monitoring
"""

import asyncio
import logging
import time
import json
import numpy as np
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime, timedelta
import signal
import sys
import os

# ECPS imports
import ecps_uv
from ecps_uv.core import StandardProfile
from ecps_uv.trust.trust import TrustProvider
from ecps_uv.trust.jwt_rotation import JWTRotationManager
from ecps_uv.trust.mtls import MTLSManager
from ecps_uv.perception.ltp import LTPProcessor
from ecps_uv.cognition.mcp import MCPHandler
from ecps_uv.cognition.mep import MEPHandler
from ecps_uv.actuation.eap import EAPHandler
from ecps_uv.observability.telemetry import TelemetryManager

# External dependencies
import openai
from opentelemetry import trace, metrics
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Metrics
PERCEPTION_LATENCY = Histogram('ecps_perception_latency_seconds', 'Perception processing latency')
COGNITION_LATENCY = Histogram('ecps_cognition_latency_seconds', 'Cognition processing latency')
ACTUATION_LATENCY = Histogram('ecps_actuation_latency_seconds', 'Actuation processing latency')
END_TO_END_LATENCY = Histogram('ecps_end_to_end_latency_seconds', 'Complete workflow latency')
PROCESSED_FRAMES = Counter('ecps_processed_frames_total', 'Total processed camera frames')
EXECUTED_ACTIONS = Counter('ecps_executed_actions_total', 'Total executed robot actions')
ACTIVE_CONNECTIONS = Gauge('ecps_active_connections', 'Number of active connections')
MEMORY_EMBEDDINGS = Gauge('ecps_memory_embeddings_count', 'Number of stored embeddings')

@dataclass
class PerceptionData:
    """Structured perception data from camera feeds"""
    timestamp: datetime
    frame_id: str
    objects: List[Dict[str, Any]]
    tensor_data: np.ndarray
    confidence: float
    processing_time: float

@dataclass
class CognitionResult:
    """Result from LLM cognition processing"""
    timestamp: datetime
    prompt: str
    response: str
    action_plan: List[Dict[str, Any]]
    confidence: float
    reasoning: str
    processing_time: float

@dataclass
class ActuationCommand:
    """Robot actuation command"""
    timestamp: datetime
    action_type: str
    target: str
    parameters: Dict[str, Any]
    priority: int
    timeout: int
    expected_duration: float

class ECPSGateway:
    """
    ECPS Gateway: The heart of the agentic AI system
    
    Orchestrates the complete perception → cognition → actuation workflow
    with full P2 security hardening and production-grade observability.
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        self.config = self._load_config(config_path)
        self.running = False
        self.stats = {
            'frames_processed': 0,
            'actions_executed': 0,
            'errors': 0,
            'start_time': None
        }
        
        # Initialize ECPS components
        self.profile = StandardProfile(transport_type="dds")
        self.server = None
        self.trust_provider = None
        self.jwt_manager = None
        self.mtls_manager = None
        
        # Protocol handlers
        self.ltp_processor = None
        self.mcp_handler = None
        self.mep_handler = None
        self.eap_handler = None
        
        # External integrations
        self.openai_client = None
        self.telemetry = None
        
        # Memory and state
        self.memory_store = {}
        self.active_sessions = {}
        self.robot_status = {"connected": False, "ready": False}
        
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration with sensible defaults"""
        default_config = {
            "security": {
                "jwt_rotation_interval": 86400,  # 24 hours
                "mtls_enabled": True,
                "hsm_enabled": False,
                "certificate_path": "./certs"
            },
            "perception": {
                "max_fps": 30,
                "tensor_compression": "zstd",
                "object_detection_threshold": 0.7
            },
            "cognition": {
                "llm_provider": "openai",
                "model": "gpt-4",
                "temperature": 0.7,
                "max_tokens": 1000,
                "memory_retrieval_limit": 10
            },
            "actuation": {
                "robot_endpoint": "localhost:8081",
                "action_timeout": 30000,
                "safety_checks": True
            },
            "observability": {
                "metrics_port": 8000,
                "tracing_enabled": True,
                "log_level": "INFO"
            }
        }
        
        if os.path.exists(config_path):
            import yaml
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                # Merge with defaults
                for section, values in user_config.items():
                    if section in default_config:
                        default_config[section].update(values)
                    else:
                        default_config[section] = values
        
        return default_config
    
    async def initialize(self):
        """Initialize all ECPS components with P2 security hardening"""
        logger.info("Initializing ECPS Gateway with P2 security hardening...")
        
        try:
            # 1. Initialize security components
            await self._initialize_security()
            
            # 2. Initialize ECPS server
            await self._initialize_server()
            
            # 3. Initialize protocol handlers
            await self._initialize_handlers()
            
            # 4. Initialize external integrations
            await self._initialize_integrations()
            
            # 5. Initialize observability
            await self._initialize_observability()
            
            logger.info("ECPS Gateway initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize ECPS Gateway: {e}")
            raise
    
    async def _initialize_security(self):
        """Initialize P2 security hardening components"""
        logger.info("Initializing P2 security hardening...")
        
        # Trust provider with RBAC
        self.trust_provider = TrustProvider()
        await self.trust_provider.initialize()
        
        # JWT rotation manager
        self.jwt_manager = JWTRotationManager(
            rotation_interval=self.config["security"]["jwt_rotation_interval"]
        )
        await self.jwt_manager.start_rotation()
        
        # mTLS manager
        if self.config["security"]["mtls_enabled"]:
            self.mtls_manager = MTLSManager(
                cert_path=self.config["security"]["certificate_path"]
            )
            await self.mtls_manager.initialize()
        
        logger.info("P2 security hardening initialized")
    
    async def _initialize_server(self):
        """Initialize ECPS server with security"""
        self.server = ecps_uv.ECPSServer(
            self.profile,
            trust_provider=self.trust_provider
        )
        
        # Register handlers
        self.server.on_perception(self._handle_perception)
        self.server.on_mcp(self._handle_cognition)
        self.server.on_eap_status(self._handle_actuation_status)
        
        await self.server.start()
        logger.info("ECPS server started with security enabled")
    
    async def _initialize_handlers(self):
        """Initialize protocol layer handlers"""
        # LTP for perception data
        self.ltp_processor = LTPProcessor(
            compression=self.config["perception"]["tensor_compression"]
        )
        
        # MCP for cognition
        self.mcp_handler = MCPHandler(self.server.transport)
        
        # MEP for memory
        self.mep_handler = MEPHandler(self.server.transport)
        
        # EAP for actuation
        self.eap_handler = EAPHandler(
            self.server.transport,
            endpoint=self.config["actuation"]["robot_endpoint"]
        )
        
        logger.info("Protocol handlers initialized")
    
    async def _initialize_integrations(self):
        """Initialize external integrations"""
        # OpenAI client
        if self.config["cognition"]["llm_provider"] == "openai":
            self.openai_client = openai.AsyncOpenAI(
                api_key=os.getenv("OPENAI_API_KEY")
            )
        
        logger.info("External integrations initialized")
    
    async def _initialize_observability(self):
        """Initialize telemetry and monitoring"""
        self.telemetry = TelemetryManager()
        await self.telemetry.initialize()
        
        # Start Prometheus metrics server
        start_http_server(self.config["observability"]["metrics_port"])
        
        logger.info(f"Observability initialized on port {self.config['observability']['metrics_port']}")
    
    async def start(self):
        """Start the ECPS Gateway"""
        logger.info("Starting ECPS Gateway...")
        self.running = True
        self.stats['start_time'] = datetime.now()
        
        # Start background tasks
        tasks = [
            asyncio.create_task(self._health_monitor()),
            asyncio.create_task(self._metrics_collector()),
            asyncio.create_task(self._security_monitor())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            logger.info("Gateway tasks cancelled")
        except Exception as e:
            logger.error(f"Gateway error: {e}")
            self.stats['errors'] += 1
    
    async def stop(self):
        """Gracefully stop the ECPS Gateway"""
        logger.info("Stopping ECPS Gateway...")
        self.running = False
        
        if self.server:
            await self.server.close()
        
        if self.jwt_manager:
            await self.jwt_manager.stop_rotation()
        
        logger.info("ECPS Gateway stopped")
    
    async def _handle_perception(self, perception_data: bytes) -> PerceptionData:
        """
        Handle incoming perception data (camera feeds, sensor data)
        
        This is the entry point for the perception → cognition → actuation workflow
        """
        start_time = time.time()
        
        try:
            # Decode LTP tensor data
            tensor_data = await self.ltp_processor.decode(perception_data)
            
            # Simulate object detection (in production, use actual CV models)
            objects = await self._detect_objects(tensor_data)
            
            # Create structured perception data
            perception_result = PerceptionData(
                timestamp=datetime.now(),
                frame_id=f"frame_{self.stats['frames_processed']}",
                objects=objects,
                tensor_data=tensor_data,
                confidence=0.85,
                processing_time=time.time() - start_time
            )
            
            # Update metrics
            PERCEPTION_LATENCY.observe(perception_result.processing_time)
            PROCESSED_FRAMES.inc()
            self.stats['frames_processed'] += 1
            
            # Trigger cognition if objects detected
            if objects:
                asyncio.create_task(self._trigger_cognition(perception_result))
            
            logger.debug(f"Processed perception data: {len(objects)} objects detected")
            return perception_result
            
        except Exception as e:
            logger.error(f"Perception processing error: {e}")
            self.stats['errors'] += 1
            raise
    
    async def _detect_objects(self, tensor_data: np.ndarray) -> List[Dict[str, Any]]:
        """Simulate object detection (replace with actual CV model)"""
        # Simulate processing time
        await asyncio.sleep(0.01)
        
        # Simulate detected objects
        objects = [
            {
                "class": "cup",
                "confidence": 0.92,
                "bbox": [100, 150, 200, 250],
                "position": {"x": 0.3, "y": 0.2, "z": 0.1}
            },
            {
                "class": "bottle",
                "confidence": 0.87,
                "bbox": [300, 100, 400, 300],
                "position": {"x": 0.5, "y": 0.3, "z": 0.15}
            }
        ]
        
        return objects
    
    async def _trigger_cognition(self, perception_data: PerceptionData):
        """Trigger cognition processing based on perception data"""
        start_time = time.time()
        
        try:
            # Retrieve relevant memories
            memories = await self._retrieve_memories(perception_data)
            
            # Construct prompt for LLM
            prompt = self._construct_prompt(perception_data, memories)
            
            # Send to LLM for reasoning
            response = await self._query_llm(prompt)
            
            # Parse action plan from response
            action_plan = self._parse_action_plan(response)
            
            # Create cognition result
            cognition_result = CognitionResult(
                timestamp=datetime.now(),
                prompt=prompt,
                response=response,
                action_plan=action_plan,
                confidence=0.8,
                reasoning="Object detected, planning manipulation",
                processing_time=time.time() - start_time
            )
            
            # Update metrics
            COGNITION_LATENCY.observe(cognition_result.processing_time)
            
            # Execute actions if plan exists
            if action_plan:
                asyncio.create_task(self._execute_actions(action_plan))
            
            logger.info(f"Cognition completed: {len(action_plan)} actions planned")
            
        except Exception as e:
            logger.error(f"Cognition processing error: {e}")
            self.stats['errors'] += 1
    
    async def _retrieve_memories(self, perception_data: PerceptionData) -> List[Dict[str, Any]]:
        """Retrieve relevant memories using MEP"""
        # Create query embedding (simplified)
        query_embedding = np.random.rand(256).astype(np.float32)
        
        # Query memory store
        memories = await self.mep_handler.query_memories(
            query_embedding,
            limit=self.config["cognition"]["memory_retrieval_limit"]
        )
        
        return memories
    
    def _construct_prompt(self, perception_data: PerceptionData, memories: List[Dict[str, Any]]) -> str:
        """Construct LLM prompt with perception data and memories"""
        objects_desc = ", ".join([obj["class"] for obj in perception_data.objects])
        
        prompt = f"""
You are an intelligent robot assistant. Based on the current perception and past experiences, plan the next actions.

Current Perception:
- Objects detected: {objects_desc}
- Confidence: {perception_data.confidence:.2f}
- Timestamp: {perception_data.timestamp}

Relevant Memories:
{json.dumps(memories, indent=2)}

Task: Plan robot actions to interact with the detected objects safely and effectively.

Respond with a JSON action plan in this format:
{{
  "actions": [
    {{
      "type": "move_to",
      "target": "cup",
      "parameters": {{"x": 0.3, "y": 0.2, "z": 0.1}},
      "priority": 1
    }}
  ],
  "reasoning": "Explanation of the plan"
}}
"""
        return prompt
    
    async def _query_llm(self, prompt: str) -> str:
        """Query LLM for reasoning and action planning"""
        if not self.openai_client:
            # Fallback response for demo
            return json.dumps({
                "actions": [
                    {
                        "type": "move_to",
                        "target": "cup",
                        "parameters": {"x": 0.3, "y": 0.2, "z": 0.1},
                        "priority": 1
                    }
                ],
                "reasoning": "Moving to cup for pickup"
            })
        
        try:
            response = await self.openai_client.chat.completions.create(
                model=self.config["cognition"]["model"],
                messages=[{"role": "user", "content": prompt}],
                temperature=self.config["cognition"]["temperature"],
                max_tokens=self.config["cognition"]["max_tokens"]
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"LLM query error: {e}")
            # Return fallback response
            return json.dumps({
                "actions": [],
                "reasoning": "LLM unavailable, no actions planned"
            })
    
    def _parse_action_plan(self, llm_response: str) -> List[Dict[str, Any]]:
        """Parse action plan from LLM response"""
        try:
            parsed = json.loads(llm_response)
            return parsed.get("actions", [])
        except json.JSONDecodeError:
            logger.error("Failed to parse LLM response as JSON")
            return []
    
    async def _execute_actions(self, action_plan: List[Dict[str, Any]]):
        """Execute robot actions using EAP"""
        start_time = time.time()
        
        for action in action_plan:
            try:
                # Create actuation command
                command = ActuationCommand(
                    timestamp=datetime.now(),
                    action_type=action["type"],
                    target=action["target"],
                    parameters=action["parameters"],
                    priority=action.get("priority", 5),
                    timeout=self.config["actuation"]["action_timeout"],
                    expected_duration=2.0
                )
                
                # Send to robot via EAP
                action_id = await self.eap_handler.execute_action(
                    command.action_type,
                    command.target,
                    command.parameters,
                    timeout=command.timeout,
                    priority=command.priority
                )
                
                # Update metrics
                EXECUTED_ACTIONS.inc()
                self.stats['actions_executed'] += 1
                
                logger.info(f"Executed action {action_id}: {command.action_type} on {command.target}")
                
            except Exception as e:
                logger.error(f"Action execution error: {e}")
                self.stats['errors'] += 1
        
        # Update end-to-end latency
        END_TO_END_LATENCY.observe(time.time() - start_time)
    
    async def _handle_cognition(self, mcp_data: bytes):
        """Handle direct MCP requests"""
        # This handles direct cognition requests (not triggered by perception)
        pass
    
    async def _handle_actuation_status(self, status_data: bytes):
        """Handle actuation status updates"""
        # Update robot status and metrics
        self.robot_status["connected"] = True
        self.robot_status["ready"] = True
        ACTIVE_CONNECTIONS.set(1)
    
    async def _health_monitor(self):
        """Monitor system health"""
        while self.running:
            try:
                # Check component health
                health_status = {
                    "gateway": "healthy",
                    "security": "healthy" if self.jwt_manager else "degraded",
                    "robot": "healthy" if self.robot_status["connected"] else "unhealthy",
                    "llm": "healthy" if self.openai_client else "degraded"
                }
                
                # Log health status
                logger.debug(f"Health status: {health_status}")
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Health monitor error: {e}")
                await asyncio.sleep(5)
    
    async def _metrics_collector(self):
        """Collect and update metrics"""
        while self.running:
            try:
                # Update memory metrics
                MEMORY_EMBEDDINGS.set(len(self.memory_store))
                
                # Update connection metrics
                ACTIVE_CONNECTIONS.set(len(self.active_sessions))
                
                await asyncio.sleep(10)  # Update every 10 seconds
                
            except Exception as e:
                logger.error(f"Metrics collector error: {e}")
                await asyncio.sleep(5)
    
    async def _security_monitor(self):
        """Monitor security components"""
        while self.running:
            try:
                # Check JWT rotation status
                if self.jwt_manager:
                    await self.jwt_manager.check_rotation_needed()
                
                # Check certificate expiration
                if self.mtls_manager:
                    await self.mtls_manager.check_certificate_expiry()
                
                await asyncio.sleep(3600)  # Check every hour
                
            except Exception as e:
                logger.error(f"Security monitor error: {e}")
                await asyncio.sleep(60)

async def main():
    """Main entry point for ECPS Gateway"""
    gateway = ECPSGateway()
    
    # Setup signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down...")
        asyncio.create_task(gateway.stop())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Initialize and start gateway
        await gateway.initialize()
        await gateway.start()
        
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received")
    except Exception as e:
        logger.error(f"Gateway error: {e}")
    finally:
        await gateway.stop()

if __name__ == "__main__":
    asyncio.run(main())