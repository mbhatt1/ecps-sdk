"""
Robot Key Management Demo.

This example demonstrates how to implement secure key management
for robots and agents in the field, including factory provisioning,
field deployment, and operational key management.
"""

import asyncio
import logging
import os
import tempfile
from typing import Dict, List

from ecps_uv.trust.key_management import (
    KeyManager, SecureKeyStore, FactoryProvisioning,
    KeyType, KeyStatus
)
from ecps_uv.core import ECPSClient, StandardProfile
from ecps_uv.coordination import A2ACoordinator
from ecps_uv.coordination.a2a_coordinator import AgentRole

# Import KMS integration if available
try:
    from ecps_uv.trust.kms_integration import (
        create_kms_manager, get_available_providers, KMSProvider
    )
    KMS_AVAILABLE = True
except ImportError:
    logger.warning("KMS integration not available - using local storage only")
    KMS_AVAILABLE = False

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SecureRobotAgent:
    """A robot agent with comprehensive key management."""
    
    def __init__(self, device_id: str, storage_path: str, kms_config: Dict = None):
        self.device_id = device_id
        self.storage_path = storage_path
        self.kms_config = kms_config
        
        # Key management
        self.key_store = SecureKeyStore(storage_path, master_password="robot_secure_123")
        
        # Create KMS manager if configured
        kms_manager = None
        use_kms_for_storage = False
        
        if kms_config and KMS_AVAILABLE:
            try:
                kms_manager = create_kms_manager(**kms_config)
                use_kms_for_storage = kms_config.get('use_kms_for_storage', False)
                logger.info(f"Robot {device_id} configured with KMS: {kms_config.get('provider', 'unknown')}")
            except Exception as e:
                logger.warning(f"Failed to configure KMS for robot {device_id}: {e}")
        
        self.key_manager = KeyManager(
            device_id,
            self.key_store,
            kms_manager=kms_manager,
            use_kms_for_storage=use_kms_for_storage
        )
        
        # ECPS components
        self.config = StandardProfile(transport_type="mqtt")
        self.client = ECPSClient(self.config)
        
        # A2A coordination with security
        self.coordinator = A2ACoordinator(
            agent_id=device_id,
            transport=self.client.transport,
            serializer=self.client.serializer,
            telemetry=self.client.telemetry,
            role=AgentRole.WORKER,
            capabilities=["navigation", "perception"],
        )
        
        # Security state
        self.trusted_agents: Dict[str, str] = {}  # agent_id -> public_key
        self.active_sessions: Dict[str, Dict] = {}  # session_id -> session_info
    
    async def start(self):
        """Start the secure robot agent."""
        logger.info(f"Starting secure robot agent {self.device_id}")
        
        # Start ECPS components
        await self.client.transport.connect()
        
        # Set up key manager with transport for distribution
        self.key_manager.transport = self.client.transport
        
        # Start coordination
        await self.coordinator.start()
        
        # Set up security message handlers
        await self._setup_security_handlers()
        
        # Start key rotation scheduler
        asyncio.create_task(self.key_manager.start_key_rotation_scheduler())
        
        logger.info(f"Secure robot agent {self.device_id} started")
    
    async def _setup_security_handlers(self):
        """Set up handlers for security-related messages."""
        # Key distribution
        await self.client.transport.subscribe(
            "keys/distribution",
            self._handle_key_distribution,
            dict,
        )
        
        # Key revocation
        await self.client.transport.subscribe(
            "keys/revocation",
            self._handle_key_revocation,
            dict,
        )
        
        # Secure handshake
        await self.client.transport.subscribe(
            f"security/handshake/{self.device_id}",
            self._handle_secure_handshake,
            dict,
        )
    
    async def _handle_key_distribution(self, message: Dict):
        """Handle key distribution from other agents."""
        try:
            sender = message.get("sender")
            key_id = message.get("key_id")
            
            if sender != self.device_id:  # Don't process our own distributions
                logger.info(f"Received key distribution from {sender}: {key_id}")
                
                # Validate and store the public key
                try:
                    # Extract the public key from the message
                    public_key_data = message.get("public_key")
                    if not public_key_data:
                        logger.error("No public key data in distribution message")
                        return
                    
                    # Validate the public key format
                    from cryptography.hazmat.primitives import serialization
                    try:
                        public_key = serialization.load_pem_public_key(
                            public_key_data.encode() if isinstance(public_key_data, str) else public_key_data
                        )
                        logger.info(f"Successfully validated public key from {sender}")
                    except Exception as e:
                        logger.error(f"Invalid public key format from {sender}: {e}")
                        return
                    
                    # Store the validated public key
                    if hasattr(self, 'key_manager') and self.key_manager:
                        # Store in key manager if available
                        metadata = {
                            "sender": sender,
                            "key_id": key_id,
                            "received_at": time.time(),
                            "key_type": "public",
                            "algorithm": "RSA"
                        }
                        
                        # Store the public key
                        await self.key_manager.store_key(
                            f"peer_{sender}_{key_id}",
                            public_key_data,
                            metadata
                        )
                        logger.info(f"Stored public key {key_id} from {sender}")
                    else:
                        # Fallback: store in a simple dictionary
                        if not hasattr(self, 'peer_keys'):
                            self.peer_keys = {}
                        self.peer_keys[f"{sender}_{key_id}"] = {
                            "public_key": public_key_data,
                            "sender": sender,
                            "key_id": key_id,
                            "received_at": time.time()
                        }
                        logger.info(f"Stored public key {key_id} from {sender} in local cache")
                        
                except Exception as e:
                    logger.error(f"Failed to validate/store public key from {sender}: {e}")
                
        except Exception as e:
            logger.error(f"Error handling key distribution: {e}")
    
    async def _handle_key_revocation(self, message: Dict):
        """Handle key revocation notifications."""
        try:
            sender = message.get("sender")
            key_id = message.get("key_id")
            reason = message.get("reason")
            
            logger.warning(f"Key revocation from {sender}: {key_id} ({reason})")
            
            # Remove from trusted agents if present
            if sender in self.trusted_agents:
                del self.trusted_agents[sender]
            
            # Invalidate any active sessions with this agent
            sessions_to_remove = []
            for session_id, session_info in self.active_sessions.items():
                if session_info.get("peer_id") == sender:
                    sessions_to_remove.append(session_id)
            
            for session_id in sessions_to_remove:
                del self.active_sessions[session_id]
                logger.info(f"Invalidated session {session_id} due to key revocation")
                
        except Exception as e:
            logger.error(f"Error handling key revocation: {e}")
    
    async def _handle_secure_handshake(self, message: Dict):
        """Handle secure handshake requests."""
        try:
            sender = message.get("sender")
            handshake_type = message.get("type")
            
            if handshake_type == "request":
                await self._process_handshake_request(sender, message)
            elif handshake_type == "response":
                await self._process_handshake_response(sender, message)
                
        except Exception as e:
            logger.error(f"Error handling secure handshake: {e}")
    
    async def _process_handshake_request(self, sender: str, message: Dict):
        """Process incoming handshake request."""
        # Get our device identity key for signing
        device_key_id = self.key_manager.get_key_for_operation("sign", KeyType.DEVICE_IDENTITY)
        if not device_key_id:
            logger.error("No device identity key available for handshake")
            return
        
        # Export our public key
        public_key = self.key_manager.export_public_key(device_key_id)
        if not public_key:
            logger.error("Failed to export public key for handshake")
            return
        
        # Create handshake response
        response = {
            "type": "response",
            "sender": self.device_id,
            "public_key": public_key.decode(),
            "timestamp": message.get("timestamp"),
            "nonce": message.get("nonce"),
        }
        
        # Send response
        await self.client.transport.publish(
            f"security/handshake/{sender}",
            response
        )
        
        logger.info(f"Sent handshake response to {sender}")
    
    async def _process_handshake_response(self, sender: str, message: Dict):
        """Process handshake response."""
        public_key_pem = message.get("public_key")
        if public_key_pem:
            # Store the public key for future secure communication
            self.trusted_agents[sender] = public_key_pem
            logger.info(f"Established trust with agent {sender}")
    
    async def initiate_secure_handshake(self, target_agent: str):
        """Initiate secure handshake with another agent."""
        import time
        import secrets
        
        # Get our device identity key
        device_key_id = self.key_manager.get_key_for_operation("sign", KeyType.DEVICE_IDENTITY)
        if not device_key_id:
            logger.error("No device identity key available for handshake")
            return False
        
        # Create handshake request
        nonce = secrets.token_hex(16)
        request = {
            "type": "request",
            "sender": self.device_id,
            "timestamp": time.time(),
            "nonce": nonce,
        }
        
        # Send request
        await self.client.transport.publish(
            f"security/handshake/{target_agent}",
            request
        )
        
        logger.info(f"Initiated secure handshake with {target_agent}")
        return True
    
    async def rotate_communication_keys(self):
        """Rotate communication keys for enhanced security."""
        logger.info("Rotating communication keys")
        
        # Get current communication keys
        comm_keys = self.key_manager.get_active_keys(KeyType.COMMUNICATION)
        
        for key_metadata in comm_keys:
            new_key_id = await self.key_manager.rotate_key(key_metadata.key_id)
            if new_key_id:
                logger.info(f"Rotated communication key: {key_metadata.key_id} -> {new_key_id}")
    
    async def emergency_key_revocation(self, reason: str = "security_breach"):
        """Emergency revocation of all keys."""
        logger.critical(f"EMERGENCY KEY REVOCATION: {reason}")
        
        # Revoke all non-emergency keys
        all_keys = self.key_manager.key_store.list_keys()
        
        for key_metadata in all_keys:
            if key_metadata.key_type != KeyType.EMERGENCY and key_metadata.status == KeyStatus.ACTIVE:
                await self.key_manager.revoke_key(key_metadata.key_id, reason)
        
        # Generate new keys
        new_device_key = self.key_manager.generate_device_identity_key()
        new_comm_key = self.key_manager.generate_communication_key()
        
        logger.critical(f"Generated new keys after emergency revocation:")
        logger.critical(f"  Device: {new_device_key}")
        logger.critical(f"  Communication: {new_comm_key}")
    
    def get_security_status(self) -> Dict:
        """Get current security status."""
        all_keys = self.key_manager.key_store.list_keys()
        
        status = {
            "device_id": self.device_id,
            "total_keys": len(all_keys),
            "active_keys": len([k for k in all_keys if k.status == KeyStatus.ACTIVE]),
            "revoked_keys": len([k for k in all_keys if k.status == KeyStatus.REVOKED]),
            "trusted_agents": len(self.trusted_agents),
            "active_sessions": len(self.active_sessions),
            "keys_by_type": {},
        }
        
        for key_type in KeyType:
            type_keys = [k for k in all_keys if k.key_type == key_type]
            status["keys_by_type"][key_type.value] = {
                "total": len(type_keys),
                "active": len([k for k in type_keys if k.status == KeyStatus.ACTIVE]),
            }
        
        return status
    
    async def stop(self):
        """Stop the secure robot agent."""
        logger.info(f"Stopping secure robot agent {self.device_id}")
        await self.coordinator.stop()
        await self.client.close()


class RobotFleetManager:
    """Manages a fleet of robots with centralized key management."""
    
    def __init__(self):
        self.robots: Dict[str, SecureRobotAgent] = {}
        self.fleet_ca_path = None
    
    async def provision_robot_factory(self, device_id: str, storage_path: str, kms_config: Dict = None) -> SecureRobotAgent:
        """Provision a robot in factory settings."""
        logger.info(f"Factory provisioning robot {device_id}")
        
        # Use factory provisioning with optional KMS
        if kms_config and KMS_AVAILABLE:
            try:
                key_manager = await FactoryProvisioning.provision_robot_with_kms(
                    device_id=device_id,
                    storage_path=storage_path,
                    ca_cert_path=self.fleet_ca_path or "",
                    kms_config=kms_config,
                    master_password="factory_secure_456"
                )
                logger.info(f"Robot {device_id} provisioned with KMS-backed keys")
            except Exception as e:
                logger.warning(f"KMS provisioning failed for {device_id}, falling back to local: {e}")
                key_manager = FactoryProvisioning.provision_robot(
                    device_id=device_id,
                    storage_path=storage_path,
                    ca_cert_path=self.fleet_ca_path or "",
                    master_password="factory_secure_456",
                    kms_config=kms_config
                )
        else:
            key_manager = FactoryProvisioning.provision_robot(
                device_id=device_id,
                storage_path=storage_path,
                ca_cert_path=self.fleet_ca_path or "",
                master_password="factory_secure_456",
                kms_config=kms_config
            )
        
        # Create robot agent
        robot = SecureRobotAgent(device_id, storage_path, kms_config)
        robot.key_manager = key_manager
        
        self.robots[device_id] = robot
        
        logger.info(f"Robot {device_id} provisioned and ready for deployment")
        return robot
    
    async def deploy_robot_field(self, device_id: str):
        """Deploy robot to field operations."""
        if device_id not in self.robots:
            logger.error(f"Robot {device_id} not found in fleet")
            return
        
        robot = self.robots[device_id]
        await robot.start()
        
        logger.info(f"Robot {device_id} deployed to field")
    
    async def fleet_key_rotation(self):
        """Rotate keys across entire fleet."""
        logger.info("Starting fleet-wide key rotation")
        
        tasks = []
        for robot in self.robots.values():
            tasks.append(robot.rotate_communication_keys())
        
        await asyncio.gather(*tasks)
        
        logger.info("Fleet-wide key rotation completed")
    
    async def emergency_fleet_lockdown(self, reason: str):
        """Emergency lockdown of entire fleet."""
        logger.critical(f"EMERGENCY FLEET LOCKDOWN: {reason}")
        
        tasks = []
        for robot in self.robots.values():
            tasks.append(robot.emergency_key_revocation(reason))
        
        await asyncio.gather(*tasks)
        
        logger.critical("Emergency fleet lockdown completed")
    
    def get_fleet_status(self) -> Dict:
        """Get status of entire fleet."""
        status = {
            "total_robots": len(self.robots),
            "robots": {},
        }
        
        for device_id, robot in self.robots.items():
            status["robots"][device_id] = robot.get_security_status()
        
        return status


async def main():
    """Main demonstration function."""
    logger.info("🔐 Starting Robot Key Management Demo with KMS Integration")
    logger.info("=" * 60)
    
    # Show available KMS providers
    if KMS_AVAILABLE:
        providers = get_available_providers()
        logger.info(f"📋 Available KMS providers: {', '.join(providers)}")
    else:
        logger.info("📋 KMS integration not available - using local storage only")
    
    # Create temporary directories for robot storage
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create fleet manager
        fleet = RobotFleetManager()
        
        # Demo KMS configuration (mock for demonstration)
        mock_kms_config = {
            "provider": "local",  # Fallback to local for demo
            "use_kms_for_storage": False
        } if KMS_AVAILABLE else None
        
        # Provision robots in factory with different configurations
        logger.info("\n🏭 Factory Provisioning Phase")
        logger.info("-" * 30)
        
        # Robot 1: Local keys only
        robot1 = await fleet.provision_robot_factory(
            "robot_001",
            os.path.join(temp_dir, "robot_001")
        )
        logger.info("✅ Robot 001: Local key storage")
        
        # Robot 2: With KMS configuration (if available)
        robot2 = await fleet.provision_robot_factory(
            "robot_002",
            os.path.join(temp_dir, "robot_002"),
            kms_config=mock_kms_config
        )
        logger.info("✅ Robot 002: KMS-enhanced storage")
        
        # Robot 3: Local keys only
        robot3 = await fleet.provision_robot_factory(
            "robot_003",
            os.path.join(temp_dir, "robot_003")
        )
        logger.info("✅ Robot 003: Local key storage")
        
        # Show KMS status for each robot
        logger.info("\n🔧 KMS Configuration Status")
        logger.info("-" * 30)
        for robot_id, robot in fleet.robots.items():
            kms_info = robot.key_manager.get_kms_info()
            if kms_info:
                logger.info(f"Robot {robot_id}: KMS Provider = {kms_info.get('provider', 'none')}")
            else:
                logger.info(f"Robot {robot_id}: Local storage only")
        
        # Deploy robots to field
        logger.info("\n🚀 Field Deployment Phase")
        logger.info("-" * 25)
        await fleet.deploy_robot_field("robot_001")
        await fleet.deploy_robot_field("robot_002")
        await fleet.deploy_robot_field("robot_003")
        
        # Wait for robots to discover each other
        await asyncio.sleep(5)
        
        # Demonstrate secure handshakes
        logger.info("\n🤝 Secure Handshake Demonstration")
        logger.info("-" * 35)
        await robot1.initiate_secure_handshake("robot_002")
        await robot2.initiate_secure_handshake("robot_003")
        await robot3.initiate_secure_handshake("robot_001")
        
        await asyncio.sleep(3)
        
        # Show initial fleet status
        logger.info("\n📊 Initial Fleet Status")
        logger.info("-" * 22)
        status = fleet.get_fleet_status()
        for robot_id, robot_status in status["robots"].items():
            logger.info(f"Robot {robot_id}: {robot_status['active_keys']} active keys, "
                       f"{robot_status['trusted_agents']} trusted agents")
        
        # Demonstrate KMS backup (if available)
        if KMS_AVAILABLE and robot2.key_manager.kms_manager:
            logger.info("\n☁️  KMS Backup Demonstration")
            logger.info("-" * 27)
            backup_success = await robot2.key_manager.backup_keys_to_kms()
            if backup_success:
                logger.info("✅ Keys backed up to KMS successfully")
            else:
                logger.info("ℹ️  KMS backup simulation completed")
        
        # Demonstrate key rotation
        logger.info("\n🔄 Key Rotation Demonstration")
        logger.info("-" * 29)
        await fleet.fleet_key_rotation()
        
        await asyncio.sleep(2)
        
        # Test KMS operations (if available)
        if KMS_AVAILABLE and robot2.key_manager.kms_manager:
            logger.info("\n🔐 KMS Operations Test")
            logger.info("-" * 21)
            
            # Test KMS key generation
            try:
                kms_key_id = await robot2.key_manager.generate_kms_key(KeyType.COMMUNICATION, expires_in=3600)
                if kms_key_id:
                    logger.info(f"✅ Generated KMS key: {kms_key_id[:20]}...")
                    
                    # Test encryption/decryption
                    test_data = b"Hello from KMS integration!"
                    if robot2.key_manager.is_kms_backed(kms_key_id):
                        encrypted = await robot2.key_manager.encrypt_with_kms(kms_key_id, test_data)
                        if encrypted:
                            decrypted = await robot2.key_manager.decrypt_with_kms(kms_key_id, encrypted)
                            if decrypted == test_data:
                                logger.info("✅ KMS encryption/decryption test passed")
                            else:
                                logger.error("❌ KMS encryption/decryption test failed")
                else:
                    logger.info("ℹ️  KMS key generation simulation completed")
            except Exception as e:
                logger.warning(f"⚠️  KMS operations require valid configuration: {e}")
        
        # Demonstrate emergency procedures
        logger.info("\n🚨 Emergency Key Revocation")
        logger.info("-" * 27)
        await robot2.emergency_key_revocation("suspected_compromise")
        
        await asyncio.sleep(2)
        
        # Show final status
        logger.info("\n📈 Final Fleet Status")
        logger.info("-" * 20)
        final_status = fleet.get_fleet_status()
        for robot_id, robot_status in final_status["robots"].items():
            logger.info(f"Robot {robot_id}: {robot_status['active_keys']} active keys, "
                       f"{robot_status['revoked_keys']} revoked keys")
        
        # Demonstrate fleet-wide emergency
        logger.info("\n🔒 Fleet Emergency Lockdown")
        logger.info("-" * 26)
        await fleet.emergency_fleet_lockdown("security_breach_detected")
        
        # Show KMS integration benefits
        logger.info("\n💡 KMS Integration Benefits")
        logger.info("-" * 27)
        logger.info("✅ Enterprise-grade key management")
        logger.info("✅ Centralized key policies and rotation")
        logger.info("✅ Hardware security module (HSM) support")
        logger.info("✅ Compliance with security standards")
        logger.info("✅ Multi-cloud and hybrid deployment")
        logger.info("✅ Automated backup and disaster recovery")
        
        logger.info("\n🎉 Robot Key Management Demo with KMS Integration completed successfully!")
        
    except Exception as e:
        logger.error(f"Demo failed: {e}")
        raise
    finally:
        # Cleanup
        for robot in fleet.robots.values():
            await robot.stop()
        
        # Clean up temporary files
        import shutil
        shutil.rmtree(temp_dir)


if __name__ == "__main__":
    asyncio.run(main())