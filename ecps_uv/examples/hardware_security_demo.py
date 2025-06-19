#!/usr/bin/env python3
"""
Hardware Security and Log Versioning Demo for ECPS-UV SDK.

This demo showcases the new hardware security integration and
versioned logging capabilities implemented for production readiness.
"""

import asyncio
import logging
import os
import tempfile
import time
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("hardware_security_demo")

# Import ECPS-UV components
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ecps_uv.trust.hardware_security import (
    HardwareSecurityManager, HardwareSecurityType, AttestationType,
    SecureBootValidator, get_hardware_identity, create_hardware_attestation,
    check_hardware_security_availability
)
from ecps_uv.actuation.log_versioning import (
    LogWriter, LogReader, LogMigrator, LogValidator, LogVersion
)
from ecps_uv.actuation.eap import EAPHandler
from ecps_uv.serialization.protobuf import ProtobufSerializer


class HardwareSecurityDemo:
    """Comprehensive demo of hardware security and logging features."""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ecps_hardware_demo_")
        self.hardware_manager = None
        
    async def run_demo(self):
        """Run the complete hardware security and logging demonstration."""
        logger.info("🔐 Starting ECPS-UV Hardware Security & Log Versioning Demo")
        logger.info("=" * 70)
        
        # Demo 1: Hardware Security Availability Check
        await self.demo_hardware_availability()
        
        # Demo 2: Hardware Security Manager
        await self.demo_hardware_security_manager()
        
        # Demo 3: Device Identity and Attestation
        await self.demo_device_identity_attestation()
        
        # Demo 4: Secure Boot Validation
        await self.demo_secure_boot_validation()
        
        # Demo 5: Log Versioning System
        await self.demo_log_versioning()
        
        # Demo 6: EAP Handler with Versioned Logging
        await self.demo_eap_versioned_logging()
        
        # Demo 7: Log Migration and Management
        await self.demo_log_migration()
        
        # Demo 8: Integration Demo
        await self.demo_integration()
        
        logger.info("🎉 Hardware Security & Log Versioning Demo completed successfully!")
        
        # Cleanup
        await self.cleanup()
    
    async def demo_hardware_availability(self):
        """Demo hardware security availability check."""
        logger.info("\n🔍 Demo 1: Hardware Security Availability Check")
        logger.info("-" * 50)
        
        try:
            availability = check_hardware_security_availability()
            
            logger.info("Hardware Security Features:")
            for feature, available in availability.items():
                status = "✅ Available" if available else "❌ Not Available"
                logger.info(f"  {feature}: {status}")
            
            if not any(availability.values()):
                logger.warning("⚠️  No hardware security features available - using software fallback")
            else:
                logger.info("✅ Hardware security features detected")
                
        except Exception as e:
            logger.error(f"❌ Hardware availability check failed: {e}")
    
    async def demo_hardware_security_manager(self):
        """Demo hardware security manager initialization."""
        logger.info("\n🛡️  Demo 2: Hardware Security Manager")
        logger.info("-" * 40)
        
        try:
            # Try different providers in order of preference
            providers_to_try = [
                HardwareSecurityType.TPM_2_0,
                HardwareSecurityType.HSM_PKCS11,
                HardwareSecurityType.SOFTWARE_FALLBACK
            ]
            
            for provider_type in providers_to_try:
                logger.info(f"Trying provider: {provider_type.value}")
                
                manager = HardwareSecurityManager(provider_type)
                if await manager.initialize():
                    self.hardware_manager = manager
                    
                    provider_info = manager.get_provider_info()
                    logger.info(f"✅ Initialized: {provider_info['provider']}")
                    
                    # Show provider capabilities
                    logger.info("Provider Information:")
                    for key, value in provider_info.items():
                        logger.info(f"  {key}: {value}")
                    
                    break
                else:
                    logger.info(f"❌ Failed to initialize {provider_type.value}")
            
            if not self.hardware_manager:
                logger.error("❌ Failed to initialize any hardware security provider")
                
        except Exception as e:
            logger.error(f"❌ Hardware security manager demo failed: {e}")
    
    async def demo_device_identity_attestation(self):
        """Demo device identity and attestation."""
        logger.info("\n🆔 Demo 3: Device Identity and Attestation")
        logger.info("-" * 45)
        
        if not self.hardware_manager:
            logger.warning("⚠️  Skipping - no hardware security manager available")
            return
        
        try:
            # Get device identity
            logger.info("Getting hardware-based device identity...")
            identity = await self.hardware_manager.get_device_identity()
            
            if identity:
                logger.info("✅ Device Identity Retrieved:")
                logger.info(f"  Device ID: {identity.device_id}")
                logger.info(f"  Hardware Type: {identity.hardware_type.value}")
                logger.info(f"  Public Key Length: {len(identity.public_key)} bytes")
                
                if identity.platform_info:
                    logger.info("  Platform Info:")
                    for key, value in identity.platform_info.items():
                        logger.info(f"    {key}: {value}")
            
            # Create attestation
            logger.info("\nCreating hardware attestation...")
            attestation = await self.hardware_manager.create_attestation(
                attestation_type=AttestationType.DEVICE_IDENTITY
            )
            
            if attestation:
                logger.info("✅ Attestation Created:")
                logger.info(f"  Type: {attestation.attestation_type.value}")
                logger.info(f"  Device ID: {attestation.device_id}")
                logger.info(f"  Timestamp: {time.ctime(attestation.timestamp)}")
                logger.info(f"  Nonce: {attestation.nonce.hex()[:16]}...")
                logger.info(f"  Measurements: {len(attestation.measurements)} items")
                logger.info(f"  Signature Length: {len(attestation.signature)} bytes")
                
                # Verify attestation
                logger.info("\nVerifying attestation...")
                is_valid = await self.hardware_manager.verify_attestation(attestation)
                status = "✅ Valid" if is_valid else "❌ Invalid"
                logger.info(f"Attestation verification: {status}")
            
        except Exception as e:
            logger.error(f"❌ Device identity and attestation demo failed: {e}")
    
    async def demo_secure_boot_validation(self):
        """Demo secure boot validation."""
        logger.info("\n🔒 Demo 4: Secure Boot Validation")
        logger.info("-" * 35)
        
        try:
            secure_boot_status = SecureBootValidator.check_secure_boot_status()
            
            logger.info("Secure Boot Status:")
            logger.info(f"  Platform: {secure_boot_status['platform']}")
            
            if secure_boot_status['secure_boot_enabled']:
                logger.info("  Status: ✅ Secure Boot Enabled")
            else:
                logger.info("  Status: ❌ Secure Boot Disabled")
            
            if secure_boot_status['details']:
                logger.info("  Details:")
                for key, value in secure_boot_status['details'].items():
                    logger.info(f"    {key}: {value}")
            
        except Exception as e:
            logger.error(f"❌ Secure boot validation demo failed: {e}")
    
    async def demo_log_versioning(self):
        """Demo log versioning system."""
        logger.info("\n📝 Demo 5: Log Versioning System")
        logger.info("-" * 35)
        
        try:
            # Test different log versions
            versions_to_test = [LogVersion.V1_1, LogVersion.V2_0, LogVersion.V2_1]
            
            for version in versions_to_test:
                logger.info(f"\nTesting log version {version.value}:")
                
                # Create versioned log file
                log_path = os.path.join(self.temp_dir, f"test_{version.value.replace('.', '_')}.eaplog")
                
                writer = LogWriter(
                    file_path=log_path,
                    version=version,
                    robot_id="demo_robot_001",
                    session_id="demo_session_123",
                    metadata={
                        "demo_version": version.value,
                        "test_data": "hardware_security_demo"
                    }
                )
                
                await writer.open()
                
                # Write test messages
                test_messages = [
                    b"Test message 1 for version " + version.value.encode(),
                    b"Test message 2 with timestamp " + str(time.time()).encode(),
                    b"Test message 3 with random data " + os.urandom(32).hex().encode()
                ]
                
                for msg in test_messages:
                    await writer.write_message(msg)
                
                await writer.close()
                
                logger.info(f"  ✅ Created log file: {Path(log_path).name}")
                logger.info(f"  Messages written: {len(test_messages)}")
                
                # Read and validate log file
                reader = LogReader(log_path)
                await reader.open()
                
                info = reader.get_info()
                logger.info(f"  Version detected: {info['version']}")
                logger.info(f"  File size: {info['file_size']} bytes")
                
                messages = await reader.read_messages()
                logger.info(f"  Messages read: {len(messages)}")
                
                await reader.close()
                
                # Validate log file
                validation = await LogValidator.validate_file(log_path)
                status = "✅ Valid" if validation['valid'] else "❌ Invalid"
                logger.info(f"  Validation: {status}")
                
                if validation['warnings']:
                    for warning in validation['warnings']:
                        logger.warning(f"    ⚠️  {warning}")
            
        except Exception as e:
            logger.error(f"❌ Log versioning demo failed: {e}")
    
    async def demo_eap_versioned_logging(self):
        """Demo EAP handler with versioned logging."""
        logger.info("\n🤖 Demo 6: EAP Handler with Versioned Logging")
        logger.info("-" * 50)
        
        try:
            # Create mock transport and serializer
            class MockTransport:
                async def connect(self): pass
                async def disconnect(self): pass
                async def publish(self, topic, message): pass
                async def subscribe(self, topic, handler, message_type): pass
            
            transport = MockTransport()
            serializer = ProtobufSerializer()
            
            # Create EAP handler with versioned logging
            eap_handler = EAPHandler(
                transport=transport,
                serializer=serializer,
                log_dir=self.temp_dir,
                robot_id="demo_robot_eap",
                session_id="eap_demo_session",
                log_version=LogVersion.V2_1
            )
            
            # Open versioned log file
            await eap_handler.open_log_file(
                log_name="eap_demo.eaplog",
                metadata={
                    "demo_type": "hardware_security_demo",
                    "eap_version": "2.1",
                    "features": ["versioned_logging", "hardware_security"]
                }
            )
            
            # Create and log some EAP messages
            test_actions = [
                {"action_type": "move", "data": {"x": 10, "y": 20, "z": 0}},
                {"action_type": "rotate", "data": {"yaw": 45, "pitch": 0, "roll": 0}},
                {"action_type": "grasp", "data": {"object_id": "cube_001", "force": 50}}
            ]
            
            for action in test_actions:
                # Create mock EAP message
                eap_message = {
                    "timestamp": time.time(),
                    "action_type": action["action_type"],
                    "action_data": action["data"],
                    "robot_id": "demo_robot_eap"
                }
                
                await eap_handler.log_action(eap_message)
                logger.info(f"  ✅ Logged action: {action['action_type']}")
            
            await eap_handler.close_log_file()
            
            # Verify the log file
            log_path = os.path.join(self.temp_dir, "eap_demo.eaplog")
            reader = LogReader(log_path)
            await reader.open()
            
            info = reader.get_info()
            logger.info(f"EAP Log Information:")
            logger.info(f"  Version: {info['version']}")
            logger.info(f"  Robot ID: {info.get('robot_id', 'N/A')}")
            logger.info(f"  Session ID: {info.get('session_id', 'N/A')}")
            logger.info(f"  File size: {info['file_size']} bytes")
            
            messages = await reader.read_messages()
            logger.info(f"  Actions logged: {len(messages)}")
            
            await reader.close()
            
        except Exception as e:
            logger.error(f"❌ EAP versioned logging demo failed: {e}")
    
    async def demo_log_migration(self):
        """Demo log migration and management."""
        logger.info("\n🔄 Demo 7: Log Migration and Management")
        logger.info("-" * 40)
        
        try:
            # Create a legacy log file (simulate old format)
            legacy_log_path = os.path.join(self.temp_dir, "legacy.eaplog")
            
            # Create legacy log writer (V1.0 - no header)
            legacy_writer = LogWriter(
                file_path=legacy_log_path,
                version=LogVersion.V1_0  # Legacy format
            )
            
            await legacy_writer.open()
            
            # Write some legacy messages
            legacy_messages = [
                b"Legacy message 1",
                b"Legacy message 2", 
                b"Legacy message 3"
            ]
            
            for msg in legacy_messages:
                await legacy_writer.write_message(msg)
            
            await legacy_writer.close()
            logger.info(f"✅ Created legacy log file: {Path(legacy_log_path).name}")
            
            # Migrate to modern format
            modern_log_path = os.path.join(self.temp_dir, "migrated.eaplog")
            
            success = await LogMigrator.migrate_file(
                source_path=legacy_log_path,
                target_path=modern_log_path,
                target_version=LogVersion.V2_1,
                robot_id="migrated_robot",
                session_id="migration_session",
                metadata={
                    "migration_demo": True,
                    "original_format": "legacy"
                }
            )
            
            if success:
                logger.info(f"✅ Successfully migrated to: {Path(modern_log_path).name}")
                
                # Verify migrated file
                reader = LogReader(modern_log_path)
                await reader.open()
                
                info = reader.get_info()
                logger.info("Migration Results:")
                logger.info(f"  Target version: {info['version']}")
                logger.info(f"  Robot ID: {info.get('robot_id', 'N/A')}")
                
                messages = await reader.read_messages()
                logger.info(f"  Messages preserved: {len(messages)}")
                
                if info.get('metadata'):
                    logger.info(f"  Migration metadata: {info['metadata']}")
                
                await reader.close()
            else:
                logger.error("❌ Migration failed")
            
        except Exception as e:
            logger.error(f"❌ Log migration demo failed: {e}")
    
    async def demo_integration(self):
        """Demo integration of hardware security with logging."""
        logger.info("\n🔗 Demo 8: Hardware Security + Logging Integration")
        logger.info("-" * 55)
        
        try:
            if not self.hardware_manager:
                logger.warning("⚠️  Skipping integration demo - no hardware security manager")
                return
            
            # Get device identity
            identity = await self.hardware_manager.get_device_identity()
            
            if identity:
                # Create secure log with hardware identity
                secure_log_path = os.path.join(self.temp_dir, "secure_robot.eaplog")
                
                # Include hardware identity in log metadata
                secure_metadata = {
                    "hardware_secured": True,
                    "device_id": identity.device_id,
                    "hardware_type": identity.hardware_type.value,
                    "platform_info": identity.platform_info,
                    "security_level": "hardware_backed"
                }
                
                writer = LogWriter(
                    file_path=secure_log_path,
                    version=LogVersion.V2_1,
                    robot_id=identity.device_id,
                    session_id="secure_session",
                    metadata=secure_metadata
                )
                
                await writer.open()
                
                # Create attestation and log it
                attestation = await self.hardware_manager.create_attestation()
                if attestation:
                    attestation_data = str(attestation.to_dict()).encode()
                    await writer.write_message(attestation_data)
                    logger.info("✅ Logged hardware attestation")
                
                # Log some secure actions
                secure_actions = [
                    b"Secure action: Initialize hardware security",
                    b"Secure action: Verify device identity", 
                    b"Secure action: Create attestation report"
                ]
                
                for action in secure_actions:
                    await writer.write_message(action)
                
                await writer.close()
                
                logger.info(f"✅ Created secure log: {Path(secure_log_path).name}")
                
                # Verify the secure log
                reader = LogReader(secure_log_path)
                await reader.open()
                
                info = reader.get_info()
                logger.info("Secure Log Information:")
                logger.info(f"  Hardware secured: {info['metadata'].get('hardware_secured', False)}")
                logger.info(f"  Device ID: {info['metadata'].get('device_id', 'N/A')}")
                logger.info(f"  Hardware type: {info['metadata'].get('hardware_type', 'N/A')}")
                logger.info(f"  Security level: {info['metadata'].get('security_level', 'N/A')}")
                
                messages = await reader.read_messages()
                logger.info(f"  Secure messages: {len(messages)}")
                
                await reader.close()
            
        except Exception as e:
            logger.error(f"❌ Integration demo failed: {e}")
    
    async def cleanup(self):
        """Clean up demo resources."""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info(f"🧹 Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"⚠️  Cleanup warning: {e}")


async def main():
    """Run the hardware security and logging demonstration."""
    demo = HardwareSecurityDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())