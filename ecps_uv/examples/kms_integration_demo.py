#!/usr/bin/env python3
"""
KMS Integration Demo for ECPS-UV SDK.

This demo showcases enterprise-grade key management using cloud KMS providers
including AWS KMS, Azure Key Vault, Google Cloud KMS, and HashiCorp Vault.
"""

import asyncio
import logging
import os
import tempfile
import time
from typing import Dict, Any, List

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("kms_integration_demo")

# Import ECPS-UV components
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ecps_uv.trust.key_management import (
    KeyManager, SecureKeyStore, FactoryProvisioning, 
    KeyType, KeyStatus
)

try:
    from ecps_uv.trust.kms_integration import (
        create_kms_manager, get_available_providers, 
        validate_kms_config, KMSConfig, KMSProvider
    )
    KMS_AVAILABLE = True
except ImportError as e:
    logger.warning(f"KMS integration not available: {e}")
    KMS_AVAILABLE = False


class KMSIntegrationDemo:
    """Comprehensive demo of KMS integration capabilities."""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp(prefix="ecps_kms_demo_")
        self.demo_robots: List[KeyManager] = []
        
    async def run_demo(self):
        """Run the complete KMS integration demonstration."""
        logger.info("🔐 Starting ECPS-UV KMS Integration Demo")
        logger.info("=" * 60)
        
        # Check available providers
        await self.show_available_providers()
        
        # Demo 1: Local key management (baseline)
        await self.demo_local_key_management()
        
        # Demo 2: Mock KMS integration (when cloud providers not available)
        await self.demo_mock_kms_integration()
        
        # Demo 3: AWS KMS integration (if available)
        await self.demo_aws_kms_integration()
        
        # Demo 4: Azure Key Vault integration (if available)
        await self.demo_azure_key_vault_integration()
        
        # Demo 5: Google Cloud KMS integration (if available)
        await self.demo_google_cloud_kms_integration()
        
        # Demo 6: HashiCorp Vault integration (if available)
        await self.demo_hashicorp_vault_integration()
        
        # Demo 7: Hybrid deployment (local + KMS backup)
        await self.demo_hybrid_deployment()
        
        # Demo 8: Key migration scenarios
        await self.demo_key_migration()
        
        # Demo 9: Disaster recovery
        await self.demo_disaster_recovery()
        
        # Demo 10: Multi-provider comparison
        await self.demo_multi_provider_comparison()
        
        logger.info("🎉 KMS Integration Demo completed successfully!")
        
        # Cleanup
        await self.cleanup()
    
    async def show_available_providers(self):
        """Show available KMS providers."""
        logger.info("\n📋 Available KMS Providers:")
        logger.info("-" * 30)
        
        if not KMS_AVAILABLE:
            logger.warning("❌ KMS integration module not available")
            logger.info("   Install dependencies: pip install boto3 azure-keyvault hvac google-cloud-kms")
            return
        
        providers = get_available_providers()
        for provider in providers:
            status = "✅" if provider != "local" else "🏠"
            logger.info(f"   {status} {provider}")
        
        if len(providers) == 1:  # Only local available
            logger.warning("   💡 Install cloud provider SDKs for full KMS integration")
    
    async def demo_local_key_management(self):
        """Demo baseline local key management."""
        logger.info("\n🏠 Demo 1: Local Key Management (Baseline)")
        logger.info("-" * 45)
        
        try:
            # Create robot with local key storage
            robot = FactoryProvisioning.provision_robot(
                device_id="robot_local_001",
                storage_path=os.path.join(self.temp_dir, "local_keys"),
                ca_cert_path="/dev/null",  # Mock CA cert
                master_password="local_secure_password"
            )
            
            self.demo_robots.append(robot)
            
            # Show key operations
            logger.info(f"✅ Provisioned robot: {robot.device_id}")
            
            # List active keys
            active_keys = robot.get_active_keys()
            logger.info(f"📊 Active keys: {len(active_keys)}")
            for key_meta in active_keys:
                logger.info(f"   - {key_meta.key_type.value}: {key_meta.key_id[:20]}...")
            
            # Test key rotation
            comm_key_id = robot.get_key_for_operation("encrypt", KeyType.COMMUNICATION)
            if comm_key_id:
                new_key_id = await robot.rotate_key(comm_key_id)
                logger.info(f"🔄 Rotated communication key: {comm_key_id[:20]}... → {new_key_id[:20]}...")
            
            logger.info("✅ Local key management demo completed")
            
        except Exception as e:
            logger.error(f"❌ Local key management demo failed: {e}")
    
    async def demo_mock_kms_integration(self):
        """Demo KMS integration with mock configuration."""
        logger.info("\n🎭 Demo 2: Mock KMS Integration")
        logger.info("-" * 35)
        
        if not KMS_AVAILABLE:
            logger.warning("❌ Skipping - KMS integration not available")
            return
        
        try:
            # Mock KMS configuration (will use local fallback)
            mock_kms_config = {
                "provider": "local",  # Fallback to local
                "use_kms_for_storage": False
            }
            
            # Validate configuration
            config = KMSConfig(provider=KMSProvider.LOCAL)
            issues = validate_kms_config(config)
            if issues:
                logger.warning(f"⚠️  Configuration issues: {issues}")
            
            # Create robot with mock KMS
            robot = FactoryProvisioning.provision_robot(
                device_id="robot_mock_kms_001",
                storage_path=os.path.join(self.temp_dir, "mock_kms_keys"),
                ca_cert_path="/dev/null",
                master_password="mock_kms_password",
                kms_config=mock_kms_config
            )
            
            self.demo_robots.append(robot)
            
            logger.info(f"✅ Provisioned robot with mock KMS: {robot.device_id}")
            
            # Show KMS info
            kms_info = robot.get_kms_info()
            if kms_info:
                logger.info(f"🔧 KMS Provider: {kms_info.get('provider', 'unknown')}")
            
            logger.info("✅ Mock KMS integration demo completed")
            
        except Exception as e:
            logger.error(f"❌ Mock KMS integration demo failed: {e}")
    
    async def demo_aws_kms_integration(self):
        """Demo AWS KMS integration."""
        logger.info("\n☁️  Demo 3: AWS KMS Integration")
        logger.info("-" * 35)
        
        if not KMS_AVAILABLE:
            logger.warning("❌ Skipping - KMS integration not available")
            return
        
        try:
            # Check if AWS credentials are available
            aws_config = {
                "provider": "aws_kms",
                "region": "us-west-2",
                "use_kms_for_storage": True
            }
            
            # Validate configuration
            config = KMSConfig(provider=KMSProvider.AWS_KMS, region="us-west-2")
            issues = validate_kms_config(config)
            
            if issues:
                logger.warning(f"⚠️  AWS KMS not properly configured: {issues}")
                logger.info("   💡 Set up AWS credentials and try again")
                return
            
            # Create KMS manager (this will fail without real AWS credentials)
            try:
                kms_manager = create_kms_manager(**aws_config)
                logger.info("✅ AWS KMS manager created successfully")
                
                # Create robot with AWS KMS
                robot = await FactoryProvisioning.provision_robot_with_kms(
                    device_id="robot_aws_kms_001",
                    storage_path=os.path.join(self.temp_dir, "aws_kms_keys"),
                    ca_cert_path="/dev/null",
                    kms_config=aws_config,
                    master_password="aws_kms_password"
                )
                
                self.demo_robots.append(robot)
                
                # Test KMS operations
                test_data = b"Hello from AWS KMS!"
                
                # Get a communication key for testing
                comm_key_id = robot.get_key_for_operation("encrypt", KeyType.COMMUNICATION)
                if comm_key_id and robot.is_kms_backed(comm_key_id):
                    # Test encryption/decryption
                    encrypted = await robot.encrypt_with_kms(comm_key_id, test_data)
                    if encrypted:
                        decrypted = await robot.decrypt_with_kms(comm_key_id, encrypted)
                        if decrypted == test_data:
                            logger.info("✅ AWS KMS encryption/decryption test passed")
                        else:
                            logger.error("❌ AWS KMS encryption/decryption test failed")
                
                logger.info("✅ AWS KMS integration demo completed")
                
            except Exception as e:
                logger.warning(f"⚠️  AWS KMS demo requires valid credentials: {e}")
                logger.info("   💡 Configure AWS credentials to test full integration")
                
        except Exception as e:
            logger.error(f"❌ AWS KMS integration demo failed: {e}")
    
    async def demo_azure_key_vault_integration(self):
        """Demo Azure Key Vault integration."""
        logger.info("\n🔷 Demo 4: Azure Key Vault Integration")
        logger.info("-" * 40)
        
        if not KMS_AVAILABLE:
            logger.warning("❌ Skipping - KMS integration not available")
            return
        
        try:
            azure_config = {
                "provider": "azure_key_vault",
                "key_vault_url": "https://ecps-demo-vault.vault.azure.net/",
                "use_kms_for_storage": True
            }
            
            # Validate configuration
            config = KMSConfig(
                provider=KMSProvider.AZURE_KEY_VAULT,
                key_vault_url=azure_config["key_vault_url"]
            )
            issues = validate_kms_config(config)
            
            if issues:
                logger.warning(f"⚠️  Azure Key Vault not properly configured: {issues}")
                logger.info("   💡 Set up Azure credentials and Key Vault URL")
                return
            
            try:
                kms_manager = create_kms_manager(**azure_config)
                logger.info("✅ Azure Key Vault manager created successfully")
                
                # Demo would continue with actual Azure operations...
                logger.info("✅ Azure Key Vault integration demo completed")
                
            except Exception as e:
                logger.warning(f"⚠️  Azure Key Vault demo requires valid credentials: {e}")
                logger.info("   💡 Configure Azure credentials to test full integration")
                
        except Exception as e:
            logger.error(f"❌ Azure Key Vault integration demo failed: {e}")
    
    async def demo_google_cloud_kms_integration(self):
        """Demo Google Cloud KMS integration."""
        logger.info("\n🌐 Demo 5: Google Cloud KMS Integration")
        logger.info("-" * 40)
        
        if not KMS_AVAILABLE:
            logger.warning("❌ Skipping - KMS integration not available")
            return
        
        try:
            gcp_config = {
                "provider": "google_cloud_kms",
                "project_id": "ecps-demo-project",
                "location_id": "global",
                "key_ring_id": "ecps-key-ring",
                "use_kms_for_storage": True
            }
            
            # Validate configuration
            config = KMSConfig(
                provider=KMSProvider.GOOGLE_CLOUD_KMS,
                project_id=gcp_config["project_id"],
                location_id=gcp_config["location_id"],
                key_ring_id=gcp_config["key_ring_id"]
            )
            issues = validate_kms_config(config)
            
            if issues:
                logger.warning(f"⚠️  Google Cloud KMS not properly configured: {issues}")
                logger.info("   💡 Set up GCP credentials and project configuration")
                return
            
            try:
                kms_manager = create_kms_manager(**gcp_config)
                logger.info("✅ Google Cloud KMS manager created successfully")
                
                # Demo would continue with actual GCP operations...
                logger.info("✅ Google Cloud KMS integration demo completed")
                
            except Exception as e:
                logger.warning(f"⚠️  Google Cloud KMS demo requires valid credentials: {e}")
                logger.info("   💡 Configure GCP credentials to test full integration")
                
        except Exception as e:
            logger.error(f"❌ Google Cloud KMS integration demo failed: {e}")
    
    async def demo_hashicorp_vault_integration(self):
        """Demo HashiCorp Vault integration."""
        logger.info("\n🏛️  Demo 6: HashiCorp Vault Integration")
        logger.info("-" * 40)
        
        if not KMS_AVAILABLE:
            logger.warning("❌ Skipping - KMS integration not available")
            return
        
        try:
            vault_config = {
                "provider": "hashicorp_vault",
                "vault_url": "https://vault.example.com",
                "vault_token": "hvs.demo_token",
                "use_kms_for_storage": True
            }
            
            # Validate configuration
            config = KMSConfig(
                provider=KMSProvider.HASHICORP_VAULT,
                vault_url=vault_config["vault_url"],
                vault_token=vault_config["vault_token"]
            )
            issues = validate_kms_config(config)
            
            if issues:
                logger.warning(f"⚠️  HashiCorp Vault not properly configured: {issues}")
                logger.info("   💡 Set up Vault URL and authentication token")
                return
            
            try:
                kms_manager = create_kms_manager(**vault_config)
                logger.info("✅ HashiCorp Vault manager created successfully")
                
                # Demo would continue with actual Vault operations...
                logger.info("✅ HashiCorp Vault integration demo completed")
                
            except Exception as e:
                logger.warning(f"⚠️  HashiCorp Vault demo requires valid connection: {e}")
                logger.info("   💡 Configure Vault connection to test full integration")
                
        except Exception as e:
            logger.error(f"❌ HashiCorp Vault integration demo failed: {e}")
    
    async def demo_hybrid_deployment(self):
        """Demo hybrid deployment with local keys and KMS backup."""
        logger.info("\n🔄 Demo 7: Hybrid Deployment (Local + KMS Backup)")
        logger.info("-" * 50)
        
        if not self.demo_robots:
            logger.warning("❌ No robots available for hybrid demo")
            return
        
        try:
            # Use the first robot for hybrid demo
            robot = self.demo_robots[0]
            
            # Simulate KMS backup (would work with real KMS)
            if robot.kms_manager:
                backup_success = await robot.backup_keys_to_kms()
                if backup_success:
                    logger.info("✅ Keys backed up to KMS successfully")
                else:
                    logger.info("ℹ️  KMS backup simulation completed")
            else:
                logger.info("ℹ️  No KMS configured - simulating backup process")
            
            # Show hybrid benefits
            logger.info("🔧 Hybrid Deployment Benefits:")
            logger.info("   - Fast local key operations")
            logger.info("   - Cloud backup for disaster recovery")
            logger.info("   - Gradual migration to full KMS")
            logger.info("   - Compliance with enterprise policies")
            
            logger.info("✅ Hybrid deployment demo completed")
            
        except Exception as e:
            logger.error(f"❌ Hybrid deployment demo failed: {e}")
    
    async def demo_key_migration(self):
        """Demo key migration scenarios."""
        logger.info("\n🚚 Demo 8: Key Migration Scenarios")
        logger.info("-" * 35)
        
        try:
            # Simulate migration from local to KMS
            logger.info("📋 Migration Scenarios:")
            logger.info("   1. Local → AWS KMS")
            logger.info("   2. Local → Azure Key Vault")
            logger.info("   3. AWS KMS → Google Cloud KMS")
            logger.info("   4. On-premises → Multi-cloud")
            
            # Show migration steps
            logger.info("\n🔧 Migration Process:")
            logger.info("   1. Backup existing keys")
            logger.info("   2. Create KMS keys")
            logger.info("   3. Re-encrypt data with new keys")
            logger.info("   4. Update key references")
            logger.info("   5. Verify operations")
            logger.info("   6. Decommission old keys")
            
            # Simulate migration for demo robot
            if self.demo_robots:
                robot = self.demo_robots[0]
                logger.info(f"\n📊 Current robot {robot.device_id} key status:")
                
                active_keys = robot.get_active_keys()
                for key_meta in active_keys:
                    is_kms = robot.is_kms_backed(key_meta.key_id)
                    storage_type = "KMS" if is_kms else "Local"
                    logger.info(f"   - {key_meta.key_type.value}: {storage_type}")
            
            logger.info("✅ Key migration demo completed")
            
        except Exception as e:
            logger.error(f"❌ Key migration demo failed: {e}")
    
    async def demo_disaster_recovery(self):
        """Demo disaster recovery scenarios."""
        logger.info("\n🚨 Demo 9: Disaster Recovery")
        logger.info("-" * 30)
        
        try:
            logger.info("🔧 Disaster Recovery Scenarios:")
            logger.info("   1. Local storage corruption")
            logger.info("   2. KMS service outage")
            logger.info("   3. Network connectivity loss")
            logger.info("   4. Robot hardware failure")
            
            logger.info("\n🛡️  Recovery Strategies:")
            logger.info("   - Emergency keys for offline operation")
            logger.info("   - Multi-region KMS deployment")
            logger.info("   - Local key caching")
            logger.info("   - Automated failover procedures")
            
            # Test emergency key access
            if self.demo_robots:
                robot = self.demo_robots[0]
                emergency_key_id = robot.get_key_for_operation("sign", KeyType.EMERGENCY)
                if emergency_key_id:
                    logger.info(f"✅ Emergency key available: {emergency_key_id[:20]}...")
                    
                    # Verify emergency key integrity
                    if robot.verify_key_integrity(emergency_key_id):
                        logger.info("✅ Emergency key integrity verified")
                    else:
                        logger.warning("⚠️  Emergency key integrity check failed")
            
            logger.info("✅ Disaster recovery demo completed")
            
        except Exception as e:
            logger.error(f"❌ Disaster recovery demo failed: {e}")
    
    async def demo_multi_provider_comparison(self):
        """Demo comparison of different KMS providers."""
        logger.info("\n📊 Demo 10: Multi-Provider Comparison")
        logger.info("-" * 40)
        
        try:
            logger.info("🔧 KMS Provider Comparison:")
            logger.info("")
            
            providers = [
                {
                    "name": "AWS KMS",
                    "strengths": ["Global availability", "Deep AWS integration", "Mature service"],
                    "use_cases": ["AWS-native applications", "Enterprise scale"]
                },
                {
                    "name": "Azure Key Vault",
                    "strengths": ["Azure integration", "HSM support", "Certificate management"],
                    "use_cases": ["Microsoft environments", "Hybrid cloud"]
                },
                {
                    "name": "Google Cloud KMS",
                    "strengths": ["Global key management", "IAM integration", "Envelope encryption"],
                    "use_cases": ["GCP applications", "Multi-region deployment"]
                },
                {
                    "name": "HashiCorp Vault",
                    "strengths": ["Multi-cloud", "Dynamic secrets", "Policy-based access"],
                    "use_cases": ["Multi-cloud", "On-premises", "DevOps workflows"]
                }
            ]
            
            for provider in providers:
                logger.info(f"🔹 {provider['name']}:")
                logger.info(f"   Strengths: {', '.join(provider['strengths'])}")
                logger.info(f"   Use cases: {', '.join(provider['use_cases'])}")
                logger.info("")
            
            logger.info("💡 Selection Criteria:")
            logger.info("   - Cloud provider alignment")
            logger.info("   - Compliance requirements")
            logger.info("   - Performance needs")
            logger.info("   - Cost considerations")
            logger.info("   - Multi-cloud strategy")
            
            logger.info("✅ Multi-provider comparison completed")
            
        except Exception as e:
            logger.error(f"❌ Multi-provider comparison failed: {e}")
    
    async def cleanup(self):
        """Clean up demo resources."""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            logger.info(f"🧹 Cleaned up temporary directory: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"⚠️  Cleanup warning: {e}")


async def main():
    """Run the KMS integration demonstration."""
    demo = KMSIntegrationDemo()
    await demo.run_demo()


if __name__ == "__main__":
    asyncio.run(main())