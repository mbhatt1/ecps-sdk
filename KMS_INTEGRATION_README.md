# KMS Integration for ECPS-UV SDK

This document describes the comprehensive Key Management Service (KMS) integration for the ECPS-UV SDK, enabling enterprise-grade key management for distributed robotic systems.

## Overview

The KMS integration provides secure, scalable key management using cloud-based services including AWS KMS, Azure Key Vault, Google Cloud KMS, and HashiCorp Vault. This enables production-ready security for robot fleets with centralized key policies, automated rotation, and compliance with enterprise security standards.

## Features

### 🔐 **Multi-Provider Support**
- **AWS KMS**: Deep integration with AWS services and global availability
- **Azure Key Vault**: Microsoft ecosystem integration with HSM support
- **Google Cloud KMS**: Global key management with IAM integration
- **HashiCorp Vault**: Multi-cloud and on-premises deployment flexibility
- **Local Fallback**: Graceful degradation to local storage when KMS unavailable

### 🛡️ **Enterprise Security**
- Hardware Security Module (HSM) backing
- Centralized key policies and access control
- Automated key rotation and lifecycle management
- Audit logging and compliance reporting
- Multi-region deployment and disaster recovery

### 🤖 **Robot-Specific Features**
- Factory provisioning with KMS-backed keys
- Field deployment with secure key distribution
- Emergency key revocation and fleet lockdown
- Offline operation with cached keys
- Agent-to-agent secure communication

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Robot Fleet   │    │  ECPS-UV SDK    │    │   KMS Provider  │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Robot A   │◄┼────┼►│ KeyManager  │◄┼────┼►│  AWS KMS    │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Robot B   │◄┼────┼►│KMSIntegration│◄┼────┼►│Azure KeyVault│ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │   Robot C   │◄┼────┼►│SecureKeyStore│◄┼────┼►│  GCP KMS    │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Installation

### Dependencies

Install the required dependencies for your chosen KMS provider:

```bash
# AWS KMS
pip install boto3

# Azure Key Vault
pip install azure-keyvault-keys azure-keyvault-secrets azure-identity

# Google Cloud KMS
pip install google-cloud-kms

# HashiCorp Vault
pip install hvac

# Install all providers
pip install boto3 azure-keyvault-keys azure-keyvault-secrets azure-identity google-cloud-kms hvac
```

### ECPS-UV SDK

The KMS integration is included in the ECPS-UV SDK:

```bash
pip install -e .
```

## Configuration

### AWS KMS Configuration

```python
aws_kms_config = {
    "provider": "aws_kms",
    "region": "us-west-2",
    "use_kms_for_storage": True
}

# AWS credentials via environment variables or IAM roles
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN
```

### Azure Key Vault Configuration

```python
azure_config = {
    "provider": "azure_key_vault",
    "key_vault_url": "https://your-vault.vault.azure.net/",
    "use_kms_for_storage": True
}

# Azure authentication via DefaultAzureCredential
# AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID
```

### Google Cloud KMS Configuration

```python
gcp_config = {
    "provider": "google_cloud_kms",
    "project_id": "your-project-id",
    "location_id": "global",
    "key_ring_id": "your-key-ring",
    "credentials_path": "/path/to/service-account.json",
    "use_kms_for_storage": True
}
```

### HashiCorp Vault Configuration

```python
vault_config = {
    "provider": "hashicorp_vault",
    "vault_url": "https://vault.example.com",
    "vault_token": "hvs.your_token",
    "vault_namespace": "your-namespace",  # Optional
    "use_kms_for_storage": True
}
```

## Usage Examples

### Basic KMS Integration

```python
from ecps_uv.trust.kms_integration import create_kms_manager
from ecps_uv.trust.key_management import FactoryProvisioning

# Create KMS manager
kms_manager = create_kms_manager(
    provider="aws_kms",
    region="us-west-2"
)

# Provision robot with KMS-backed keys
robot_key_manager = await FactoryProvisioning.provision_robot_with_kms(
    device_id="robot_001",
    storage_path="/secure/keys",
    ca_cert_path="/certs/ca.pem",
    kms_config={
        "provider": "aws_kms",
        "region": "us-west-2",
        "use_kms_for_storage": True
    }
)
```

### Key Operations

```python
# Generate KMS-backed keys
device_key_id = await key_manager.generate_kms_key(KeyType.DEVICE_IDENTITY)
comm_key_id = await key_manager.generate_kms_key(KeyType.COMMUNICATION, expires_in=86400)

# Encrypt/decrypt with KMS
plaintext = b"Sensitive robot data"
encrypted = await key_manager.encrypt_with_kms(comm_key_id, plaintext)
decrypted = await key_manager.decrypt_with_kms(comm_key_id, encrypted)

# Rotate KMS keys
new_key_id = await key_manager.rotate_kms_key(comm_key_id)

# Backup local keys to KMS
backup_success = await key_manager.backup_keys_to_kms()
```

### Hybrid Deployment

```python
# Local storage with KMS backup
hybrid_config = {
    "provider": "aws_kms",
    "region": "us-west-2",
    "use_kms_for_storage": False  # Keep metadata local, backup to KMS
}

key_manager = KeyManager(
    device_id="robot_001",
    key_store=SecureKeyStore("/local/keys"),
    kms_manager=create_kms_manager(**hybrid_config)
)

# Generate local keys
local_key_id = key_manager.generate_communication_key()

# Backup to KMS for disaster recovery
await key_manager.backup_keys_to_kms()
```

## Security Considerations

### Key Types and Usage

| Key Type | Algorithm | Usage | Rotation | KMS Support |
|----------|-----------|-------|----------|-------------|
| Device Identity | RSA 2048 | Authentication, Signing | Manual | ✅ |
| Communication | AES 256 | Encryption, Decryption | 24 hours | ✅ |
| Storage | AES 256 | Data Encryption | Manual | ✅ |
| Emergency | RSA 2048 | Emergency Override | 1 year | ✅ |

### Access Control

```python
# KMS policies control access to keys
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::account:role/RobotRole"},
            "Action": [
                "kms:Encrypt",
                "kms:Decrypt",
                "kms:GenerateDataKey"
            ],
            "Resource": "*",
            "Condition": {
                "StringEquals": {
                    "kms:ViaService": "secretsmanager.region.amazonaws.com"
                }
            }
        }
    ]
}
```

### Network Security

- All KMS communications use TLS 1.2+
- Certificate pinning for KMS endpoints
- Network isolation and VPC endpoints
- Rate limiting and DDoS protection

## Deployment Patterns

### 1. Cloud-Native Deployment

```yaml
# Kubernetes deployment with KMS integration
apiVersion: apps/v1
kind: Deployment
metadata:
  name: robot-fleet
spec:
  template:
    spec:
      serviceAccountName: robot-kms-service-account
      containers:
      - name: robot-agent
        image: ecps-uv-robot:latest
        env:
        - name: KMS_PROVIDER
          value: "aws_kms"
        - name: AWS_REGION
          value: "us-west-2"
        - name: USE_KMS_FOR_STORAGE
          value: "true"
```

### 2. Hybrid Cloud Deployment

```python
# Multi-region deployment with failover
primary_kms = create_kms_manager(
    provider="aws_kms",
    region="us-west-2"
)

backup_kms = create_kms_manager(
    provider="azure_key_vault",
    key_vault_url="https://backup-vault.vault.azure.net/"
)

# Implement failover logic
try:
    key_id = await primary_kms.create_key("robot_key", "symmetric", "AES_256")
except Exception:
    key_id = await backup_kms.create_key("robot_key", "symmetric", "AES_256")
```

### 3. Edge Deployment with Offline Support

```python
# Edge deployment with local caching
edge_config = {
    "provider": "aws_kms",
    "region": "us-west-2",
    "use_kms_for_storage": False,  # Cache locally
    "offline_mode": True
}

# Generate emergency keys for offline operation
emergency_key_id = key_manager.generate_emergency_key()
```

## Monitoring and Compliance

### Audit Logging

```python
# KMS operations are automatically logged
logger.info(f"KMS key created: {key_id}")
logger.info(f"Key rotation completed: {old_key_id} -> {new_key_id}")
logger.warning(f"Key revoked: {key_id} (reason: {reason})")
```

### Compliance Features

- **SOC 2 Type II**: Automated compliance reporting
- **FIPS 140-2**: Hardware security module backing
- **Common Criteria**: Certified cryptographic modules
- **ISO 27001**: Security management system integration

### Metrics and Alerting

```python
# Key performance indicators
metrics = {
    "key_operations_per_second": 1000,
    "key_rotation_success_rate": 99.9,
    "kms_availability": 99.99,
    "encryption_latency_ms": 5
}

# Alerting thresholds
alerts = {
    "key_rotation_failure": "CRITICAL",
    "kms_connectivity_loss": "HIGH",
    "unauthorized_key_access": "CRITICAL"
}
```

## Troubleshooting

### Common Issues

1. **KMS Authentication Failures**
   ```bash
   # Check AWS credentials
   aws sts get-caller-identity
   
   # Check Azure authentication
   az account show
   
   # Check GCP authentication
   gcloud auth list
   ```

2. **Network Connectivity Issues**
   ```python
   # Test KMS connectivity
   try:
       kms_manager = create_kms_manager(**config)
       keys = await kms_manager.list_keys()
       print(f"Connected successfully, found {len(keys)} keys")
   except Exception as e:
       print(f"Connection failed: {e}")
   ```

3. **Key Rotation Failures**
   ```python
   # Check key status before rotation
   if key_manager.verify_key_integrity(key_id):
       new_key_id = await key_manager.rotate_kms_key(key_id)
   else:
       logger.error(f"Key integrity check failed: {key_id}")
   ```

### Debug Mode

```python
import logging
logging.getLogger("ecps_uv.trust.kms_integration").setLevel(logging.DEBUG)
logging.getLogger("ecps_uv.trust.key_management").setLevel(logging.DEBUG)
```

## Performance Optimization

### Caching Strategies

```python
# Local key caching for performance
cache_config = {
    "enable_local_cache": True,
    "cache_ttl_seconds": 3600,
    "max_cache_size": 1000
}
```

### Batch Operations

```python
# Batch key operations for efficiency
keys_to_rotate = [key1, key2, key3]
rotation_tasks = [key_manager.rotate_kms_key(k) for k in keys_to_rotate]
results = await asyncio.gather(*rotation_tasks)
```

## Migration Guide

### From Local to KMS

1. **Assessment Phase**
   - Inventory existing keys
   - Identify compliance requirements
   - Plan migration timeline

2. **Preparation Phase**
   ```python
   # Backup existing keys
   await key_manager.backup_keys_to_kms()
   
   # Validate KMS connectivity
   kms_manager = create_kms_manager(**config)
   ```

3. **Migration Phase**
   ```python
   # Gradual migration
   for key_metadata in local_keys:
       if key_metadata.key_type == KeyType.COMMUNICATION:
           # Migrate communication keys first
           await migrate_key_to_kms(key_metadata.key_id)
   ```

4. **Validation Phase**
   ```python
   # Verify migration success
   for key_id in migrated_keys:
       assert key_manager.is_kms_backed(key_id)
       assert key_manager.verify_key_integrity(key_id)
   ```

## Examples and Demos

### Running the Demos

```bash
# Basic KMS integration demo
python examples/kms_integration_demo.py

# Robot fleet with KMS
python examples/robot_key_management_demo.py

# Comprehensive security demo
python examples/secure_ecps.py
```

### Demo Scenarios

1. **Factory Provisioning**: Secure robot setup with KMS-backed keys
2. **Field Deployment**: Secure communication establishment
3. **Key Rotation**: Automated and manual key rotation procedures
4. **Emergency Response**: Fleet-wide security incident handling
5. **Disaster Recovery**: Key backup and restoration procedures

## Best Practices

### Security Best Practices

1. **Principle of Least Privilege**: Grant minimal required KMS permissions
2. **Key Rotation**: Implement automated rotation for short-lived keys
3. **Monitoring**: Enable comprehensive audit logging and alerting
4. **Backup**: Maintain secure key backups across multiple regions
5. **Testing**: Regular disaster recovery and security testing

### Operational Best Practices

1. **Gradual Rollout**: Phase KMS integration across robot fleet
2. **Fallback Planning**: Maintain local key capabilities for emergencies
3. **Performance Testing**: Validate KMS performance under load
4. **Documentation**: Maintain current operational procedures
5. **Training**: Ensure team familiarity with KMS operations

## Support and Resources

### Documentation
- [AWS KMS Developer Guide](https://docs.aws.amazon.com/kms/)
- [Azure Key Vault Documentation](https://docs.microsoft.com/en-us/azure/key-vault/)
- [Google Cloud KMS Documentation](https://cloud.google.com/kms/docs)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)

### Community
- ECPS-UV GitHub Repository
- Security Working Group
- Robot Fleet Operators Forum

### Professional Support
- Enterprise support contracts available
- Security consulting services
- Custom integration development

---

**Note**: This KMS integration provides enterprise-grade security for production robot deployments. Always follow your organization's security policies and compliance requirements when implementing key management systems.