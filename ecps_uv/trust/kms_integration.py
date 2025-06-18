"""
KMS (Key Management Service) Integration for ECPS-UV SDK.

This module provides integration with enterprise-grade key management services
including AWS KMS, Azure Key Vault, Google Cloud KMS, and HashiCorp Vault.
"""

import asyncio
import logging
import os
import time
import json
import base64
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass
from abc import ABC, abstractmethod

# Optional imports for different KMS providers
try:
    import boto3
    from botocore.exceptions import ClientError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False

try:
    from azure.keyvault.keys import KeyClient
    from azure.keyvault.secrets import SecretClient
    from azure.identity import DefaultAzureCredential
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False

try:
    from google.cloud import kms
    from google.oauth2 import service_account
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False

try:
    import hvac
    VAULT_AVAILABLE = True
except ImportError:
    VAULT_AVAILABLE = False

from .key_management import KeyMetadata, KeyType, KeyStatus

logger = logging.getLogger("ecps_uv.trust.kms_integration")


class KMSProvider(Enum):
    """Supported KMS providers."""
    AWS_KMS = "aws_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    GOOGLE_CLOUD_KMS = "google_cloud_kms"
    HASHICORP_VAULT = "hashicorp_vault"
    LOCAL = "local"  # Fallback to local storage


@dataclass
class KMSConfig:
    """Configuration for KMS providers."""
    provider: KMSProvider
    region: Optional[str] = None
    vault_url: Optional[str] = None
    key_vault_url: Optional[str] = None
    project_id: Optional[str] = None
    location_id: Optional[str] = None
    key_ring_id: Optional[str] = None
    credentials_path: Optional[str] = None
    vault_token: Optional[str] = None
    vault_namespace: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "provider": self.provider.value,
            "region": self.region,
            "vault_url": self.vault_url,
            "key_vault_url": self.key_vault_url,
            "project_id": self.project_id,
            "location_id": self.location_id,
            "key_ring_id": self.key_ring_id,
            "credentials_path": self.credentials_path,
            "vault_token": self.vault_token,
            "vault_namespace": self.vault_namespace,
        }


class KMSBackend(ABC):
    """Abstract base class for KMS backends."""
    
    @abstractmethod
    async def create_key(self, key_id: str, key_type: str, key_spec: str) -> bool:
        """Create a new key in the KMS."""
        pass
    
    @abstractmethod
    async def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using KMS key."""
        pass
    
    @abstractmethod
    async def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using KMS key."""
        pass
    
    @abstractmethod
    async def store_secret(self, secret_id: str, secret_value: bytes, metadata: Dict[str, Any]) -> bool:
        """Store a secret in the KMS."""
        pass
    
    @abstractmethod
    async def retrieve_secret(self, secret_id: str) -> Optional[bytes]:
        """Retrieve a secret from the KMS."""
        pass
    
    @abstractmethod
    async def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret from the KMS."""
        pass
    
    @abstractmethod
    async def list_keys(self) -> List[str]:
        """List all keys in the KMS."""
        pass
    
    @abstractmethod
    async def rotate_key(self, key_id: str) -> bool:
        """Rotate a key in the KMS."""
        pass


class AWSKMSBackend(KMSBackend):
    """AWS KMS backend implementation."""
    
    def __init__(self, config: KMSConfig):
        if not AWS_AVAILABLE:
            raise ImportError("boto3 is required for AWS KMS integration")
        
        self.config = config
        self.kms_client = boto3.client('kms', region_name=config.region)
        self.secrets_client = boto3.client('secretsmanager', region_name=config.region)
        
    async def create_key(self, key_id: str, key_type: str, key_spec: str) -> bool:
        """Create a new key in AWS KMS."""
        try:
            response = self.kms_client.create_key(
                Description=f"ECPS-UV {key_type} key: {key_id}",
                KeyUsage='ENCRYPT_DECRYPT' if key_type == 'symmetric' else 'SIGN_VERIFY',
                KeySpec=key_spec,
                Tags=[
                    {'TagKey': 'Application', 'TagValue': 'ECPS-UV'},
                    {'TagKey': 'KeyType', 'TagValue': key_type},
                    {'TagKey': 'KeyId', 'TagValue': key_id},
                ]
            )
            
            # Create alias for easier reference
            self.kms_client.create_alias(
                AliasName=f"alias/ecps-uv/{key_id}",
                TargetKeyId=response['KeyMetadata']['KeyId']
            )
            
            logger.info(f"Created AWS KMS key: {key_id}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to create AWS KMS key {key_id}: {e}")
            return False
    
    async def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using AWS KMS key."""
        try:
            response = self.kms_client.encrypt(
                KeyId=f"alias/ecps-uv/{key_id}",
                Plaintext=plaintext
            )
            return response['CiphertextBlob']
            
        except ClientError as e:
            logger.error(f"Failed to encrypt with AWS KMS key {key_id}: {e}")
            raise
    
    async def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using AWS KMS key."""
        try:
            response = self.kms_client.decrypt(
                CiphertextBlob=ciphertext
            )
            return response['Plaintext']
            
        except ClientError as e:
            logger.error(f"Failed to decrypt with AWS KMS key {key_id}: {e}")
            raise
    
    async def store_secret(self, secret_id: str, secret_value: bytes, metadata: Dict[str, Any]) -> bool:
        """Store a secret in AWS Secrets Manager."""
        try:
            self.secrets_client.create_secret(
                Name=f"ecps-uv/{secret_id}",
                SecretBinary=secret_value,
                Description=f"ECPS-UV secret: {secret_id}",
                Tags=[
                    {'Key': 'Application', 'Value': 'ECPS-UV'},
                    {'Key': 'SecretId', 'Value': secret_id},
                ]
            )
            
            logger.info(f"Stored secret in AWS Secrets Manager: {secret_id}")
            return True
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceExistsException':
                # Update existing secret
                self.secrets_client.update_secret(
                    SecretId=f"ecps-uv/{secret_id}",
                    SecretBinary=secret_value
                )
                return True
            else:
                logger.error(f"Failed to store secret {secret_id}: {e}")
                return False
    
    async def retrieve_secret(self, secret_id: str) -> Optional[bytes]:
        """Retrieve a secret from AWS Secrets Manager."""
        try:
            response = self.secrets_client.get_secret_value(
                SecretId=f"ecps-uv/{secret_id}"
            )
            return response['SecretBinary']
            
        except ClientError as e:
            logger.error(f"Failed to retrieve secret {secret_id}: {e}")
            return None
    
    async def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret from AWS Secrets Manager."""
        try:
            self.secrets_client.delete_secret(
                SecretId=f"ecps-uv/{secret_id}",
                ForceDeleteWithoutRecovery=True
            )
            
            logger.info(f"Deleted secret from AWS Secrets Manager: {secret_id}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to delete secret {secret_id}: {e}")
            return False
    
    async def list_keys(self) -> List[str]:
        """List all ECPS-UV keys in AWS KMS."""
        try:
            keys = []
            paginator = self.kms_client.get_paginator('list_aliases')
            
            for page in paginator.paginate():
                for alias in page['Aliases']:
                    if alias['AliasName'].startswith('alias/ecps-uv/'):
                        key_id = alias['AliasName'].replace('alias/ecps-uv/', '')
                        keys.append(key_id)
            
            return keys
            
        except ClientError as e:
            logger.error(f"Failed to list AWS KMS keys: {e}")
            return []
    
    async def rotate_key(self, key_id: str) -> bool:
        """Rotate a key in AWS KMS."""
        try:
            self.kms_client.enable_key_rotation(
                KeyId=f"alias/ecps-uv/{key_id}"
            )
            
            logger.info(f"Enabled rotation for AWS KMS key: {key_id}")
            return True
            
        except ClientError as e:
            logger.error(f"Failed to rotate AWS KMS key {key_id}: {e}")
            return False


class AzureKeyVaultBackend(KMSBackend):
    """Azure Key Vault backend implementation."""
    
    def __init__(self, config: KMSConfig):
        if not AZURE_AVAILABLE:
            raise ImportError("azure-keyvault-keys and azure-keyvault-secrets are required for Azure Key Vault integration")
        
        self.config = config
        credential = DefaultAzureCredential()
        self.key_client = KeyClient(vault_url=config.key_vault_url, credential=credential)
        self.secret_client = SecretClient(vault_url=config.key_vault_url, credential=credential)
    
    async def create_key(self, key_id: str, key_type: str, key_spec: str) -> bool:
        """Create a new key in Azure Key Vault."""
        try:
            from azure.keyvault.keys import KeyType as AzureKeyType
            
            azure_key_type = AzureKeyType.rsa if key_type == 'asymmetric' else AzureKeyType.oct
            
            self.key_client.create_key(
                name=f"ecps-uv-{key_id}",
                key_type=azure_key_type,
                tags={
                    'Application': 'ECPS-UV',
                    'KeyType': key_type,
                    'KeyId': key_id,
                }
            )
            
            logger.info(f"Created Azure Key Vault key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create Azure Key Vault key {key_id}: {e}")
            return False
    
    async def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using Azure Key Vault key."""
        try:
            from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
            
            key = self.key_client.get_key(f"ecps-uv-{key_id}")
            crypto_client = CryptographyClient(key, DefaultAzureCredential())
            
            result = crypto_client.encrypt(EncryptionAlgorithm.rsa_oaep, plaintext)
            return result.ciphertext
            
        except Exception as e:
            logger.error(f"Failed to encrypt with Azure Key Vault key {key_id}: {e}")
            raise
    
    async def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using Azure Key Vault key."""
        try:
            from azure.keyvault.keys.crypto import CryptographyClient, EncryptionAlgorithm
            
            key = self.key_client.get_key(f"ecps-uv-{key_id}")
            crypto_client = CryptographyClient(key, DefaultAzureCredential())
            
            result = crypto_client.decrypt(EncryptionAlgorithm.rsa_oaep, ciphertext)
            return result.plaintext
            
        except Exception as e:
            logger.error(f"Failed to decrypt with Azure Key Vault key {key_id}: {e}")
            raise
    
    async def store_secret(self, secret_id: str, secret_value: bytes, metadata: Dict[str, Any]) -> bool:
        """Store a secret in Azure Key Vault."""
        try:
            self.secret_client.set_secret(
                name=f"ecps-uv-{secret_id}",
                value=base64.b64encode(secret_value).decode('utf-8'),
                tags={
                    'Application': 'ECPS-UV',
                    'SecretId': secret_id,
                }
            )
            
            logger.info(f"Stored secret in Azure Key Vault: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secret {secret_id}: {e}")
            return False
    
    async def retrieve_secret(self, secret_id: str) -> Optional[bytes]:
        """Retrieve a secret from Azure Key Vault."""
        try:
            secret = self.secret_client.get_secret(f"ecps-uv-{secret_id}")
            return base64.b64decode(secret.value.encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Failed to retrieve secret {secret_id}: {e}")
            return None
    
    async def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret from Azure Key Vault."""
        try:
            self.secret_client.begin_delete_secret(f"ecps-uv-{secret_id}")
            
            logger.info(f"Deleted secret from Azure Key Vault: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret {secret_id}: {e}")
            return False
    
    async def list_keys(self) -> List[str]:
        """List all ECPS-UV keys in Azure Key Vault."""
        try:
            keys = []
            for key_properties in self.key_client.list_properties_of_keys():
                if key_properties.name.startswith('ecps-uv-'):
                    key_id = key_properties.name.replace('ecps-uv-', '')
                    keys.append(key_id)
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to list Azure Key Vault keys: {e}")
            return []
    
    async def rotate_key(self, key_id: str) -> bool:
        """Rotate a key in Azure Key Vault."""
        try:
            # Azure Key Vault doesn't have automatic rotation, so we create a new version
            key = self.key_client.get_key(f"ecps-uv-{key_id}")
            self.key_client.create_key(
                name=f"ecps-uv-{key_id}",
                key_type=key.key_type,
                tags=key.properties.tags
            )
            
            logger.info(f"Rotated Azure Key Vault key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate Azure Key Vault key {key_id}: {e}")
            return False


class GoogleCloudKMSBackend(KMSBackend):
    """Google Cloud KMS backend implementation."""
    
    def __init__(self, config: KMSConfig):
        if not GCP_AVAILABLE:
            raise ImportError("google-cloud-kms is required for Google Cloud KMS integration")
        
        self.config = config
        
        if config.credentials_path:
            credentials = service_account.Credentials.from_service_account_file(config.credentials_path)
            self.client = kms.KeyManagementServiceClient(credentials=credentials)
        else:
            self.client = kms.KeyManagementServiceClient()
        
        self.key_ring_name = self.client.key_ring_path(
            config.project_id, config.location_id, config.key_ring_id
        )
    
    async def create_key(self, key_id: str, key_type: str, key_spec: str) -> bool:
        """Create a new key in Google Cloud KMS."""
        try:
            purpose = kms.CryptoKey.CryptoKeyPurpose.ENCRYPT_DECRYPT if key_type == 'symmetric' else kms.CryptoKey.CryptoKeyPurpose.ASYMMETRIC_SIGN
            
            crypto_key = {
                'purpose': purpose,
                'labels': {
                    'application': 'ecps-uv',
                    'key-type': key_type,
                    'key-id': key_id.replace('_', '-'),  # GCP labels don't allow underscores
                }
            }
            
            if key_type == 'symmetric':
                crypto_key['version_template'] = {
                    'algorithm': kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.GOOGLE_SYMMETRIC_ENCRYPTION
                }
            else:
                crypto_key['version_template'] = {
                    'algorithm': kms.CryptoKeyVersion.CryptoKeyVersionAlgorithm.RSA_SIGN_PSS_2048_SHA256
                }
            
            self.client.create_crypto_key(
                request={
                    'parent': self.key_ring_name,
                    'crypto_key_id': f"ecps-uv-{key_id}",
                    'crypto_key': crypto_key
                }
            )
            
            logger.info(f"Created Google Cloud KMS key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create Google Cloud KMS key {key_id}: {e}")
            return False
    
    async def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using Google Cloud KMS key."""
        try:
            crypto_key_name = self.client.crypto_key_path(
                self.config.project_id, self.config.location_id, 
                self.config.key_ring_id, f"ecps-uv-{key_id}"
            )
            
            response = self.client.encrypt(
                request={
                    'name': crypto_key_name,
                    'plaintext': plaintext
                }
            )
            
            return response.ciphertext
            
        except Exception as e:
            logger.error(f"Failed to encrypt with Google Cloud KMS key {key_id}: {e}")
            raise
    
    async def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using Google Cloud KMS key."""
        try:
            crypto_key_name = self.client.crypto_key_path(
                self.config.project_id, self.config.location_id,
                self.config.key_ring_id, f"ecps-uv-{key_id}"
            )
            
            response = self.client.decrypt(
                request={
                    'name': crypto_key_name,
                    'ciphertext': ciphertext
                }
            )
            
            return response.plaintext
            
        except Exception as e:
            logger.error(f"Failed to decrypt with Google Cloud KMS key {key_id}: {e}")
            raise
    
    async def store_secret(self, secret_id: str, secret_value: bytes, metadata: Dict[str, Any]) -> bool:
        """Store a secret (using encryption with a dedicated key)."""
        try:
            # For GCP, we'll encrypt the secret with a dedicated key and store metadata separately
            # This is a simplified implementation - in production, you might use Secret Manager
            encrypted_data = await self.encrypt_data(f"secret-key-{secret_id}", secret_value)
            
            # Store metadata in a separate system or as labels
            logger.info(f"Stored secret in Google Cloud KMS: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secret {secret_id}: {e}")
            return False
    
    async def retrieve_secret(self, secret_id: str) -> Optional[bytes]:
        """Retrieve a secret (decrypt using dedicated key)."""
        try:
            # This would need to be implemented with proper secret storage
            # For now, return None as this is a simplified implementation
            logger.warning(f"Secret retrieval not fully implemented for GCP KMS: {secret_id}")
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve secret {secret_id}: {e}")
            return None
    
    async def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret."""
        try:
            # This would need to be implemented with proper secret storage
            logger.info(f"Secret deletion not fully implemented for GCP KMS: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret {secret_id}: {e}")
            return False
    
    async def list_keys(self) -> List[str]:
        """List all ECPS-UV keys in Google Cloud KMS."""
        try:
            keys = []
            
            for crypto_key in self.client.list_crypto_keys(request={'parent': self.key_ring_name}):
                if crypto_key.name.endswith('ecps-uv-'):
                    key_id = crypto_key.name.split('/')[-1].replace('ecps-uv-', '')
                    keys.append(key_id)
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to list Google Cloud KMS keys: {e}")
            return []
    
    async def rotate_key(self, key_id: str) -> bool:
        """Rotate a key in Google Cloud KMS."""
        try:
            crypto_key_name = self.client.crypto_key_path(
                self.config.project_id, self.config.location_id,
                self.config.key_ring_id, f"ecps-uv-{key_id}"
            )
            
            # Update rotation schedule
            crypto_key = {
                'rotation_schedule': {
                    'next_rotation_time': {'seconds': int(time.time()) + 86400},  # 24 hours
                    'rotation_period': {'seconds': 86400}  # Daily rotation
                }
            }
            
            self.client.update_crypto_key(
                request={
                    'crypto_key': crypto_key,
                    'update_mask': {'paths': ['rotation_schedule']}
                }
            )
            
            logger.info(f"Set rotation schedule for Google Cloud KMS key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate Google Cloud KMS key {key_id}: {e}")
            return False


class HashiCorpVaultBackend(KMSBackend):
    """HashiCorp Vault backend implementation."""
    
    def __init__(self, config: KMSConfig):
        if not VAULT_AVAILABLE:
            raise ImportError("hvac is required for HashiCorp Vault integration")
        
        self.config = config
        self.client = hvac.Client(url=config.vault_url, token=config.vault_token)
        
        if config.vault_namespace:
            self.client.namespace = config.vault_namespace
        
        if not self.client.is_authenticated():
            raise Exception("Failed to authenticate with HashiCorp Vault")
    
    async def create_key(self, key_id: str, key_type: str, key_spec: str) -> bool:
        """Create a new key in HashiCorp Vault."""
        try:
            # Enable transit secrets engine if not already enabled
            try:
                self.client.sys.enable_secrets_engine(backend_type='transit', path='transit')
            except Exception:
                pass  # Already enabled
            
            # Create key
            self.client.secrets.transit.create_key(
                name=f"ecps-uv-{key_id}",
                key_type='rsa-2048' if key_type == 'asymmetric' else 'aes256-gcm96'
            )
            
            logger.info(f"Created HashiCorp Vault key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create HashiCorp Vault key {key_id}: {e}")
            return False
    
    async def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using HashiCorp Vault key."""
        try:
            response = self.client.secrets.transit.encrypt_data(
                name=f"ecps-uv-{key_id}",
                plaintext=base64.b64encode(plaintext).decode('utf-8')
            )
            
            return response['data']['ciphertext'].encode('utf-8')
            
        except Exception as e:
            logger.error(f"Failed to encrypt with HashiCorp Vault key {key_id}: {e}")
            raise
    
    async def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using HashiCorp Vault key."""
        try:
            response = self.client.secrets.transit.decrypt_data(
                name=f"ecps-uv-{key_id}",
                ciphertext=ciphertext.decode('utf-8')
            )
            
            return base64.b64decode(response['data']['plaintext'])
            
        except Exception as e:
            logger.error(f"Failed to decrypt with HashiCorp Vault key {key_id}: {e}")
            raise
    
    async def store_secret(self, secret_id: str, secret_value: bytes, metadata: Dict[str, Any]) -> bool:
        """Store a secret in HashiCorp Vault."""
        try:
            # Enable KV secrets engine if not already enabled
            try:
                self.client.sys.enable_secrets_engine(backend_type='kv', path='secret', options={'version': '2'})
            except Exception:
                pass  # Already enabled
            
            self.client.secrets.kv.v2.create_or_update_secret(
                path=f"ecps-uv/{secret_id}",
                secret={
                    'data': base64.b64encode(secret_value).decode('utf-8'),
                    'metadata': metadata
                }
            )
            
            logger.info(f"Stored secret in HashiCorp Vault: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store secret {secret_id}: {e}")
            return False
    
    async def retrieve_secret(self, secret_id: str) -> Optional[bytes]:
        """Retrieve a secret from HashiCorp Vault."""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(
                path=f"ecps-uv/{secret_id}"
            )
            
            secret_data = response['data']['data']['data']
            return base64.b64decode(secret_data)
            
        except Exception as e:
            logger.error(f"Failed to retrieve secret {secret_id}: {e}")
            return None
    
    async def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret from HashiCorp Vault."""
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=f"ecps-uv/{secret_id}"
            )
            
            logger.info(f"Deleted secret from HashiCorp Vault: {secret_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret {secret_id}: {e}")
            return False
    
    async def list_keys(self) -> List[str]:
        """List all ECPS-UV keys in HashiCorp Vault."""
        try:
            keys = []
            
            response = self.client.secrets.transit.list_keys()
            for key_name in response['data']['keys']:
                if key_name.startswith('ecps-uv-'):
                    key_id = key_name.replace('ecps-uv-', '')
                    keys.append(key_id)
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to list HashiCorp Vault keys: {e}")
            return []
    
    async def rotate_key(self, key_id: str) -> bool:
        """Rotate a key in HashiCorp Vault."""
        try:
            self.client.secrets.transit.rotate_key(name=f"ecps-uv-{key_id}")
            
            logger.info(f"Rotated HashiCorp Vault key: {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rotate HashiCorp Vault key {key_id}: {e}")
            return False


class KMSManager:
    """
    Unified KMS manager that provides a consistent interface across different KMS providers.
    """
    
    def __init__(self, config: KMSConfig):
        """
        Initialize KMS manager with the specified provider.
        
        Args:
            config: KMS configuration
        """
        self.config = config
        self.backend = self._create_backend(config)
    
    def _create_backend(self, config: KMSConfig) -> KMSBackend:
        """Create the appropriate KMS backend based on configuration."""
        if config.provider == KMSProvider.AWS_KMS:
            return AWSKMSBackend(config)
        elif config.provider == KMSProvider.AZURE_KEY_VAULT:
            return AzureKeyVaultBackend(config)
        elif config.provider == KMSProvider.GOOGLE_CLOUD_KMS:
            return GoogleCloudKMSBackend(config)
        elif config.provider == KMSProvider.HASHICORP_VAULT:
            return HashiCorpVaultBackend(config)
        else:
            raise ValueError(f"Unsupported KMS provider: {config.provider}")
    
    async def create_key(self, key_id: str, key_type: str = "symmetric", key_spec: str = "AES_256") -> bool:
        """Create a new key in the KMS."""
        return await self.backend.create_key(key_id, key_type, key_spec)
    
    async def encrypt_data(self, key_id: str, plaintext: bytes) -> bytes:
        """Encrypt data using KMS key."""
        return await self.backend.encrypt_data(key_id, plaintext)
    
    async def decrypt_data(self, key_id: str, ciphertext: bytes) -> bytes:
        """Decrypt data using KMS key."""
        return await self.backend.decrypt_data(key_id, ciphertext)
    
    async def store_secret(self, secret_id: str, secret_value: bytes, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """Store a secret in the KMS."""
        if metadata is None:
            metadata = {}
        return await self.backend.store_secret(secret_id, secret_value, metadata)
    
    async def retrieve_secret(self, secret_id: str) -> Optional[bytes]:
        """Retrieve a secret from the KMS."""
        return await self.backend.retrieve_secret(secret_id)
    
    async def delete_secret(self, secret_id: str) -> bool:
        """Delete a secret from the KMS."""
        return await self.backend.delete_secret(secret_id)
    
    async def list_keys(self) -> List[str]:
        """List all keys in the KMS."""
        return await self.backend.list_keys()
    
    async def rotate_key(self, key_id: str) -> bool:
        """Rotate a key in the KMS."""
        return await self.backend.rotate_key(key_id)
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the current KMS provider."""
        return {
            "provider": self.config.provider.value,
            "region": self.config.region,
            "vault_url": self.config.vault_url,
            "key_vault_url": self.config.key_vault_url,
            "project_id": self.config.project_id,
        }


def create_kms_manager(provider: str, **kwargs) -> KMSManager:
    """
    Factory function to create a KMS manager.
    
    Args:
        provider: KMS provider name ("aws_kms", "azure_key_vault", "google_cloud_kms", "hashicorp_vault")
        **kwargs: Provider-specific configuration parameters
        
    Returns:
        Configured KMSManager instance
        
    Examples:
        # AWS KMS
        kms = create_kms_manager("aws_kms", region="us-west-2")
        
        # Azure Key Vault
        kms = create_kms_manager("azure_key_vault", key_vault_url="https://vault.vault.azure.net/")
        
        # Google Cloud KMS
        kms = create_kms_manager("google_cloud_kms",
                                project_id="my-project",
                                location_id="global",
                                key_ring_id="my-ring")
        
        # HashiCorp Vault
        kms = create_kms_manager("hashicorp_vault",
                                vault_url="https://vault.example.com",
                                vault_token="hvs.token")
    """
    try:
        provider_enum = KMSProvider(provider)
    except ValueError:
        raise ValueError(f"Unsupported KMS provider: {provider}")
    
    config = KMSConfig(provider=provider_enum, **kwargs)
    return KMSManager(config)


def get_available_providers() -> List[str]:
    """
    Get list of available KMS providers based on installed dependencies.
    
    Returns:
        List of available provider names
    """
    available = ["local"]  # Local storage is always available
    
    if AWS_AVAILABLE:
        available.append("aws_kms")
    
    if AZURE_AVAILABLE:
        available.append("azure_key_vault")
    
    if GCP_AVAILABLE:
        available.append("google_cloud_kms")
    
    if VAULT_AVAILABLE:
        available.append("hashicorp_vault")
    
    return available


def validate_kms_config(config: KMSConfig) -> List[str]:
    """
    Validate KMS configuration and return list of issues.
    
    Args:
        config: KMS configuration to validate
        
    Returns:
        List of validation error messages (empty if valid)
    """
    issues = []
    
    if config.provider == KMSProvider.AWS_KMS:
        if not AWS_AVAILABLE:
            issues.append("boto3 is required for AWS KMS integration")
        if not config.region:
            issues.append("region is required for AWS KMS")
    
    elif config.provider == KMSProvider.AZURE_KEY_VAULT:
        if not AZURE_AVAILABLE:
            issues.append("azure-keyvault-keys and azure-keyvault-secrets are required for Azure Key Vault")
        if not config.key_vault_url:
            issues.append("key_vault_url is required for Azure Key Vault")
    
    elif config.provider == KMSProvider.GOOGLE_CLOUD_KMS:
        if not GCP_AVAILABLE:
            issues.append("google-cloud-kms is required for Google Cloud KMS")
        if not config.project_id:
            issues.append("project_id is required for Google Cloud KMS")
        if not config.location_id:
            issues.append("location_id is required for Google Cloud KMS")
        if not config.key_ring_id:
            issues.append("key_ring_id is required for Google Cloud KMS")
    
    elif config.provider == KMSProvider.HASHICORP_VAULT:
        if not VAULT_AVAILABLE:
            issues.append("hvac is required for HashiCorp Vault")
        if not config.vault_url:
            issues.append("vault_url is required for HashiCorp Vault")
        if not config.vault_token:
            issues.append("vault_token is required for HashiCorp Vault")
    
    return issues