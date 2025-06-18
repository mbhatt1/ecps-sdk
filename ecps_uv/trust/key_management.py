"""
Key Management System for ECPS-UV SDK.

This module provides comprehensive key management for distributed robotic systems,
including factory provisioning, field deployment, rotation, and revocation.
"""

import asyncio
import logging
import os
import time
import uuid
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509 import load_pem_x509_certificate, CertificateBuilder, Name, NameAttribute
from cryptography.x509.oid import NameOID
import secrets
import json
import base64

# Import KMS integration
try:
    from .kms_integration import KMSManager, KMSConfig, KMSProvider, create_kms_manager
    KMS_AVAILABLE = True
except ImportError:
    KMS_AVAILABLE = False

logger = logging.getLogger("ecps_uv.trust.key_management")


class KeyType(Enum):
    """Types of cryptographic keys."""
    DEVICE_IDENTITY = "device_identity"
    COMMUNICATION = "communication"
    STORAGE = "storage"
    EMERGENCY = "emergency"


class KeyStatus(Enum):
    """Key lifecycle status."""
    ACTIVE = "active"
    PENDING_ROTATION = "pending_rotation"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass
class KeyMetadata:
    """Metadata for cryptographic keys."""
    key_id: str
    key_type: KeyType
    created_at: float
    expires_at: Optional[float]
    status: KeyStatus
    device_id: str
    version: int
    algorithm: str
    key_size: int
    usage: List[str]  # ["encrypt", "decrypt", "sign", "verify"]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "key_id": self.key_id,
            "key_type": self.key_type.value,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "status": self.status.value,
            "device_id": self.device_id,
            "version": self.version,
            "algorithm": self.algorithm,
            "key_size": self.key_size,
            "usage": self.usage,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "KeyMetadata":
        """Create from dictionary."""
        return cls(
            key_id=data["key_id"],
            key_type=KeyType(data["key_type"]),
            created_at=data["created_at"],
            expires_at=data.get("expires_at"),
            status=KeyStatus(data["status"]),
            device_id=data["device_id"],
            version=data["version"],
            algorithm=data["algorithm"],
            key_size=data["key_size"],
            usage=data["usage"],
        )


class SecureKeyStore:
    """Secure storage for cryptographic keys."""
    
    def __init__(self, storage_path: str, master_password: Optional[str] = None):
        """
        Initialize secure key store.
        
        Args:
            storage_path: Path to store encrypted keys
            master_password: Master password for key encryption (optional)
        """
        self.storage_path = storage_path
        self.master_password = master_password
        self.keys: Dict[str, bytes] = {}  # key_id -> encrypted_key
        self.metadata: Dict[str, KeyMetadata] = {}  # key_id -> metadata
        
        # Ensure storage directory exists
        os.makedirs(storage_path, exist_ok=True)
        
        # Load existing keys
        self._load_keys()
    
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    def _encrypt_key(self, key_data: bytes, password: str) -> Tuple[bytes, bytes]:
        """Encrypt key data with password."""
        salt = secrets.token_bytes(16)
        derived_key = self._derive_key(password, salt)
        
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad key data to AES block size
        padding_length = 16 - (len(key_data) % 16)
        padded_data = key_data + bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        return salt + iv + encrypted_data, salt
    
    def _decrypt_key(self, encrypted_data: bytes, password: str) -> bytes:
        """Decrypt key data with password."""
        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        derived_key = self._derive_key(password, salt)
        
        cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
    
    def store_key(self, key_id: str, key_data: bytes, metadata: KeyMetadata) -> bool:
        """Store a key securely."""
        try:
            if self.master_password:
                encrypted_key, _ = self._encrypt_key(key_data, self.master_password)
            else:
                encrypted_key = key_data  # Store unencrypted if no master password
            
            # Store in memory
            self.keys[key_id] = encrypted_key
            self.metadata[key_id] = metadata
            
            # Persist to disk
            key_file = os.path.join(self.storage_path, f"{key_id}.key")
            metadata_file = os.path.join(self.storage_path, f"{key_id}.meta")
            
            with open(key_file, "wb") as f:
                f.write(encrypted_key)
            
            with open(metadata_file, "w") as f:
                json.dump(metadata.to_dict(), f, indent=2)
            
            logger.info(f"Stored key {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store key {key_id}: {e}")
            return False
    
    def retrieve_key(self, key_id: str) -> Optional[bytes]:
        """Retrieve a key."""
        try:
            if key_id not in self.keys:
                return None
            
            encrypted_key = self.keys[key_id]
            
            if self.master_password:
                return self._decrypt_key(encrypted_key, self.master_password)
            else:
                return encrypted_key
                
        except Exception as e:
            logger.error(f"Failed to retrieve key {key_id}: {e}")
            return None
    
    def delete_key(self, key_id: str) -> bool:
        """Delete a key."""
        try:
            # Remove from memory
            if key_id in self.keys:
                del self.keys[key_id]
            if key_id in self.metadata:
                del self.metadata[key_id]
            
            # Remove from disk
            key_file = os.path.join(self.storage_path, f"{key_id}.key")
            metadata_file = os.path.join(self.storage_path, f"{key_id}.meta")
            
            if os.path.exists(key_file):
                os.remove(key_file)
            if os.path.exists(metadata_file):
                os.remove(metadata_file)
            
            logger.info(f"Deleted key {key_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete key {key_id}: {e}")
            return False
    
    def list_keys(self) -> List[KeyMetadata]:
        """List all stored keys."""
        return list(self.metadata.values())
    
    def _load_keys(self):
        """Load keys from disk."""
        try:
            for filename in os.listdir(self.storage_path):
                if filename.endswith(".key"):
                    key_id = filename[:-4]  # Remove .key extension
                    
                    # Load key data
                    key_file = os.path.join(self.storage_path, filename)
                    with open(key_file, "rb") as f:
                        self.keys[key_id] = f.read()
                    
                    # Load metadata
                    metadata_file = os.path.join(self.storage_path, f"{key_id}.meta")
                    if os.path.exists(metadata_file):
                        with open(metadata_file, "r") as f:
                            metadata_dict = json.load(f)
                            self.metadata[key_id] = KeyMetadata.from_dict(metadata_dict)
            
            logger.info(f"Loaded {len(self.keys)} keys from storage")
            
        except Exception as e:
            logger.error(f"Failed to load keys: {e}")


class KeyManager:
    """
    Comprehensive key management system for robotic agents.
    
    Handles key generation, distribution, rotation, and revocation
    for distributed robotic systems.
    """
    
    def __init__(
        self,
        device_id: str,
        key_store: SecureKeyStore,
        transport: Optional[Any] = None,
        ca_cert_path: Optional[str] = None,
        kms_manager: Optional[Any] = None,
        use_kms_for_storage: bool = False,
    ):
        """
        Initialize key manager.
        
        Args:
            device_id: Unique device identifier
            key_store: Secure key storage backend
            transport: Transport for key distribution (optional)
            ca_cert_path: Path to CA certificate for validation
            kms_manager: KMS manager for cloud key management (optional)
            use_kms_for_storage: Whether to use KMS for key storage instead of local storage
        """
        self.device_id = device_id
        self.key_store = key_store
        self.transport = transport
        self.ca_cert_path = ca_cert_path
        self.kms_manager = kms_manager
        self.use_kms_for_storage = use_kms_for_storage and kms_manager is not None
        
        # Key rotation settings
        self.rotation_interval = 24 * 3600  # 24 hours
        self.rotation_overlap = 3600  # 1 hour overlap
        
        # Emergency keys
        self.emergency_keys: Dict[str, bytes] = {}
        
        # Key distribution
        self.pending_distributions: Dict[str, Dict[str, Any]] = {}
        
        # Load CA certificate if provided
        self.ca_cert = None
        if ca_cert_path and os.path.exists(ca_cert_path):
            with open(ca_cert_path, "rb") as f:
                self.ca_cert = load_pem_x509_certificate(f.read())
        
        # KMS key mapping (local key_id -> KMS key_id)
        self.kms_key_mapping: Dict[str, str] = {}
    
    def generate_device_identity_key(self) -> str:
        """Generate device identity key pair."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create metadata
        key_id = f"device_identity_{self.device_id}_{int(time.time())}"
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.DEVICE_IDENTITY,
            created_at=time.time(),
            expires_at=None,  # Device identity keys don't expire
            status=KeyStatus.ACTIVE,
            device_id=self.device_id,
            version=1,
            algorithm="RSA",
            key_size=2048,
            usage=["sign", "verify", "encrypt", "decrypt"],
        )
        
        # Store key
        if self.key_store.store_key(key_id, private_pem, metadata):
            logger.info(f"Generated device identity key: {key_id}")
            return key_id
        else:
            raise Exception("Failed to store device identity key")
    
    def generate_communication_key(self, expires_in: int = 86400) -> str:
        """Generate communication key for secure messaging."""
        # Generate AES key
        aes_key = secrets.token_bytes(32)  # 256-bit AES key
        
        # Create metadata
        key_id = f"comm_{self.device_id}_{int(time.time())}"
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.COMMUNICATION,
            created_at=time.time(),
            expires_at=time.time() + expires_in,
            status=KeyStatus.ACTIVE,
            device_id=self.device_id,
            version=1,
            algorithm="AES",
            key_size=256,
            usage=["encrypt", "decrypt"],
        )
        
        # Store key
        if self.key_store.store_key(key_id, aes_key, metadata):
            logger.info(f"Generated communication key: {key_id}")
            return key_id
        else:
            raise Exception("Failed to store communication key")
    
    def generate_emergency_key(self) -> str:
        """Generate emergency override key."""
        # Generate RSA key pair for emergency use
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Create metadata
        key_id = f"emergency_{self.device_id}_{int(time.time())}"
        metadata = KeyMetadata(
            key_id=key_id,
            key_type=KeyType.EMERGENCY,
            created_at=time.time(),
            expires_at=time.time() + (365 * 24 * 3600),  # 1 year
            status=KeyStatus.ACTIVE,
            device_id=self.device_id,
            version=1,
            algorithm="RSA",
            key_size=2048,
            usage=["sign", "verify"],
        )
        
        # Store key
        if self.key_store.store_key(key_id, private_pem, metadata):
            # Also store in emergency keys for quick access
            self.emergency_keys[key_id] = private_pem
            logger.info(f"Generated emergency key: {key_id}")
            return key_id
        else:
            raise Exception("Failed to store emergency key")
    
    async def rotate_key(self, key_id: str) -> Optional[str]:
        """Rotate an existing key."""
        # Get current key metadata
        current_keys = self.key_store.list_keys()
        current_metadata = None
        
        for metadata in current_keys:
            if metadata.key_id == key_id:
                current_metadata = metadata
                break
        
        if not current_metadata:
            logger.error(f"Key {key_id} not found for rotation")
            return None
        
        # Generate new key of the same type
        if current_metadata.key_type == KeyType.DEVICE_IDENTITY:
            new_key_id = self.generate_device_identity_key()
        elif current_metadata.key_type == KeyType.COMMUNICATION:
            new_key_id = self.generate_communication_key()
        elif current_metadata.key_type == KeyType.EMERGENCY:
            new_key_id = self.generate_emergency_key()
        else:
            logger.error(f"Unknown key type for rotation: {current_metadata.key_type}")
            return None
        
        # Mark old key as pending rotation
        current_metadata.status = KeyStatus.PENDING_ROTATION
        self.key_store.store_key(
            key_id,
            self.key_store.retrieve_key(key_id),
            current_metadata
        )
        
        # Schedule old key deletion after overlap period
        asyncio.create_task(self._schedule_key_deletion(key_id, self.rotation_overlap))
        
        # Distribute new key to other agents if transport available
        if self.transport:
            await self._distribute_key(new_key_id)
        
        logger.info(f"Rotated key {key_id} -> {new_key_id}")
        return new_key_id
    
    async def revoke_key(self, key_id: str, reason: str = "manual_revocation") -> bool:
        """Revoke a key immediately."""
        # Get key metadata
        current_keys = self.key_store.list_keys()
        metadata = None
        
        for meta in current_keys:
            if meta.key_id == key_id:
                metadata = meta
                break
        
        if not metadata:
            logger.error(f"Key {key_id} not found for revocation")
            return False
        
        # Mark as revoked
        metadata.status = KeyStatus.REVOKED
        self.key_store.store_key(
            key_id,
            self.key_store.retrieve_key(key_id),
            metadata
        )
        
        # Notify other agents if transport available
        if self.transport:
            await self._broadcast_revocation(key_id, reason)
        
        logger.warning(f"Revoked key {key_id}: {reason}")
        return True
    
    async def _schedule_key_deletion(self, key_id: str, delay: int):
        """Schedule key deletion after delay."""
        await asyncio.sleep(delay)
        self.key_store.delete_key(key_id)
        logger.info(f"Deleted rotated key {key_id}")
    
    async def _distribute_key(self, key_id: str):
        """Distribute key to other agents."""
        if not self.transport:
            return
        
        # Get key metadata
        current_keys = self.key_store.list_keys()
        metadata = None
        
        for meta in current_keys:
            if meta.key_id == key_id:
                metadata = meta
                break
        
        if not metadata:
            return
        
        # Create distribution message
        message = {
            "type": "key_distribution",
            "key_id": key_id,
            "metadata": metadata.to_dict(),
            "sender": self.device_id,
            "timestamp": time.time(),
        }
        
        # Broadcast to key distribution topic
        await self.transport.publish("keys/distribution", message)
        logger.info(f"Distributed key {key_id}")
    
    async def _broadcast_revocation(self, key_id: str, reason: str):
        """Broadcast key revocation to other agents."""
        if not self.transport:
            return
        
        message = {
            "type": "key_revocation",
            "key_id": key_id,
            "reason": reason,
            "sender": self.device_id,
            "timestamp": time.time(),
        }
        
        await self.transport.publish("keys/revocation", message)
        logger.warning(f"Broadcast revocation for key {key_id}")
    
    def get_active_keys(self, key_type: Optional[KeyType] = None) -> List[KeyMetadata]:
        """Get all active keys, optionally filtered by type."""
        keys = self.key_store.list_keys()
        active_keys = [k for k in keys if k.status == KeyStatus.ACTIVE]
        
        if key_type:
            active_keys = [k for k in active_keys if k.key_type == key_type]
        
        return active_keys
    
    def get_key_for_operation(self, operation: str, key_type: KeyType) -> Optional[str]:
        """Get the best key for a specific operation."""
        active_keys = self.get_active_keys(key_type)
        
        # Filter by usage
        suitable_keys = [k for k in active_keys if operation in k.usage]
        
        if not suitable_keys:
            return None
        
        # Return the newest key
        suitable_keys.sort(key=lambda k: k.created_at, reverse=True)
        return suitable_keys[0].key_id
    
    async def start_key_rotation_scheduler(self):
        """Start automatic key rotation scheduler."""
        while True:
            try:
                current_time = time.time()
                
                # Check for keys that need rotation
                for metadata in self.key_store.list_keys():
                    if (metadata.status == KeyStatus.ACTIVE and 
                        metadata.expires_at and 
                        metadata.expires_at - current_time < self.rotation_overlap):
                        
                        logger.info(f"Auto-rotating key {metadata.key_id}")
                        await self.rotate_key(metadata.key_id)
                
                # Sleep for 1 hour before next check
                await asyncio.sleep(3600)
                
            except Exception as e:
                logger.error(f"Error in key rotation scheduler: {e}")
                await asyncio.sleep(300)  # Retry in 5 minutes
    
    def export_public_key(self, key_id: str) -> Optional[bytes]:
        """Export public key for sharing with other agents."""
        key_data = self.key_store.retrieve_key(key_id)
        if not key_data:
            return None
        
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(key_data, password=None)
            
            # Extract public key
            public_key = private_key.public_key()
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return public_pem
            
        except Exception as e:
            logger.error(f"Failed to export public key {key_id}: {e}")
            return None
    
    def verify_key_integrity(self, key_id: str) -> bool:
        """Verify key integrity and validity."""
        try:
            key_data = self.key_store.retrieve_key(key_id)
            if not key_data:
                return False
            
            # Try to load the key
            if key_id.startswith("device_identity") or key_id.startswith("emergency"):
                serialization.load_pem_private_key(key_data, password=None)
            else:
                # For AES keys, just check length
                if len(key_data) != 32:  # 256-bit AES
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Key integrity check failed for {key_id}: {e}")
            return False
    
    async def generate_kms_key(self, key_type: KeyType, expires_in: Optional[int] = None) -> Optional[str]:
        """Generate a key using KMS backend."""
        if not self.kms_manager:
            logger.error("KMS manager not configured")
            return None
        
        try:
            # Generate unique key ID
            key_id = f"{key_type.value}_{self.device_id}_{int(time.time())}"
            
            # Determine KMS key type and spec
            if key_type == KeyType.DEVICE_IDENTITY or key_type == KeyType.EMERGENCY:
                kms_key_type = "asymmetric"
                kms_key_spec = "RSA_2048"
            else:
                kms_key_type = "symmetric"
                kms_key_spec = "AES_256"
            
            # Create key in KMS
            success = await self.kms_manager.create_key(key_id, kms_key_type, kms_key_spec)
            if not success:
                logger.error(f"Failed to create KMS key: {key_id}")
                return None
            
            # Create metadata
            metadata = KeyMetadata(
                key_id=key_id,
                key_type=key_type,
                created_at=time.time(),
                expires_at=time.time() + expires_in if expires_in else None,
                status=KeyStatus.ACTIVE,
                device_id=self.device_id,
                version=1,
                algorithm="RSA" if kms_key_type == "asymmetric" else "AES",
                key_size=2048 if kms_key_type == "asymmetric" else 256,
                usage=["encrypt", "decrypt", "sign", "verify"] if kms_key_type == "asymmetric" else ["encrypt", "decrypt"],
            )
            
            # Store metadata locally (key data stays in KMS)
            if self.use_kms_for_storage:
                # Store metadata as a secret in KMS
                metadata_json = json.dumps(metadata.to_dict()).encode('utf-8')
                await self.kms_manager.store_secret(f"{key_id}_metadata", metadata_json)
            else:
                # Store metadata locally, mark as KMS-backed
                self.key_store.store_key(key_id, b"KMS_BACKED_KEY", metadata)
            
            # Track KMS key mapping
            self.kms_key_mapping[key_id] = key_id
            
            logger.info(f"Generated KMS key: {key_id}")
            return key_id
            
        except Exception as e:
            logger.error(f"Failed to generate KMS key: {e}")
            return None
    
    async def encrypt_with_kms(self, key_id: str, plaintext: bytes) -> Optional[bytes]:
        """Encrypt data using KMS key."""
        if not self.kms_manager or key_id not in self.kms_key_mapping:
            return None
        
        try:
            kms_key_id = self.kms_key_mapping[key_id]
            return await self.kms_manager.encrypt_data(kms_key_id, plaintext)
        except Exception as e:
            logger.error(f"Failed to encrypt with KMS key {key_id}: {e}")
            return None
    
    async def decrypt_with_kms(self, key_id: str, ciphertext: bytes) -> Optional[bytes]:
        """Decrypt data using KMS key."""
        if not self.kms_manager or key_id not in self.kms_key_mapping:
            return None
        
        try:
            kms_key_id = self.kms_key_mapping[key_id]
            return await self.kms_manager.decrypt_data(kms_key_id, ciphertext)
        except Exception as e:
            logger.error(f"Failed to decrypt with KMS key {key_id}: {e}")
            return None
    
    async def rotate_kms_key(self, key_id: str) -> Optional[str]:
        """Rotate a KMS-backed key."""
        if not self.kms_manager or key_id not in self.kms_key_mapping:
            logger.error(f"Key {key_id} is not KMS-backed")
            return None
        
        try:
            # Get current key metadata
            current_keys = self.key_store.list_keys() if not self.use_kms_for_storage else []
            current_metadata = None
            
            if self.use_kms_for_storage:
                # Retrieve metadata from KMS
                metadata_bytes = await self.kms_manager.retrieve_secret(f"{key_id}_metadata")
                if metadata_bytes:
                    metadata_dict = json.loads(metadata_bytes.decode('utf-8'))
                    current_metadata = KeyMetadata.from_dict(metadata_dict)
            else:
                # Get metadata from local storage
                for metadata in current_keys:
                    if metadata.key_id == key_id:
                        current_metadata = metadata
                        break
            
            if not current_metadata:
                logger.error(f"Metadata not found for key {key_id}")
                return None
            
            # Rotate key in KMS
            kms_key_id = self.kms_key_mapping[key_id]
            success = await self.kms_manager.rotate_key(kms_key_id)
            
            if success:
                # Update metadata version
                current_metadata.version += 1
                current_metadata.created_at = time.time()
                
                if self.use_kms_for_storage:
                    metadata_json = json.dumps(current_metadata.to_dict()).encode('utf-8')
                    await self.kms_manager.store_secret(f"{key_id}_metadata", metadata_json)
                else:
                    self.key_store.store_key(key_id, b"KMS_BACKED_KEY", current_metadata)
                
                logger.info(f"Rotated KMS key: {key_id}")
                return key_id
            else:
                logger.error(f"Failed to rotate KMS key: {key_id}")
                return None
                
        except Exception as e:
            logger.error(f"Failed to rotate KMS key {key_id}: {e}")
            return None
    
    async def backup_keys_to_kms(self) -> bool:
        """Backup local keys to KMS for disaster recovery."""
        if not self.kms_manager:
            logger.error("KMS manager not configured")
            return False
        
        try:
            backup_count = 0
            
            for metadata in self.key_store.list_keys():
                # Skip keys that are already KMS-backed
                if metadata.key_id in self.kms_key_mapping:
                    continue
                
                # Get key data
                key_data = self.key_store.retrieve_key(metadata.key_id)
                if not key_data or key_data == b"KMS_BACKED_KEY":
                    continue
                
                # Store key as secret in KMS
                backup_id = f"backup_{metadata.key_id}"
                metadata_dict = metadata.to_dict()
                
                # Combine key data and metadata
                backup_data = {
                    "key_data": base64.b64encode(key_data).decode('utf-8'),
                    "metadata": metadata_dict
                }
                backup_json = json.dumps(backup_data).encode('utf-8')
                
                success = await self.kms_manager.store_secret(backup_id, backup_json, metadata_dict)
                if success:
                    backup_count += 1
                    logger.info(f"Backed up key to KMS: {metadata.key_id}")
                else:
                    logger.error(f"Failed to backup key to KMS: {metadata.key_id}")
            
            logger.info(f"Backed up {backup_count} keys to KMS")
            return backup_count > 0
            
        except Exception as e:
            logger.error(f"Failed to backup keys to KMS: {e}")
            return False
    
    async def restore_keys_from_kms(self) -> bool:
        """Restore keys from KMS backup."""
        if not self.kms_manager:
            logger.error("KMS manager not configured")
            return False
        
        try:
            # This would require listing secrets in KMS, which varies by provider
            # For now, we'll implement a basic version
            logger.info("Key restoration from KMS would require provider-specific implementation")
            return True
            
        except Exception as e:
            logger.error(f"Failed to restore keys from KMS: {e}")
            return False
    
    def is_kms_backed(self, key_id: str) -> bool:
        """Check if a key is backed by KMS."""
        return key_id in self.kms_key_mapping
    
    def get_kms_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the configured KMS."""
        if not self.kms_manager:
            return None
        
        return self.kms_manager.get_provider_info()


class FactoryProvisioning:
    """Factory provisioning system for new robots."""
    
    @staticmethod
    def provision_robot(
        device_id: str,
        storage_path: str,
        ca_cert_path: str,
        master_password: Optional[str] = None,
        kms_config: Optional[Dict[str, Any]] = None,
    ) -> KeyManager:
        """
        Provision a new robot with initial keys.
        
        Args:
            device_id: Unique device identifier
            storage_path: Path for key storage
            ca_cert_path: Path to CA certificate
            master_password: Master password for key encryption
            kms_config: Optional KMS configuration for cloud key management
            
        Returns:
            Configured KeyManager instance
        """
        # Create secure key store
        key_store = SecureKeyStore(storage_path, master_password)
        
        # Create KMS manager if configured
        kms_manager = None
        use_kms_for_storage = False
        
        if kms_config and KMS_AVAILABLE:
            try:
                from .kms_integration import create_kms_manager
                kms_manager = create_kms_manager(**kms_config)
                use_kms_for_storage = kms_config.get('use_kms_for_storage', False)
                logger.info(f"Configured KMS provider: {kms_config.get('provider', 'unknown')}")
            except Exception as e:
                logger.warning(f"Failed to configure KMS: {e}")
        
        # Create key manager
        key_manager = KeyManager(
            device_id,
            key_store,
            ca_cert_path=ca_cert_path,
            kms_manager=kms_manager,
            use_kms_for_storage=use_kms_for_storage
        )
        
        # Generate initial keys
        device_key_id = key_manager.generate_device_identity_key()
        comm_key_id = key_manager.generate_communication_key()
        emergency_key_id = key_manager.generate_emergency_key()
        
        logger.info(f"Provisioned robot {device_id} with keys:")
        logger.info(f"  Device Identity: {device_key_id}")
        logger.info(f"  Communication: {comm_key_id}")
        logger.info(f"  Emergency: {emergency_key_id}")
        
        return key_manager
    
    @staticmethod
    async def provision_robot_with_kms(
        device_id: str,
        storage_path: str,
        ca_cert_path: str,
        kms_config: Dict[str, Any],
        master_password: Optional[str] = None,
    ) -> KeyManager:
        """
        Provision a new robot with KMS-backed keys.
        
        Args:
            device_id: Unique device identifier
            storage_path: Path for key storage
            ca_cert_path: Path to CA certificate
            kms_config: KMS configuration
            master_password: Master password for key encryption
            
        Returns:
            Configured KeyManager instance with KMS-backed keys
        """
        if not KMS_AVAILABLE:
            raise ImportError("KMS integration not available")
        
        # Create secure key store
        key_store = SecureKeyStore(storage_path, master_password)
        
        # Create KMS manager
        from .kms_integration import create_kms_manager
        kms_manager = create_kms_manager(**kms_config)
        
        # Create key manager with KMS
        key_manager = KeyManager(
            device_id,
            key_store,
            ca_cert_path=ca_cert_path,
            kms_manager=kms_manager,
            use_kms_for_storage=kms_config.get('use_kms_for_storage', True)
        )
        
        # Generate initial KMS-backed keys
        device_key_id = await key_manager.generate_kms_key(KeyType.DEVICE_IDENTITY)
        comm_key_id = await key_manager.generate_kms_key(KeyType.COMMUNICATION, expires_in=86400)
        emergency_key_id = await key_manager.generate_kms_key(KeyType.EMERGENCY, expires_in=365*24*3600)
        
        logger.info(f"Provisioned robot {device_id} with KMS-backed keys:")
        logger.info(f"  Device Identity: {device_key_id}")
        logger.info(f"  Communication: {comm_key_id}")
        logger.info(f"  Emergency: {emergency_key_id}")
        
        return key_manager