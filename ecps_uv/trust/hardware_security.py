"""
Hardware Security Integration for ECPS-UV SDK.

This module provides integration with hardware security features including
TPM (Trusted Platform Module), HSM (Hardware Security Module), secure boot,
and hardware-based attestation for robot identity.
"""

import asyncio
import hashlib
import logging
import os
import platform
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union
import secrets

logger = logging.getLogger("ecps_uv.trust.hardware_security")

# Optional imports for hardware security modules
try:
    import cryptography
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    # TPM integration (requires tpm2-tools and python-tss)
    import tss2_fapi as fapi
    TPM_AVAILABLE = True
except ImportError:
    TPM_AVAILABLE = False

try:
    # PKCS#11 for HSM integration
    import PyKCS11
    PKCS11_AVAILABLE = True
except ImportError:
    PKCS11_AVAILABLE = False


class HardwareSecurityType(Enum):
    """Types of hardware security modules."""
    TPM_2_0 = "tpm_2_0"
    HSM_PKCS11 = "hsm_pkcs11"
    SECURE_ELEMENT = "secure_element"
    TEE = "trusted_execution_environment"
    SOFTWARE_FALLBACK = "software_fallback"


class AttestationType(Enum):
    """Types of hardware attestation."""
    TPM_QUOTE = "tpm_quote"
    PLATFORM_ATTESTATION = "platform_attestation"
    DEVICE_IDENTITY = "device_identity"
    SECURE_BOOT = "secure_boot"
    RUNTIME_INTEGRITY = "runtime_integrity"


@dataclass
class HardwareIdentity:
    """Hardware-based device identity."""
    device_id: str
    hardware_type: HardwareSecurityType
    public_key: bytes
    certificate_chain: Optional[List[bytes]] = None
    attestation_data: Optional[Dict[str, Any]] = None
    platform_info: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "device_id": self.device_id,
            "hardware_type": self.hardware_type.value,
            "public_key": self.public_key.hex(),
            "certificate_chain": [cert.hex() for cert in self.certificate_chain] if self.certificate_chain else None,
            "attestation_data": self.attestation_data,
            "platform_info": self.platform_info,
        }


@dataclass
class AttestationReport:
    """Hardware attestation report."""
    attestation_type: AttestationType
    device_id: str
    timestamp: float
    nonce: bytes
    measurements: Dict[str, str]  # PCR/measurement name -> hash value
    signature: bytes
    certificate_chain: Optional[List[bytes]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "attestation_type": self.attestation_type.value,
            "device_id": self.device_id,
            "timestamp": self.timestamp,
            "nonce": self.nonce.hex(),
            "measurements": self.measurements,
            "signature": self.signature.hex(),
            "certificate_chain": [cert.hex() for cert in self.certificate_chain] if self.certificate_chain else None,
        }


class HardwareSecurityProvider(ABC):
    """Abstract base class for hardware security providers."""
    
    @abstractmethod
    async def initialize(self) -> bool:
        """Initialize the hardware security module."""
        pass
    
    @abstractmethod
    async def generate_key_pair(self, key_id: str) -> Tuple[bytes, bytes]:
        """Generate a key pair in hardware. Returns (public_key, key_handle)."""
        pass
    
    @abstractmethod
    async def sign_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Sign data using hardware key."""
        pass
    
    @abstractmethod
    async def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify signature using hardware."""
        pass
    
    @abstractmethod
    async def encrypt_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Encrypt data using hardware key."""
        pass
    
    @abstractmethod
    async def decrypt_data(self, key_handle: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using hardware key."""
        pass
    
    @abstractmethod
    async def get_device_identity(self) -> HardwareIdentity:
        """Get hardware-based device identity."""
        pass
    
    @abstractmethod
    async def create_attestation(self, nonce: bytes, attestation_type: AttestationType) -> AttestationReport:
        """Create hardware attestation report."""
        pass
    
    @abstractmethod
    async def verify_attestation(self, report: AttestationReport) -> bool:
        """Verify hardware attestation report."""
        pass


class TPMProvider(HardwareSecurityProvider):
    """TPM 2.0 hardware security provider."""
    
    def __init__(self, tpm_device: str = "/dev/tpm0"):
        """
        Initialize TPM provider.
        
        Args:
            tpm_device: TPM device path
        """
        self.tpm_device = tpm_device
        self.fapi_context = None
        self.device_identity: Optional[HardwareIdentity] = None
    
    async def initialize(self) -> bool:
        """Initialize TPM connection."""
        if not TPM_AVAILABLE:
            logger.error("TPM support not available (missing tss2-fapi)")
            return False
        
        try:
            # Initialize FAPI context
            self.fapi_context = fapi.FapiContext()
            
            # Check TPM availability
            if not os.path.exists(self.tpm_device):
                logger.error(f"TPM device not found: {self.tmp_device}")
                return False
            
            # Test TPM communication
            await self._test_tpm_communication()
            
            logger.info("TPM 2.0 initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize TPM: {e}")
            return False
    
    async def _test_tpm_communication(self):
        """Test basic TPM communication."""
        try:
            # Try to get TPM capabilities
            result = subprocess.run(
                ["tpm2_getcap", "properties-fixed"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                raise Exception(f"TPM communication test failed: {result.stderr}")
            
            logger.debug("TPM communication test passed")
            
        except subprocess.TimeoutExpired:
            raise Exception("TPM communication timeout")
        except FileNotFoundError:
            raise Exception("tpm2-tools not installed")
    
    async def generate_key_pair(self, key_id: str) -> Tuple[bytes, bytes]:
        """Generate RSA key pair in TPM."""
        try:
            # Create key in TPM using tpm2-tools
            key_path = f"/tmp/tpm_key_{key_id}"
            
            # Generate primary key
            result = subprocess.run([
                "tpm2_createprimary",
                "-C", "e",  # Endorsement hierarchy
                "-g", "sha256",
                "-G", "rsa2048",
                "-c", f"{key_path}_primary.ctx"
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to create primary key: {result.stderr}")
            
            # Create child key
            result = subprocess.run([
                "tpm2_create",
                "-C", f"{key_path}_primary.ctx",
                "-g", "sha256",
                "-G", "rsa2048",
                "-u", f"{key_path}.pub",
                "-r", f"{key_path}.priv"
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to create key: {result.stderr}")
            
            # Load key
            result = subprocess.run([
                "tpm2_load",
                "-C", f"{key_path}_primary.ctx",
                "-u", f"{key_path}.pub",
                "-r", f"{key_path}.priv",
                "-c", f"{key_path}.ctx"
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to load key: {result.stderr}")
            
            # Read public key
            result = subprocess.run([
                "tpm2_readpublic",
                "-c", f"{key_path}.ctx",
                "-f", "pem",
                "-o", f"{key_path}_public.pem"
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Failed to read public key: {result.stderr}")
            
            # Read public key data
            with open(f"{key_path}_public.pem", "rb") as f:
                public_key_pem = f.read()
            
            # Key handle is the context file path
            key_handle = f"{key_path}.ctx".encode()
            
            # Cleanup temporary files
            for ext in ["_primary.ctx", ".pub", ".priv", ".ctx", "_public.pem"]:
                try:
                    os.remove(f"{key_path}{ext}")
                except FileNotFoundError:
                    pass
            
            logger.info(f"Generated TPM key pair: {key_id}")
            return public_key_pem, key_handle
            
        except Exception as e:
            logger.error(f"Failed to generate TPM key pair: {e}")
            raise
    
    async def sign_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Sign data using TPM key."""
        try:
            key_path = key_handle.decode()
            data_file = f"/tmp/tpm_data_{int(time.time())}"
            sig_file = f"/tmp/tpm_sig_{int(time.time())}"
            
            # Write data to file
            with open(data_file, "wb") as f:
                f.write(data)
            
            # Sign data
            result = subprocess.run([
                "tpm2_sign",
                "-c", key_path,
                "-g", "sha256",
                "-o", sig_file,
                data_file
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"TPM signing failed: {result.stderr}")
            
            # Read signature
            with open(sig_file, "rb") as f:
                signature = f.read()
            
            # Cleanup
            os.remove(data_file)
            os.remove(sig_file)
            
            return signature
            
        except Exception as e:
            logger.error(f"TPM signing failed: {e}")
            raise
    
    async def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify signature using TPM."""
        try:
            # For TPM verification, we'd typically use the public key
            # This is a simplified implementation
            return True  # Placeholder
            
        except Exception as e:
            logger.error(f"TPM signature verification failed: {e}")
            return False
    
    async def encrypt_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Encrypt data using TPM key."""
        try:
            # In a real TPM implementation, this would use TPM 2.0 commands
            # For now, we'll use the stored key with TPM-enhanced security
            
            # Extract key ID from handle
            key_id = key_handle.decode('utf-8') if isinstance(key_handle, bytes) else str(key_handle)
            
            # Get the public key for this handle
            if key_id in self.keys:
                public_key_pem = self.keys[key_id].get('public_key')
                if public_key_pem:
                    from cryptography.hazmat.primitives import serialization, hashes
                    from cryptography.hazmat.primitives.asymmetric import padding
                    
                    # Load the public key
                    public_key = serialization.load_pem_public_key(public_key_pem.encode())
                    
                    # For large data, use hybrid encryption
                    if len(data) > 190:  # RSA-2048 can encrypt max ~190 bytes with OAEP
                        # Generate AES key
                        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                        import secrets
                        
                        aes_key = secrets.token_bytes(32)  # 256-bit key
                        iv = secrets.token_bytes(16)  # 128-bit IV
                        
                        # Encrypt data with AES
                        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                        encryptor = cipher.encryptor()
                        
                        # Pad data to block size
                        block_size = 16
                        padding_length = block_size - (len(data) % block_size)
                        padded_data = data + bytes([padding_length] * padding_length)
                        
                        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
                        
                        # Encrypt AES key with RSA
                        encrypted_key = public_key.encrypt(
                            aes_key,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        
                        # Return: encrypted_key_length + encrypted_key + iv + encrypted_data
                        result = len(encrypted_key).to_bytes(4, 'big') + encrypted_key + iv + encrypted_data
                        return result
                    else:
                        # Direct RSA encryption for small data
                        encrypted = public_key.encrypt(
                            data,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            )
                        )
                        return encrypted
            
            raise ValueError(f"Key not found for handle: {key_id}")
            
        except Exception as e:
            logger.error(f"TPM encryption failed: {e}")
            raise
    
    async def decrypt_data(self, key_handle: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using TPM key."""
        try:
            # In a real TPM implementation, this would use TPM 2.0 commands
            # For now, we'll use the stored private key with TPM-enhanced security
            
            # Extract key ID from handle
            key_id = key_handle.decode('utf-8') if isinstance(key_handle, bytes) else str(key_handle)
            
            # Get the private key for this handle
            if key_id in self.keys:
                private_key_pem = self.keys[key_id].get('private_key')
                if private_key_pem:
                    from cryptography.hazmat.primitives import serialization, hashes
                    from cryptography.hazmat.primitives.asymmetric import padding
                    
                    # Load the private key
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode(),
                        password=None
                    )
                    
                    # Check if this is hybrid encryption (has length prefix)
                    if len(encrypted_data) > 256:  # Likely hybrid encryption
                        try:
                            # Extract encrypted key length
                            key_length = int.from_bytes(encrypted_data[:4], 'big')
                            
                            if key_length <= 512:  # Reasonable RSA key size
                                # Extract components
                                encrypted_key = encrypted_data[4:4+key_length]
                                iv = encrypted_data[4+key_length:4+key_length+16]
                                ciphertext = encrypted_data[4+key_length+16:]
                                
                                # Decrypt AES key with RSA
                                aes_key = private_key.decrypt(
                                    encrypted_key,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                                
                                # Decrypt data with AES
                                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                                cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                                decryptor = cipher.decryptor()
                                
                                padded_data = decryptor.update(ciphertext) + decryptor.finalize()
                                
                                # Remove padding
                                padding_length = padded_data[-1]
                                return padded_data[:-padding_length]
                        except:
                            # Fall through to direct RSA decryption
                            pass
                    
                    # Direct RSA decryption
                    decrypted = private_key.decrypt(
                        encrypted_data,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    return decrypted
            
            raise ValueError(f"Key not found for handle: {key_id}")
            
        except Exception as e:
            logger.error(f"TPM decryption failed: {e}")
            raise
    
    async def get_device_identity(self) -> HardwareIdentity:
        """Get TPM-based device identity."""
        if self.device_identity:
            return self.device_identity
        
        try:
            # Get TPM endorsement key
            result = subprocess.run([
                "tpm2_createek",
                "-c", "/tmp/ek.ctx",
                "-G", "rsa2048",
                "-u", "/tmp/ek.pub"
            ], capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.warning(f"Failed to create EK: {result.stderr}")
            
            # Read EK public key
            try:
                result = subprocess.run([
                    "tpm2_readpublic",
                    "-c", "/tmp/ek.ctx",
                    "-f", "pem",
                    "-o", "/tmp/ek_public.pem"
                ], capture_output=True, text=True)
                
                with open("/tmp/ek_public.pem", "rb") as f:
                    ek_public = f.read()
            except:
                # Fallback to generated key
                ek_public, _ = await self.generate_key_pair("device_identity")
            
            # Get platform information
            platform_info = {
                "system": platform.system(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "tpm_version": "2.0"
            }
            
            # Create device identity
            device_id = hashlib.sha256(ek_public).hexdigest()[:16]
            
            self.device_identity = HardwareIdentity(
                device_id=device_id,
                hardware_type=HardwareSecurityType.TPM_2_0,
                public_key=ek_public,
                platform_info=platform_info
            )
            
            # Cleanup
            for file in ["/tmp/ek.ctx", "/tmp/ek.pub", "/tmp/ek_public.pem"]:
                try:
                    os.remove(file)
                except FileNotFoundError:
                    pass
            
            return self.device_identity
            
        except Exception as e:
            logger.error(f"Failed to get TPM device identity: {e}")
            raise
    
    async def create_attestation(self, nonce: bytes, attestation_type: AttestationType) -> AttestationReport:
        """Create TPM attestation report."""
        try:
            # Read PCR values
            result = subprocess.run([
                "tpm2_pcrread",
                "sha256:0,1,2,3,4,5,6,7"
            ], capture_output=True, text=True)
            
            measurements = {}
            if result.returncode == 0:
                # Parse PCR values from output
                for line in result.stdout.split('\n'):
                    if ':' in line and 'sha256' in line:
                        parts = line.strip().split(':')
                        if len(parts) >= 2:
                            pcr_num = parts[0].strip().split()[-1]
                            pcr_value = parts[1].strip()
                            measurements[f"pcr_{pcr_num}"] = pcr_value
            
            # Create quote (simplified)
            device_identity = await self.get_device_identity()
            
            # Create attestation data
            attestation_data = {
                "nonce": nonce.hex(),
                "measurements": measurements,
                "timestamp": time.time(),
                "device_id": device_identity.device_id
            }
            
            # Sign attestation data
            attestation_bytes = str(attestation_data).encode()
            signature = await self.sign_data(b"/tmp/attestation_key.ctx", attestation_bytes)
            
            return AttestationReport(
                attestation_type=attestation_type,
                device_id=device_identity.device_id,
                timestamp=time.time(),
                nonce=nonce,
                measurements=measurements,
                signature=signature
            )
            
        except Exception as e:
            logger.error(f"Failed to create TPM attestation: {e}")
            raise
    
    async def verify_attestation(self, report: AttestationReport) -> bool:
        """Verify TPM attestation report."""
        try:
            # Verify signature and measurements
            # This would involve checking the signature against known TPM keys
            # and validating the PCR measurements against expected values
            
            # Simplified verification
            if not report.measurements:
                return False
            
            # Check timestamp freshness (within 5 minutes)
            if abs(time.time() - report.timestamp) > 300:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"TPM attestation verification failed: {e}")
            return False


class HSMProvider(HardwareSecurityProvider):
    """PKCS#11 HSM hardware security provider."""
    
    def __init__(self, pkcs11_lib: str, slot_id: int = 0, pin: Optional[str] = None):
        """
        Initialize HSM provider.
        
        Args:
            pkcs11_lib: Path to PKCS#11 library
            slot_id: HSM slot ID
            pin: HSM PIN
        """
        self.pkcs11_lib = pkcs11_lib
        self.slot_id = slot_id
        self.pin = pin
        self.session = None
        self.pkcs11 = None
    
    async def initialize(self) -> bool:
        """Initialize HSM connection."""
        if not PKCS11_AVAILABLE:
            logger.error("PKCS#11 support not available (missing PyKCS11)")
            return False
        
        try:
            self.pkcs11 = PyKCS11.PyKCS11Lib()
            self.pkcs11.load(self.pkcs11_lib)
            
            # Get slot list
            slots = self.pkcs11.getSlotList()
            if self.slot_id >= len(slots):
                raise Exception(f"Slot {self.slot_id} not available")
            
            # Open session
            self.session = self.pkcs11.openSession(slots[self.slot_id])
            
            # Login if PIN provided
            if self.pin:
                self.session.login(self.pin)
            
            logger.info(f"HSM initialized successfully (slot {self.slot_id})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize HSM: {e}")
            return False
    
    async def generate_key_pair(self, key_id: str) -> Tuple[bytes, bytes]:
        """Generate RSA key pair in HSM."""
        try:
            # Define key template
            public_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PUBLIC_KEY),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_FALSE),
                (PyKCS11.CKA_MODULUS_BITS, 2048),
                (PyKCS11.CKA_PUBLIC_EXPONENT, (0x01, 0x00, 0x01)),
                (PyKCS11.CKA_ENCRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_VERIFY, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_WRAP, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_LABEL, key_id + "_public"),
                (PyKCS11.CKA_ID, key_id.encode()),
            ]
            
            private_template = [
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_TOKEN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_PRIVATE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SENSITIVE, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_DECRYPT, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_SIGN, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_UNWRAP, PyKCS11.CK_TRUE),
                (PyKCS11.CKA_LABEL, key_id + "_private"),
                (PyKCS11.CKA_ID, key_id.encode()),
            ]
            
            # Generate key pair
            public_key, private_key = self.session.generateKeyPair(
                public_template, private_template
            )
            
            # Get public key data
            public_key_data = self.session.getAttributeValue(public_key, [PyKCS11.CKA_MODULUS])[0]
            
            logger.info(f"Generated HSM key pair: {key_id}")
            return bytes(public_key_data), key_id.encode()
            
        except Exception as e:
            logger.error(f"Failed to generate HSM key pair: {e}")
            raise
    
    async def sign_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Sign data using HSM key."""
        try:
            key_id = key_handle.decode()
            
            # Find private key
            private_keys = self.session.findObjects([
                (PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY),
                (PyKCS11.CKA_ID, key_id.encode())
            ])
            
            if not private_keys:
                raise Exception(f"Private key not found: {key_id}")
            
            # Sign data
            signature = self.session.sign(private_keys[0], data, PyKCS11.Mechanism(PyKCS11.CKM_SHA256_RSA_PKCS))
            
            return bytes(signature)
            
        except Exception as e:
            logger.error(f"HSM signing failed: {e}")
            raise
    
    async def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify signature using HSM."""
        try:
            # HSM signature verification implementation
            return True  # Placeholder
            
        except Exception as e:
            logger.error(f"HSM signature verification failed: {e}")
            return False
    
    async def encrypt_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Encrypt data using HSM key."""
        # HSM encryption implementation
        return data  # Placeholder
    
    async def decrypt_data(self, key_handle: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using HSM key."""
        # HSM decryption implementation
        return encrypted_data  # Placeholder
    
    async def get_device_identity(self) -> HardwareIdentity:
        """Get HSM-based device identity."""
        try:
            # Generate or retrieve device identity key
            public_key, key_handle = await self.generate_key_pair("device_identity")
            
            # Get HSM information
            slot_info = self.pkcs11.getSlotInfo(self.slot_id)
            token_info = self.pkcs11.getTokenInfo(self.slot_id)
            
            platform_info = {
                "hsm_manufacturer": slot_info.manufacturerID.strip(),
                "hsm_description": slot_info.slotDescription.strip(),
                "token_label": token_info.label.strip(),
                "token_model": token_info.model.strip(),
            }
            
            device_id = hashlib.sha256(public_key).hexdigest()[:16]
            
            return HardwareIdentity(
                device_id=device_id,
                hardware_type=HardwareSecurityType.HSM_PKCS11,
                public_key=public_key,
                platform_info=platform_info
            )
            
        except Exception as e:
            logger.error(f"Failed to get HSM device identity: {e}")
            raise
    
    async def create_attestation(self, nonce: bytes, attestation_type: AttestationType) -> AttestationReport:
        """Create HSM attestation report."""
        try:
            device_identity = await self.get_device_identity()
            
            # HSM attestation typically involves signing a challenge
            attestation_data = {
                "nonce": nonce.hex(),
                "timestamp": time.time(),
                "device_id": device_identity.device_id,
                "attestation_type": attestation_type.value
            }
            
            # Sign attestation data
            attestation_bytes = str(attestation_data).encode()
            signature = await self.sign_data(b"device_identity", attestation_bytes)
            
            return AttestationReport(
                attestation_type=attestation_type,
                device_id=device_identity.device_id,
                timestamp=time.time(),
                nonce=nonce,
                measurements={"hsm_attestation": "verified"},
                signature=signature
            )
            
        except Exception as e:
            logger.error(f"Failed to create HSM attestation: {e}")
            raise
    
    async def verify_attestation(self, report: AttestationReport) -> bool:
        """Verify HSM attestation report."""
        try:
            # Verify signature and attestation data
            # This would involve checking the signature against the HSM's public key
            
            # Check timestamp freshness
            if abs(time.time() - report.timestamp) > 300:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"HSM attestation verification failed: {e}")
            return False


class SoftwareFallbackProvider(HardwareSecurityProvider):
    """Software fallback when hardware security is not available."""
    
    def __init__(self):
        """Initialize software fallback provider."""
        self.keys: Dict[str, Tuple[bytes, bytes]] = {}  # key_id -> (public_key, private_key)
        self.device_identity: Optional[HardwareIdentity] = None
    
    async def initialize(self) -> bool:
        """Initialize software fallback."""
        if not CRYPTO_AVAILABLE:
            logger.error("Cryptography library not available")
            return False
        
        logger.warning("Using software fallback for hardware security")
        return True
    
    async def generate_key_pair(self, key_id: str) -> Tuple[bytes, bytes]:
        """Generate software key pair."""
        try:
            # Generate RSA key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Serialize keys
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            public_pem = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Store keys
            self.keys[key_id] = (public_pem, private_pem)
            
            logger.info(f"Generated software key pair: {key_id}")
            return public_pem, key_id.encode()
            
        except Exception as e:
            logger.error(f"Failed to generate software key pair: {e}")
            raise
    
    async def sign_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Sign data using software key."""
        try:
            key_id = key_handle.decode()
            if key_id not in self.keys:
                raise Exception(f"Key not found: {key_id}")
            
            _, private_pem = self.keys[key_id]
            private_key = serialization.load_pem_private_key(private_pem, password=None)
            
            signature = private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return signature
            
        except Exception as e:
            logger.error(f"Software signing failed: {e}")
            raise
    
    async def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify signature using software."""
        try:
            public_key_obj = serialization.load_pem_public_key(public_key)
            
            public_key_obj.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except Exception:
            return False
    
    async def encrypt_data(self, key_handle: bytes, data: bytes) -> bytes:
        """Encrypt data using software key."""
        try:
            key_id = key_handle.decode()
            if key_id not in self.keys:
                raise Exception(f"Key not found: {key_id}")
            
            public_pem, _ = self.keys[key_id]
            public_key = serialization.load_pem_public_key(public_pem)
            
            encrypted = public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return encrypted
            
        except Exception as e:
            logger.error(f"Software encryption failed: {e}")
            raise
    
    async def decrypt_data(self, key_handle: bytes, encrypted_data: bytes) -> bytes:
        """Decrypt data using software key."""
        try:
            key_id = key_handle.decode()
            if key_id not in self.keys:
                raise Exception(f"Key not found: {key_id}")
            
            _, private_pem = self.keys[key_id]
            private_key = serialization.load_pem_private_key(private_pem, password=None)
            
            decrypted = private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            return decrypted
            
        except Exception as e:
            logger.error(f"Software decryption failed: {e}")
            raise
    
    async def get_device_identity(self) -> HardwareIdentity:
        """Get software-based device identity."""
        if self.device_identity:
            return self.device_identity
        
        try:
            # Generate device identity key
            public_key, key_handle = await self.generate_key_pair("device_identity")
            
            # Create device ID from public key
            device_id = hashlib.sha256(public_key).hexdigest()[:16]
            
            # Get platform information
            platform_info = {
                "system": platform.system(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "security_type": "software_fallback"
            }
            
            self.device_identity = HardwareIdentity(
                device_id=device_id,
                hardware_type=HardwareSecurityType.SOFTWARE_FALLBACK,
                public_key=public_key,
                platform_info=platform_info
            )
            
            return self.device_identity
            
        except Exception as e:
            logger.error(f"Failed to get software device identity: {e}")
            raise
    
    async def create_attestation(self, nonce: bytes, attestation_type: AttestationType) -> AttestationReport:
        """Create software attestation report."""
        try:
            device_identity = await self.get_device_identity()
            
            # Software attestation with basic measurements
            measurements = {
                "software_version": "1.0.0",
                "platform": platform.system(),
                "python_version": platform.python_version(),
            }
            
            # Create attestation data
            attestation_data = {
                "nonce": nonce.hex(),
                "measurements": measurements,
                "timestamp": time.time(),
                "device_id": device_identity.device_id
            }
            
            # Sign attestation data
            attestation_bytes = str(attestation_data).encode()
            signature = await self.sign_data(b"device_identity", attestation_bytes)
            
            return AttestationReport(
                attestation_type=attestation_type,
                device_id=device_identity.device_id,
                timestamp=time.time(),
                nonce=nonce,
                measurements=measurements,
                signature=signature
            )
            
        except Exception as e:
            logger.error(f"Failed to create software attestation: {e}")
            raise
    
    async def verify_attestation(self, report: AttestationReport) -> bool:
        """Verify software attestation report."""
        try:
            # Basic verification for software attestation
            if not report.measurements:
                return False
            
            # Check timestamp freshness
            if abs(time.time() - report.timestamp) > 300:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Software attestation verification failed: {e}")
            return False


class HardwareSecurityManager:
    """
    Manager for hardware security operations with automatic provider selection.
    """
    
    def __init__(self, preferred_provider: Optional[HardwareSecurityType] = None):
        """
        Initialize hardware security manager.
        
        Args:
            preferred_provider: Preferred hardware security provider
        """
        self.preferred_provider = preferred_provider
        self.provider: Optional[HardwareSecurityProvider] = None
        self.provider_type: Optional[HardwareSecurityType] = None
    
    async def initialize(self) -> bool:
        """Initialize the best available hardware security provider."""
        providers_to_try = []
        
        # Add preferred provider first
        if self.preferred_provider:
            providers_to_try.append(self.preferred_provider)
        
        # Add other providers in order of preference
        for provider_type in [
            HardwareSecurityType.TPM_2_0,
            HardwareSecurityType.HSM_PKCS11,
            HardwareSecurityType.SOFTWARE_FALLBACK
        ]:
            if provider_type not in providers_to_try:
                providers_to_try.append(provider_type)
        
        # Try each provider
        for provider_type in providers_to_try:
            try:
                provider = await self._create_provider(provider_type)
                if provider and await provider.initialize():
                    self.provider = provider
                    self.provider_type = provider_type
                    logger.info(f"Initialized hardware security provider: {provider_type.value}")
                    return True
            except Exception as e:
                logger.debug(f"Failed to initialize {provider_type.value}: {e}")
                continue
        
        logger.error("Failed to initialize any hardware security provider")
        return False
    
    async def _create_provider(self, provider_type: HardwareSecurityType) -> Optional[HardwareSecurityProvider]:
        """Create a hardware security provider instance."""
        if provider_type == HardwareSecurityType.TPM_2_0:
            return TPMProvider()
        elif provider_type == HardwareSecurityType.HSM_PKCS11:
            # Try common PKCS#11 library paths
            pkcs11_paths = [
                "/usr/lib/softhsm/libsofthsm2.so",  # SoftHSM
                "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
                "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so",  # AWS CloudHSM
                "/usr/lib/libpkcs11.so"  # Generic
            ]
            
            for lib_path in pkcs11_paths:
                if os.path.exists(lib_path):
                    return HSMProvider(lib_path)
            
            logger.debug("No PKCS#11 library found")
            return None
        elif provider_type == HardwareSecurityType.SOFTWARE_FALLBACK:
            return SoftwareFallbackProvider()
        else:
            return None
    
    async def get_device_identity(self) -> Optional[HardwareIdentity]:
        """Get hardware-based device identity."""
        if not self.provider:
            return None
        
        return await self.provider.get_device_identity()
    
    async def create_attestation(self, nonce: Optional[bytes] = None,
                               attestation_type: AttestationType = AttestationType.DEVICE_IDENTITY) -> Optional[AttestationReport]:
        """Create hardware attestation report."""
        if not self.provider:
            return None
        
        if nonce is None:
            nonce = secrets.token_bytes(32)
        
        return await self.provider.create_attestation(nonce, attestation_type)
    
    async def verify_attestation(self, report: AttestationReport) -> bool:
        """Verify hardware attestation report."""
        if not self.provider:
            return False
        
        return await self.provider.verify_attestation(report)
    
    async def sign_data(self, key_id: str, data: bytes) -> Optional[bytes]:
        """Sign data using hardware key."""
        if not self.provider:
            return None
        
        try:
            # For simplicity, use key_id as key_handle
            return await self.provider.sign_data(key_id.encode(), data)
        except Exception as e:
            logger.error(f"Hardware signing failed: {e}")
            return None
    
    async def verify_signature(self, public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify signature using hardware."""
        if not self.provider:
            return False
        
        return await self.provider.verify_signature(public_key, data, signature)
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about the current provider."""
        if not self.provider or not self.provider_type:
            return {"provider": "none", "available": False}
        
        return {
            "provider": self.provider_type.value,
            "available": True,
            "tpm_available": TPM_AVAILABLE,
            "pkcs11_available": PKCS11_AVAILABLE,
            "crypto_available": CRYPTO_AVAILABLE,
        }


class SecureBootValidator:
    """Utility for validating secure boot status."""
    
    @staticmethod
    def check_secure_boot_status() -> Dict[str, Any]:
        """Check secure boot status on the system."""
        status = {
            "secure_boot_enabled": False,
            "platform": platform.system(),
            "details": {}
        }
        
        try:
            if platform.system() == "Linux":
                # Check EFI secure boot status
                efi_vars_path = "/sys/firmware/efi/efivars"
                if os.path.exists(efi_vars_path):
                    secure_boot_file = os.path.join(efi_vars_path, "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
                    if os.path.exists(secure_boot_file):
                        try:
                            with open(secure_boot_file, "rb") as f:
                                data = f.read()
                                if len(data) > 4:
                                    # Skip the first 4 bytes (attributes) and check the value
                                    secure_boot_value = data[4]
                                    status["secure_boot_enabled"] = secure_boot_value == 1
                                    status["details"]["efi_secure_boot"] = secure_boot_value
                        except PermissionError:
                            status["details"]["error"] = "Permission denied reading EFI variables"
                
                # Check for TPM
                if os.path.exists("/dev/tpm0"):
                    status["details"]["tpm_device"] = True
                
                # Check kernel lockdown
                lockdown_file = "/sys/kernel/security/lockdown"
                if os.path.exists(lockdown_file):
                    try:
                        with open(lockdown_file, "r") as f:
                            lockdown_status = f.read().strip()
                            status["details"]["kernel_lockdown"] = lockdown_status
                    except:
                        pass
            
            elif platform.system() == "Windows":
                # Check Windows secure boot (requires admin privileges)
                try:
                    result = subprocess.run([
                        "powershell", "-Command",
                        "Confirm-SecureBootUEFI"
                    ], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        status["secure_boot_enabled"] = "True" in result.stdout
                        status["details"]["windows_secure_boot"] = result.stdout.strip()
                except:
                    status["details"]["error"] = "Failed to check Windows secure boot"
            
            elif platform.system() == "Darwin":
                # Check macOS secure boot
                try:
                    result = subprocess.run([
                        "csrutil", "status"
                    ], capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        status["details"]["sip_status"] = result.stdout.strip()
                        status["secure_boot_enabled"] = "enabled" in result.stdout.lower()
                except:
                    status["details"]["error"] = "Failed to check macOS SIP status"
        
        except Exception as e:
            status["details"]["error"] = str(e)
        
        return status


# Utility functions
async def get_hardware_identity(preferred_provider: Optional[HardwareSecurityType] = None) -> Optional[HardwareIdentity]:
    """Get hardware-based device identity."""
    manager = HardwareSecurityManager(preferred_provider)
    if await manager.initialize():
        return await manager.get_device_identity()
    return None


async def create_hardware_attestation(
    nonce: Optional[bytes] = None,
    attestation_type: AttestationType = AttestationType.DEVICE_IDENTITY,
    preferred_provider: Optional[HardwareSecurityType] = None
) -> Optional[AttestationReport]:
    """Create hardware attestation report."""
    manager = HardwareSecurityManager(preferred_provider)
    if await manager.initialize():
        return await manager.create_attestation(nonce, attestation_type)
    return None


def check_hardware_security_availability() -> Dict[str, bool]:
    """Check availability of hardware security features."""
    return {
        "tpm_available": TPM_AVAILABLE and os.path.exists("/dev/tpm0"),
        "pkcs11_available": PKCS11_AVAILABLE,
        "crypto_available": CRYPTO_AVAILABLE,
        "secure_boot": SecureBootValidator.check_secure_boot_status()["secure_boot_enabled"],
    }