"""
Trust provider for ECPS UV SDK.

This module provides security mechanisms for the ECPS protocol stack,
including authentication, authorization, and encryption.
"""

import asyncio
import base64
import enum
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

import jwt
import cryptography.hazmat.primitives.asymmetric.padding as padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
)
from cryptography.x509 import load_pem_x509_certificate

logger = logging.getLogger("ecps_uv.trust")


class TrustLevel(enum.IntEnum):
    """Trust level required for communication."""
    NONE = 0
    ENCRYPTION = 1
    AUTHENTICATED = 2
    AUTHORIZED = 3
    AUDITED = 4


class TrustMechanism(enum.IntEnum):
    """Security mechanism used."""
    TLS = 0
    JWT = 1
    OAUTH = 2
    MTLS = 3


@dataclass
class Principal:
    """An authenticated entity."""
    id: str
    name: str = ""
    roles: List[str] = field(default_factory=list)
    permissions: Dict[str, bool] = field(default_factory=dict)
    attributes: Dict[str, str] = field(default_factory=dict)
    expires_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        """Check if the principal has expired."""
        if self.expires_at is None:
            return False
        return datetime.now() > self.expires_at


class Authorizer:
    """Interface for authorization decisions."""

    async def authorize(
        self, 
        principal: Principal, 
        action: str, 
        resource: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a principal has permission for an action on a resource.
        
        Args:
            principal: The authenticated principal
            action: The action to perform
            resource: The resource to act upon
            
        Returns:
            (authorized, reason): Whether the action is authorized and reason if not
        """
        raise NotImplementedError("Subclasses must implement authorize")


class RBACAuthorizer(Authorizer):
    """Role-based access control implementation."""

    def __init__(self):
        """Initialize the RBAC authorizer."""
        self.role_permissions: Dict[str, Dict[str, bool]] = {}

    def add_role_permission(self, role: str, action: str, resource: str) -> None:
        """
        Add a permission for a role.
        
        Args:
            role: The role name
            action: The action to permit
            resource: The resource to permit action on
        """
        key = f"{action}:{resource}"
        
        if role not in self.role_permissions:
            self.role_permissions[role] = {}
            
        self.role_permissions[role][key] = True
        logger.debug(f"Added permission {key} to role {role}")

    async def authorize(
        self, 
        principal: Principal, 
        action: str, 
        resource: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a principal has permission for an action on a resource.
        
        Args:
            principal: The authenticated principal
            action: The action to perform
            resource: The resource to act upon
            
        Returns:
            (authorized, reason): Whether the action is authorized and reason if not
        """
        if principal is None:
            return False, "Principal cannot be None"
        
        # Check if the principal has expired
        if principal.is_expired():
            return False, "Principal has expired"
        
        # Direct permission check
        perm_key = f"{action}:{resource}"
        if perm_key in principal.permissions and principal.permissions[perm_key]:
            return True, None
        
        # Role-based permission check
        for role in principal.roles:
            if role in self.role_permissions:
                perms = self.role_permissions[role]
                
                # Exact permission match
                if perm_key in perms and perms[perm_key]:
                    return True, None
                
                # Wildcard resource match
                wildcard_key = f"{action}:*"
                if wildcard_key in perms and perms[wildcard_key]:
                    return True, None
        
        return False, f"Principal {principal.id} does not have permission for {action} on {resource}"


class TrustProvider:
    """Provides security services for ECPS."""

    def __init__(
        self,
        trust_level: TrustLevel = TrustLevel.NONE,
        mechanisms: Optional[List[TrustMechanism]] = None,
        private_key_path: Optional[str] = None,
        public_key_path: Optional[str] = None,
        jwt_secret: Optional[str] = None,
        authorizer: Optional[Authorizer] = None,
    ):
        """
        Initialize the trust provider.
        
        Args:
            trust_level: Level of trust required
            mechanisms: Security mechanisms to use
            private_key_path: Path to private key file (PEM)
            public_key_path: Path to public key file (PEM)
            jwt_secret: Secret for JWT signing
            authorizer: Authorizer for authorization decisions
        """
        self.trust_level = trust_level
        self.mechanisms = mechanisms or []
        self.private_key = None
        self.public_key = None
        self.jwt_secret = jwt_secret.encode("utf-8") if jwt_secret else None
        self.authorizer = authorizer or RBACAuthorizer()
        self.principals: Dict[str, Principal] = {}
        self.certificates = []
        
        # Load keys if provided
        if private_key_path:
            self._load_private_key(private_key_path)
            
        if public_key_path:
            self._load_public_key(public_key_path)
            
        # Generate keys if needed for higher trust levels
        if trust_level > TrustLevel.ENCRYPTION and not self.private_key:
            self._generate_keys()
            
        # Generate JWT secret if needed
        if (trust_level > TrustLevel.ENCRYPTION and 
            TrustMechanism.JWT in self.mechanisms and 
            not self.jwt_secret):
            self._generate_jwt_secret()

    def _load_private_key(self, path: str) -> None:
        """
        Load a private key from a PEM file.
        
        Args:
            path: Path to the private key file
        """
        try:
            with open(path, "rb") as f:
                key_data = f.read()
                
            self.private_key = load_pem_private_key(
                key_data,
                password=None,
            )
            logger.info(f"Loaded private key from {path}")
        except Exception as e:
            logger.error(f"Failed to load private key: {e}")
            raise

    def _load_public_key(self, path: str) -> None:
        """
        Load a public key from a PEM file.
        
        Args:
            path: Path to the public key file
        """
        try:
            with open(path, "rb") as f:
                key_data = f.read()
                
            self.public_key = load_pem_public_key(key_data)
            logger.info(f"Loaded public key from {path}")
        except Exception as e:
            logger.error(f"Failed to load public key: {e}")
            raise

    def _generate_keys(self) -> None:
        """Generate a new RSA key pair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        self.public_key = self.private_key.public_key()
        logger.info("Generated temporary RSA key pair")

    def _generate_jwt_secret(self) -> None:
        """Generate a random JWT secret."""
        self.jwt_secret = os.urandom(32)
        logger.info("Generated temporary JWT secret")

    def add_principal(self, principal: Principal) -> None:
        """
        Add a principal.
        
        Args:
            principal: The principal to add
        """
        self.principals[principal.id] = principal
        logger.debug(f"Added principal: {principal.id}")

    def get_principal(self, id: str) -> Optional[Principal]:
        """
        Get a principal by ID.
        
        Args:
            id: The principal ID
            
        Returns:
            The principal or None if not found
        """
        return self.principals.get(id)

    def create_jwt(
        self, 
        principal: Principal, 
        expires_in: Optional[timedelta] = None
    ) -> str:
        """
        Create a JSON Web Token for a principal.
        
        Args:
            principal: The principal to create a token for
            expires_in: Token expiration time
            
        Returns:
            JWT token string
        """
        if not self.jwt_secret and not self.private_key:
            raise ValueError("No JWT secret or private key available")
        
        # Set expiration time if not already set
        expires_at = principal.expires_at
        if expires_at is None and expires_in:
            expires_at = datetime.now() + expires_in
            
        # Create claims
        claims = {
            "sub": principal.id,
            "name": principal.name,
        }
        
        if expires_at:
            claims["exp"] = int(expires_at.timestamp())
            
        # Add roles
        if principal.roles:
            claims["roles"] = ",".join(principal.roles)
            
        # Add custom attributes
        for k, v in principal.attributes.items():
            claims[k] = v
            
        # Sign with JWT secret if available
        if self.jwt_secret:
            return jwt.encode(claims, self.jwt_secret, algorithm="HS256")
        
        # Otherwise use private key
        return jwt.encode(claims, self.private_key, algorithm="RS256")

    def validate_jwt(self, token: str) -> Optional[Principal]:
        """
        Validate a JWT and extract the principal.
        
        Args:
            token: The JWT token
            
        Returns:
            The authenticated principal or None if invalid
        """
        try:
            # Try to decode with JWT secret first
            if self.jwt_secret:
                try:
                    payload = jwt.decode(
                        token, 
                        self.jwt_secret, 
                        algorithms=["HS256"],
                    )
                except jwt.exceptions.InvalidSignatureError:
                    # If that fails, try with public key
                    if self.public_key:
                        payload = jwt.decode(
                            token, 
                            self.public_key, 
                            algorithms=["RS256"],
                        )
                    else:
                        raise
            elif self.public_key:
                # Only public key available
                payload = jwt.decode(
                    token, 
                    self.public_key, 
                    algorithms=["RS256"],
                )
            else:
                raise ValueError("No JWT secret or public key available")
                
            # Extract principal information
            principal_id = payload.get("sub")
            if not principal_id:
                logger.error("JWT missing subject claim")
                return None
                
            # Create principal
            principal = Principal(id=principal_id)
            
            # Extract name
            if "name" in payload:
                principal.name = payload["name"]
                
            # Extract roles
            if "roles" in payload:
                principal.roles = payload["roles"].split(",")
                
            # Extract expiration
            if "exp" in payload:
                principal.expires_at = datetime.fromtimestamp(payload["exp"])
                
            # Extract other attributes
            for k, v in payload.items():
                if k not in ["sub", "name", "roles", "exp"] and isinstance(v, str):
                    principal.attributes[k] = v
                    
            return principal
            
        except jwt.exceptions.PyJWTError as e:
            logger.error(f"JWT validation failed: {e}")
            return None

    def sign_message(self, message: bytes) -> bytes:
        """
        Sign a message with the private key.
        
        Args:
            message: The message to sign
            
        Returns:
            The signature
        """
        if not self.private_key:
            raise ValueError("No private key available")
            
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature

    def verify_message(self, message: bytes, signature: bytes) -> bool:
        """
        Verify a message signature.
        
        Args:
            message: The message
            signature: The signature
            
        Returns:
            True if signature is valid
        """
        if not self.public_key:
            raise ValueError("No public key available")
            
        try:
            self.public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False

    async def authenticate(
        self, 
        id: str, 
        credential: Optional[str] = None
    ) -> Optional[Principal]:
        """
        Authenticate a principal using credentials.
        
        Args:
            id: Principal ID
            credential: Authentication credential (e.g., JWT token)
            
        Returns:
            The authenticated principal or None if authentication fails
        """
        # Check if credential is a JWT
        if credential and credential.startswith("Bearer "):
            token = credential.replace("Bearer ", "", 1)
            return self.validate_jwt(token)
            
        # Look up principal
        principal = self.get_principal(id)
        if not principal:
            logger.error(f"Principal not found: {id}")
            return None
            
        # Validate the credential against stored credentials
        # This would typically involve checking against a database or identity provider
        
        # For demonstration, we'll implement a simple credential validation
        # In production, this should integrate with your identity management system
        
        # Check if we have an identity manager to validate credentials
        if hasattr(self, 'identity_manager') and self.identity_manager:
            try:
                # Verify the credential using the identity manager
                is_valid = self.identity_manager.verify_credential(principal.id, credential)
                if not is_valid:
                    logger.warning(f"Invalid credential for principal {principal.id}")
                    return None
            except Exception as e:
                logger.error(f"Error validating credential for principal {principal.id}: {e}")
                return None
        else:
            # Fallback: simple credential check (not recommended for production)
            # This is just for backward compatibility
            logger.warning("No identity manager configured, using fallback credential validation")
            
            # In a real implementation, you would never store plaintext credentials
            # This is just for demonstration purposes
            stored_credential = getattr(principal, '_credential', None)
            if stored_credential != credential:
                logger.warning(f"Credential mismatch for principal {principal.id}")
                return None
        
        # Update last authenticated time
        principal.last_authenticated = datetime.now()
        
        return principal

    async def authorize(
        self, 
        principal: Principal, 
        action: str, 
        resource: str
    ) -> Tuple[bool, Optional[str]]:
        """
        Check if a principal has permission for an action on a resource.
        
        Args:
            principal: The authenticated principal
            action: The action to perform
            resource: The resource to act upon
            
        Returns:
            (authorized, reason): Whether the action is authorized and reason if not
        """
        # Check if authorization is required
        if self.trust_level < TrustLevel.AUTHORIZED:
            return True, None
            
        # Use authorizer if available
        if self.authorizer:
            return await self.authorizer.authorize(principal, action, resource)
            
        # Default deny if no authorizer
        return False, "No authorizer available"

    def encrypt_message(self, message: bytes) -> bytes:
        """
        Encrypt a message with the public key.
        
        Args:
            message: The message to encrypt
            
        Returns:
            The encrypted message
        """
        if not self.public_key:
            raise ValueError("No public key available")
            
        # Note: RSA encryption is limited by key size
        # For large messages, use a hybrid approach with symmetric encryption
        
        # Check if message is too large for direct RSA encryption
        max_rsa_size = (self.public_key.key_size // 8) - 2 * (256 // 8) - 2  # OAEP overhead
        
        if len(message) <= max_rsa_size:
            # Direct RSA encryption for small messages
            ciphertext = self.public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return ciphertext
        else:
            # Hybrid encryption for large messages
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            import secrets
            
            # Generate AES key and IV
            aes_key = secrets.token_bytes(32)  # 256-bit key
            iv = secrets.token_bytes(16)  # 128-bit IV
            
            # Encrypt message with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            # Pad message to block size
            block_size = 16
            padding_length = block_size - (len(message) % block_size)
            padded_message = message + bytes([padding_length] * padding_length)
            
            encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
            
            # Encrypt AES key with RSA
            encrypted_key = self.public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Return: encrypted_key_length + encrypted_key + iv + encrypted_message
            result = len(encrypted_key).to_bytes(4, 'big') + encrypted_key + iv + encrypted_message
            return result

    def decrypt_message(self, ciphertext: bytes) -> bytes:
        """
        Decrypt a message with the private key.
        
        Args:
            ciphertext: The encrypted message
            
        Returns:
            The decrypted message
        """
        if not self.private_key:
            raise ValueError("No private key available")
        
        # Check if this is hybrid encryption (has length prefix)
        max_rsa_size = (self.private_key.key_size // 8)
        
        if len(ciphertext) > max_rsa_size:
            # Hybrid decryption
            try:
                # Extract encrypted key length
                key_length = int.from_bytes(ciphertext[:4], 'big')
                
                if key_length <= max_rsa_size:  # Reasonable RSA key size
                    # Extract components
                    encrypted_key = ciphertext[4:4+key_length]
                    iv = ciphertext[4+key_length:4+key_length+16]
                    encrypted_message = ciphertext[4+key_length+16:]
                    
                    # Decrypt AES key with RSA
                    aes_key = self.private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    
                    # Decrypt message with AES
                    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
                    decryptor = cipher.decryptor()
                    
                    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
                    
                    # Remove padding
                    padding_length = padded_message[-1]
                    return padded_message[:-padding_length]
            except:
                # Fall through to direct RSA decryption
                pass
        
        # Direct RSA decryption
        plaintext = self.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return plaintext

    def secure_transport(self, transport: Any) -> Any:
        """
        Wrap a transport with security features.
        
        Args:
            transport: The transport to secure
            
        Returns:
            Secure transport wrapper
        """
        # Avoid circular imports
        from ecps_uv.trust.secure_transport import SecureTransport
        
        # If no security required, return the original transport
        if self.trust_level == TrustLevel.NONE:
            return transport
            
        # Create a secure transport wrapper
        return SecureTransport(transport, self)