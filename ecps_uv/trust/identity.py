"""
Identity management for ECPS UV Trust Layer.

This module provides identity management capabilities for the ECPS trust layer,
including identity creation, verification, and integration with external
identity providers.
"""

import enum
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple, Union

import jwt

from .trust import Principal


class IdentityType(enum.Enum):
    """Types of identities in the system."""
    USER = "user"
    SERVICE = "service"
    DEVICE = "device"
    ROBOT = "robot"


@dataclass
class Identity:
    """
    Represents an identity in the system.
    
    An identity is a unique entity that can be authenticated and
    associated with a principal for authorization purposes.
    """
    id: str
    name: str
    type: IdentityType
    created_at: datetime = field(default_factory=datetime.now)
    last_authenticated: Optional[datetime] = None
    attributes: Dict[str, str] = field(default_factory=dict)
    enabled: bool = True
    
    @property
    def is_user(self) -> bool:
        """Check if this is a user identity."""
        return self.type == IdentityType.USER
    
    @property
    def is_service(self) -> bool:
        """Check if this is a service identity."""
        return self.type == IdentityType.SERVICE
    
    @property
    def is_device(self) -> bool:
        """Check if this is a device identity."""
        return self.type == IdentityType.DEVICE
    
    @property
    def is_robot(self) -> bool:
        """Check if this is a robot identity."""
        return self.type == IdentityType.ROBOT


class IdentityStore:
    """
    Stores and manages identities.
    
    The identity store provides operations to create, retrieve, update,
    and delete identities, as well as authentication operations.
    """
    
    def __init__(self):
        """Initialize the identity store."""
        self.identities: Dict[str, Identity] = {}
        self.credentials: Dict[str, str] = {}  # Simple credential store (id -> password hash)
        self.identity_principals: Dict[str, str] = {}  # Mapping from identity ID to principal ID
        
    def create_identity(
        self, 
        name: str, 
        type: IdentityType, 
        attributes: Optional[Dict[str, str]] = None,
        id: Optional[str] = None
    ) -> Identity:
        """
        Create a new identity.
        
        Args:
            name: The display name for the identity
            type: The type of identity
            attributes: Optional attributes for the identity
            id: Optional ID (generated if not provided)
            
        Returns:
            The created identity
        """
        identity_id = id or f"{type.value}-{uuid.uuid4()}"
        identity = Identity(
            id=identity_id,
            name=name,
            type=type,
            attributes=attributes or {},
        )
        
        self.identities[identity_id] = identity
        return identity
    
    def get_identity(self, id: str) -> Optional[Identity]:
        """
        Get an identity by ID.
        
        Args:
            id: The identity ID
            
        Returns:
            The identity or None if not found
        """
        return self.identities.get(id)
    
    def update_identity(self, identity: Identity) -> None:
        """
        Update an existing identity.
        
        Args:
            identity: The updated identity
        """
        if identity.id not in self.identities:
            raise ValueError(f"Identity not found: {identity.id}")
            
        self.identities[identity.id] = identity
    
    def delete_identity(self, id: str) -> None:
        """
        Delete an identity.
        
        Args:
            id: The identity ID
        """
        if id in self.identities:
            del self.identities[id]
            
        # Clean up related data
        if id in self.credentials:
            del self.credentials[id]
            
        if id in self.identity_principals:
            del self.identity_principals[id]
    
    def set_credential(self, identity_id: str, credential: str) -> None:
        """
        Set a credential for an identity.
        
        This securely hashes the credential using PBKDF2 with SHA-256.
        
        Args:
            identity_id: The identity ID
            credential: The credential (e.g., password)
        """
        if identity_id not in self.identities:
            raise ValueError(f"Identity not found: {identity_id}")
            
        # Generate a random salt
        salt = secrets.token_bytes(32)
        
        # Hash the credential using PBKDF2 with SHA-256
        hashed_credential = hashlib.pbkdf2_hmac(
            'sha256',
            credential.encode('utf-8'),
            salt,
            100000  # 100,000 iterations
        )
        
        # Store salt + hash
        self.credentials[identity_id] = salt + hashed_credential
    
    def verify_credential(self, identity_id: str, credential: str) -> bool:
        """
        Verify a credential for an identity.
        
        Args:
            identity_id: The identity ID
            credential: The credential to verify
            
        Returns:
            True if credential is valid
        """
        if identity_id not in self.identities:
            return False
            
        stored_credential = self.credentials.get(identity_id)
        if not stored_credential:
            return False
            
        # Extract salt and hash from stored credential
        if len(stored_credential) < 64:  # 32 bytes salt + 32 bytes hash
            return False
            
        salt = stored_credential[:32]
        stored_hash = stored_credential[32:]
        
        # Hash the provided credential with the same salt
        candidate_hash = hashlib.pbkdf2_hmac(
            'sha256',
            credential.encode('utf-8'),
            salt,
            100000  # Same number of iterations
        )
        
        # Use constant-time comparison to prevent timing attacks
        is_valid = hmac.compare_digest(stored_hash, candidate_hash)
        
        # Update last authenticated time if valid
        if is_valid:
            identity = self.identities[identity_id]
            identity.last_authenticated = datetime.now()
            self.identities[identity_id] = identity
            
        return is_valid
    
    def associate_principal(self, identity_id: str, principal_id: str) -> None:
        """
        Associate an identity with a principal.
        
        Args:
            identity_id: The identity ID
            principal_id: The principal ID
        """
        if identity_id not in self.identities:
            raise ValueError(f"Identity not found: {identity_id}")
            
        self.identity_principals[identity_id] = principal_id
    
    def get_principal_id(self, identity_id: str) -> Optional[str]:
        """
        Get the principal ID associated with an identity.
        
        Args:
            identity_id: The identity ID
            
        Returns:
            The associated principal ID or None
        """
        return self.identity_principals.get(identity_id)
    
    def list_identities(
        self, 
        type: Optional[IdentityType] = None
    ) -> List[Identity]:
        """
        List all identities, optionally filtered by type.
        
        Args:
            type: Optional identity type to filter by
            
        Returns:
            List of identities
        """
        if type is None:
            return list(self.identities.values())
            
        return [
            identity for identity in self.identities.values()
            if identity.type == type
        ]


class IdentityProvider:
    """
    Manages identity authentication and integration with external providers.
    
    The identity provider handles authentication flows and can integrate
    with external identity providers like OAuth, OIDC, LDAP, etc.
    """
    
    def __init__(
        self, 
        identity_store: IdentityStore,
        jwt_secret: Optional[str] = None,
    ):
        """
        Initialize the identity provider.
        
        Args:
            identity_store: The identity store to use
            jwt_secret: Secret for JWT token signing
        """
        self.identity_store = identity_store
        self.jwt_secret = jwt_secret.encode("utf-8") if jwt_secret else None
        
    async def authenticate(
        self, 
        identity_id: str, 
        credential: str
    ) -> Optional[Identity]:
        """
        Authenticate an identity using credentials.
        
        Args:
            identity_id: The identity ID
            credential: The credential to verify
            
        Returns:
            The authenticated identity or None if authentication fails
        """
        # Verify the credential
        if not self.identity_store.verify_credential(identity_id, credential):
            return None
            
        # Get the identity
        identity = self.identity_store.get_identity(identity_id)
        if identity is None:
            return None
            
        # Check if the identity is enabled
        if not identity.enabled:
            return None
            
        return identity
    
    def create_identity_token(
        self, 
        identity: Identity, 
        expires_in: Optional[timedelta] = None
    ) -> str:
        """
        Create a JWT token for an identity.
        
        Args:
            identity: The identity to create a token for
            expires_in: Token expiration time
            
        Returns:
            JWT token string
        """
        if not self.jwt_secret:
            raise ValueError("No JWT secret available")
            
        # Set expiration time
        expires_at = None
        if expires_in:
            expires_at = datetime.now() + expires_in
            
        # Create claims
        claims = {
            "sub": identity.id,
            "name": identity.name,
            "type": identity.type.value,
        }
        
        if expires_at:
            claims["exp"] = int(expires_at.timestamp())
            
        # Add custom attributes
        for k, v in identity.attributes.items():
            claims[k] = v
            
        # Sign with JWT secret
        return jwt.encode(claims, self.jwt_secret, algorithm="HS256")
    
    def validate_identity_token(self, token: str) -> Optional[Identity]:
        """
        Validate a JWT token and extract the identity.
        
        Args:
            token: The JWT token
            
        Returns:
            The authenticated identity or None if invalid
        """
        if not self.jwt_secret:
            raise ValueError("No JWT secret available")
            
        try:
            # Decode and verify the token
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=["HS256"],
            )
                
            # Extract identity information
            identity_id = payload.get("sub")
            if not identity_id:
                return None
                
            # Get the stored identity
            identity = self.identity_store.get_identity(identity_id)
            if not identity:
                return None
                
            # Update last authenticated time
            identity.last_authenticated = datetime.now()
            self.identity_store.update_identity(identity)
                
            return identity
                
        except jwt.exceptions.PyJWTError:
            return None
    
    async def identity_to_principal(
        self, 
        identity: Identity
    ) -> Optional[str]:
        """
        Convert an identity to a principal ID.
        
        Args:
            identity: The authenticated identity
            
        Returns:
            The associated principal ID or None
        """
        return self.identity_store.get_principal_id(identity.id)


def create_default_identity_provider() -> Tuple[IdentityStore, IdentityProvider]:
    """
    Create a default identity store and provider with sample identities.
    
    Returns:
        Tuple of (identity_store, identity_provider)
    """
    # Create identity store
    identity_store = IdentityStore()
    
    # Create identity provider
    identity_provider = IdentityProvider(
        identity_store=identity_store,
        jwt_secret="default-identity-jwt-secret",
    )
    
    # Create sample user identity
    user = identity_store.create_identity(
        name="Sample User",
        type=IdentityType.USER,
        attributes={"email": "user@example.com"},
    )
    identity_store.set_credential(user.id, "password123")
    identity_store.associate_principal(user.id, "user1")
    
    # Create sample service identity
    service = identity_store.create_identity(
        name="API Service",
        type=IdentityType.SERVICE,
        attributes={"service_type": "api"},
    )
    identity_store.set_credential(service.id, "service-api-key")
    identity_store.associate_principal(service.id, "service1")
    
    # Create sample device identity
    device = identity_store.create_identity(
        name="IoT Sensor",
        type=IdentityType.DEVICE,
        attributes={"device_type": "sensor", "location": "lab"},
    )
    identity_store.set_credential(device.id, "device-secret")
    identity_store.associate_principal(device.id, "device1")
    
    # Create sample robot identity
    robot = identity_store.create_identity(
        name="Robot Arm",
        type=IdentityType.ROBOT,
        attributes={"model": "UR5", "location": "factory"},
    )
    identity_store.set_credential(robot.id, "robot-token")
    identity_store.associate_principal(robot.id, "robot1")
    
    return identity_store, identity_provider