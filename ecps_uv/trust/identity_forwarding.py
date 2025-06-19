"""
Identity forwarding system for ECPS UV Trust Layer.

This module provides identity forwarding capabilities that allow establishing
identity once and forwarding it through request chains, avoiding the need
to sign every individual request.
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from .identity import Identity, IdentityProvider
from .trust import Principal, TrustLevel, TrustProvider


@dataclass
class IdentityContext:
    """
    Context containing identity information that can be forwarded.
    
    This context is established once during authentication and then
    forwarded through subsequent requests without requiring re-signing.
    """
    # The authenticated identity
    identity: Identity
    # Associated principal ID
    principal_id: str
    # Session ID for this identity context
    session_id: str
    # When this context was established
    established_at: datetime
    # When this context expires
    expires_at: datetime
    # Capabilities granted to this identity
    capabilities: Set[str] = field(default_factory=set)
    # Additional context attributes
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        """Check if this context has expired."""
        return datetime.now() > self.expires_at
    
    @property
    def time_remaining(self) -> timedelta:
        """Get time remaining before expiration."""
        return self.expires_at - datetime.now()
    
    def has_capability(self, capability: str) -> bool:
        """Check if this context has a specific capability."""
        return capability in self.capabilities
    
    def add_capability(self, capability: str) -> None:
        """Add a capability to this context."""
        self.capabilities.add(capability)
    
    def remove_capability(self, capability: str) -> None:
        """Remove a capability from this context."""
        self.capabilities.discard(capability)


@dataclass
class ForwardedRequest:
    """
    A request with forwarded identity context.
    
    Instead of signing each request, we forward the identity context
    that was established during initial authentication.
    """
    # The original request payload
    payload: Any
    # Forwarded identity context
    identity_context: IdentityContext
    # Request ID for tracking
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    # Timestamp when request was created
    timestamp: datetime = field(default_factory=datetime.now)
    # Chain of services this request has passed through
    service_chain: List[str] = field(default_factory=list)
    
    def add_to_chain(self, service_name: str) -> None:
        """Add a service to the forwarding chain."""
        self.service_chain.append(service_name)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for transport."""
        return {
            "payload": self.payload,
            "identity_context": {
                "identity_id": self.identity_context.identity.id,
                "principal_id": self.identity_context.principal_id,
                "session_id": self.identity_context.session_id,
                "established_at": self.identity_context.established_at.isoformat(),
                "expires_at": self.identity_context.expires_at.isoformat(),
                "capabilities": list(self.identity_context.capabilities),
                "attributes": self.identity_context.attributes,
            },
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
            "service_chain": self.service_chain,
        }


class IdentityForwardingManager:
    """
    Manages identity forwarding for ECPS requests.
    
    This manager handles:
    1. Establishing identity contexts during authentication
    2. Forwarding identity contexts through request chains
    3. Validating forwarded contexts at each hop
    4. Managing context lifecycle and expiration
    """
    
    def __init__(
        self,
        identity_provider: IdentityProvider,
        trust_provider: TrustProvider,
        default_session_duration: timedelta = timedelta(hours=8),
    ):
        """
        Initialize the identity forwarding manager.
        
        Args:
            identity_provider: Identity provider for authentication
            trust_provider: Trust provider for authorization
            default_session_duration: Default session duration
        """
        self.identity_provider = identity_provider
        self.trust_provider = trust_provider
        self.default_session_duration = default_session_duration
        
        # Active identity contexts by session ID
        self.active_contexts: Dict[str, IdentityContext] = {}
        
        # Context cleanup task
        self._cleanup_task: Optional[asyncio.Task] = None
        self._start_cleanup_task()
    
    def _start_cleanup_task(self) -> None:
        """Start the context cleanup task."""
        if self._cleanup_task is None or self._cleanup_task.done():
            self._cleanup_task = asyncio.create_task(self._cleanup_expired_contexts())
    
    async def _cleanup_expired_contexts(self) -> None:
        """Periodically clean up expired contexts."""
        while True:
            try:
                # Clean up expired contexts every minute
                await asyncio.sleep(60)
                
                expired_sessions = [
                    session_id for session_id, context in self.active_contexts.items()
                    if context.is_expired
                ]
                
                for session_id in expired_sessions:
                    del self.active_contexts[session_id]
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue cleanup
                print(f"Error during context cleanup: {e}")
    
    async def establish_identity_context(
        self,
        identity_id: str,
        credential: str,
        capabilities: Optional[Set[str]] = None,
        session_duration: Optional[timedelta] = None,
    ) -> Optional[IdentityContext]:
        """
        Establish an identity context through authentication.
        
        This is done once at the beginning of a session, replacing
        the need to sign every individual request.
        
        Args:
            identity_id: Identity to authenticate
            credential: Authentication credential
            capabilities: Capabilities to grant
            session_duration: How long the context should be valid
            
        Returns:
            Established identity context or None if authentication fails
        """
        # Authenticate the identity
        identity = await self.identity_provider.authenticate(identity_id, credential)
        if not identity:
            return None
        
        # Get associated principal
        principal_id = await self.identity_provider.identity_to_principal(identity)
        if not principal_id:
            return None
        
        # Create identity context
        session_id = str(uuid.uuid4())
        duration = session_duration or self.default_session_duration
        
        context = IdentityContext(
            identity=identity,
            principal_id=principal_id,
            session_id=session_id,
            established_at=datetime.now(),
            expires_at=datetime.now() + duration,
            capabilities=capabilities or set(),
        )
        
        # Store active context
        self.active_contexts[session_id] = context
        
        return context
    
    def create_forwarded_request(
        self,
        payload: Any,
        identity_context: IdentityContext,
    ) -> ForwardedRequest:
        """
        Create a request with forwarded identity context.
        
        Args:
            payload: Request payload
            identity_context: Identity context to forward
            
        Returns:
            Forwarded request
        """
        return ForwardedRequest(
            payload=payload,
            identity_context=identity_context,
        )
    
    async def validate_forwarded_request(
        self,
        forwarded_request: ForwardedRequest,
        required_capability: Optional[str] = None,
        service_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate a forwarded request.
        
        Args:
            forwarded_request: The forwarded request to validate
            required_capability: Required capability for this operation
            service_name: Name of the service validating the request
            
        Returns:
            Tuple of (is_valid, error_reason)
        """
        context = forwarded_request.identity_context
        
        # Check if context is expired
        if context.is_expired:
            return False, "Identity context has expired"
        
        # Check if session is still active
        if context.session_id not in self.active_contexts:
            return False, "Identity session is no longer active"
        
        # Verify context matches stored context
        stored_context = self.active_contexts[context.session_id]
        if (stored_context.identity.id != context.identity.id or
            stored_context.principal_id != context.principal_id):
            return False, "Identity context mismatch"
        
        # Check required capability
        if required_capability and not context.has_capability(required_capability):
            return False, f"Missing required capability: {required_capability}"
        
        # Add service to chain if provided
        if service_name:
            forwarded_request.add_to_chain(service_name)
        
        return True, None
    
    async def authorize_forwarded_request(
        self,
        forwarded_request: ForwardedRequest,
        action: str,
        resource: str,
    ) -> Tuple[bool, Optional[str]]:
        """
        Authorize a forwarded request using the trust provider.
        
        Args:
            forwarded_request: The forwarded request
            action: Action being performed
            resource: Resource being accessed
            
        Returns:
            Tuple of (is_authorized, reason)
        """
        context = forwarded_request.identity_context
        
        # Get principal for authorization
        principal = Principal(
            id=context.principal_id,
            name=context.identity.name,
            type=context.identity.type.value,
        )
        
        # Use trust provider for authorization
        return await self.trust_provider.authorize(principal, action, resource)
    
    def refresh_context(
        self,
        session_id: str,
        additional_duration: Optional[timedelta] = None,
    ) -> bool:
        """
        Refresh an identity context to extend its lifetime.
        
        Args:
            session_id: Session ID to refresh
            additional_duration: Additional time to add
            
        Returns:
            True if context was refreshed
        """
        if session_id not in self.active_contexts:
            return False
        
        context = self.active_contexts[session_id]
        duration = additional_duration or self.default_session_duration
        
        # Extend expiration time
        context.expires_at = datetime.now() + duration
        
        return True
    
    def revoke_context(self, session_id: str) -> bool:
        """
        Revoke an identity context.
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if context was revoked
        """
        if session_id in self.active_contexts:
            del self.active_contexts[session_id]
            return True
        return False
    
    def get_active_contexts(self) -> List[IdentityContext]:
        """
        Get all active identity contexts.
        
        Returns:
            List of active contexts
        """
        return [
            context for context in self.active_contexts.values()
            if not context.is_expired
        ]
    
    def get_context_by_session(self, session_id: str) -> Optional[IdentityContext]:
        """
        Get an identity context by session ID.
        
        Args:
            session_id: Session ID
            
        Returns:
            Identity context or None
        """
        context = self.active_contexts.get(session_id)
        if context and not context.is_expired:
            return context
        return None
    
    async def shutdown(self) -> None:
        """Shutdown the identity forwarding manager."""
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Clear all contexts
        self.active_contexts.clear()


def create_default_identity_forwarding_manager(
    identity_provider: IdentityProvider,
    trust_provider: TrustProvider,
) -> IdentityForwardingManager:
    """
    Create a default identity forwarding manager.
    
    Args:
        identity_provider: Identity provider
        trust_provider: Trust provider
        
    Returns:
        Configured identity forwarding manager
    """
    return IdentityForwardingManager(
        identity_provider=identity_provider,
        trust_provider=trust_provider,
        default_session_duration=timedelta(hours=8),
    )