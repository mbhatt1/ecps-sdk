"""
Trust layer for ECPS UV SDK.

This module provides security mechanisms for the ECPS protocol stack,
including authentication, authorization, and encryption.
"""

from ecps_uv.trust.trust import (
    TrustLevel,
    TrustMechanism,
    Principal,
    Authorizer,
    RBACAuthorizer,
    TrustProvider,
)
from ecps_uv.trust.secure_transport import SecureTransport, SecureMessage
from ecps_uv.trust.decorators import (
    AuthenticationError,
    AuthorizationError,
    requires_authentication,
    requires_authorization,
    secure_operation,
    secure,
)
from ecps_uv.trust.identity import (
    IdentityType,
    Identity,
    IdentityStore,
    IdentityProvider,
    create_default_identity_provider,
)
from ecps_uv.trust.identity_forwarding import (
    IdentityContext,
    ForwardedRequest,
    IdentityForwardingManager,
    create_default_identity_forwarding_manager,
)

__all__ = [
    "TrustLevel",
    "TrustMechanism",
    "Principal",
    "Authorizer",
    "RBACAuthorizer",
    "TrustProvider",
    "SecureTransport",
    "SecureMessage",
    "AuthenticationError",
    "AuthorizationError",
    "requires_authentication",
    "requires_authorization",
    "secure_operation",
    "secure",
    "IdentityType",
    "Identity",
    "IdentityStore",
    "IdentityProvider",
    "create_default_identity_provider",
    "IdentityContext",
    "ForwardedRequest",
    "IdentityForwardingManager",
    "create_default_identity_forwarding_manager",
]