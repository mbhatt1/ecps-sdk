"""
Decorator API for the ECPS UV Trust layer.

This module provides easy-to-use decorators for applying security checks
to functions and methods in Python applications.
"""

import asyncio
import functools
import inspect
from typing import Any, Callable, Optional, TypeVar, cast, Union

from .trust import Principal, TrustProvider

# Type variables for better type hinting
F = TypeVar('F', bound=Callable[..., Any])
AsyncF = TypeVar('AsyncF', bound=Callable[..., Any])

class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class AuthorizationError(Exception):
    """Raised when authorization fails."""
    pass


def requires_authentication(
    trust_provider: TrustProvider,
    principal_param: str = "principal"
) -> Callable[[F], F]:
    """
    Decorator that requires authentication before executing the function.
    
    Args:
        trust_provider: The trust provider to use for authentication
        principal_param: The parameter name that contains the principal ID or object
        
    Returns:
        A decorator function
        
    Example:
        @requires_authentication(trust_provider)
        async def get_user_data(principal_id: str, data_id: str):
            # Only executed if principal_id is authenticated
            return await db.get_data(data_id)
    """
    def decorator(func: F) -> F:
        is_async = asyncio.iscoroutinefunction(func)
        
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get the principal ID or object
            principal_value = kwargs.get(principal_param)
            if principal_value is None:
                # Try to get from positional arguments
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                if principal_param in param_names:
                    idx = param_names.index(principal_param)
                    if idx < len(args):
                        principal_value = args[idx]
            
            # If it's already a Principal object
            if isinstance(principal_value, Principal):
                if principal_value.is_expired():
                    raise AuthenticationError("Principal has expired")
                return await func(*args, **kwargs)
                
            # If it's an ID, authenticate it
            principal = await trust_provider.authenticate(str(principal_value))
            if principal is None:
                raise AuthenticationError(f"Authentication failed for {principal_value}")
                
            # Replace the ID with the authenticated principal object
            new_kwargs = kwargs.copy()
            new_kwargs[principal_param] = principal
            
            if is_async:
                return await func(*args, **new_kwargs)
            else:
                return func(*args, **new_kwargs)
                
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # For synchronous functions, we still need to run the async authentication
            # using an event loop
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(async_wrapper(*args, **kwargs))
            
        return cast(F, async_wrapper if is_async else sync_wrapper)
    
    return decorator


def requires_authorization(
    trust_provider: TrustProvider,
    action: str,
    resource: str,
    principal_param: str = "principal"
) -> Callable[[F], F]:
    """
    Decorator that requires authorization for a specific action on a resource.
    
    Args:
        trust_provider: The trust provider to use for authentication
        action: The action to authorize
        resource: The resource to authorize action on
        principal_param: The parameter name that contains the principal ID or object
        
    Returns:
        A decorator function
        
    Example:
        @requires_authorization(trust_provider, "publish", "topic:sensor_data")
        async def publish_sensor_data(principal_id: str, data: dict):
            # Only executed if principal_id is authorized to publish to sensor_data
            await mqtt.publish("sensor_data", json.dumps(data))
    """
    def decorator(func: F) -> F:
        is_async = asyncio.iscoroutinefunction(func)
        
        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            # Get the principal ID or object
            principal_value = kwargs.get(principal_param)
            if principal_value is None:
                # Try to get from positional arguments
                sig = inspect.signature(func)
                param_names = list(sig.parameters.keys())
                if principal_param in param_names:
                    idx = param_names.index(principal_param)
                    if idx < len(args):
                        principal_value = args[idx]
                        
            # If we don't have a principal, can't authorize
            if principal_value is None:
                raise AuthorizationError(f"No {principal_param} provided for authorization")
                
            # If it's a string ID, authenticate first
            if not isinstance(principal_value, Principal):
                principal = await trust_provider.authenticate(str(principal_value))
                if principal is None:
                    raise AuthenticationError(f"Authentication failed for {principal_value}")
            else:
                principal = principal_value
                
            # Now authorize
            authorized, reason = await trust_provider.authorize(principal, action, resource)
            if not authorized:
                raise AuthorizationError(
                    f"Not authorized to {action} on {resource}: {reason}"
                )
                
            # Replace the ID with the authenticated principal object if needed
            if not isinstance(principal_value, Principal):
                new_kwargs = kwargs.copy()
                new_kwargs[principal_param] = principal
                kwargs = new_kwargs
                
            if is_async:
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)
                
        @functools.wraps(func)
        def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            # For synchronous functions, we still need to run the async authorization
            # using an event loop
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(async_wrapper(*args, **kwargs))
            
        return cast(F, async_wrapper if is_async else sync_wrapper)
    
    return decorator


def secure_operation(
    trust_provider: TrustProvider,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    authenticate_only: bool = False,
    principal_param: str = "principal"
) -> Callable[[F], F]:
    """
    Comprehensive security decorator that can perform both authentication and authorization.
    
    Args:
        trust_provider: The trust provider to use
        action: The action to authorize (if None, only authentication is performed)
        resource: The resource to authorize action on
        authenticate_only: If True, only authentication is performed regardless of action/resource
        principal_param: The parameter name that contains the principal ID or object
        
    Returns:
        A decorator function
        
    Example:
        @secure_operation(trust_provider, "read", "user_data")
        async def get_user_profile(principal: Principal, user_id: str):
            # Only executed if principal is authenticated and authorized
            return await db.get_user(user_id)
    """
    def decorator(func: F) -> F:
        # If we're just doing authentication
        if authenticate_only or (action is None or resource is None):
            return requires_authentication(trust_provider, principal_param)(func)
            
        # Otherwise, do full authorization
        return requires_authorization(
            trust_provider, action, resource, principal_param
        )(func)
    
    return decorator


# Convenience function to create a secured version of a function
def secure(
    func: F,
    trust_provider: TrustProvider,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    authenticate_only: bool = False,
    principal_param: str = "principal"
) -> F:
    """
    Create a secured version of a function.
    
    This is useful when you want to secure a function without modifying its definition.
    
    Args:
        func: The function to secure
        trust_provider: The trust provider to use
        action: The action to authorize
        resource: The resource to authorize action on
        authenticate_only: If True, only authentication is performed
        principal_param: The parameter name for the principal
        
    Returns:
        A secured version of the function
        
    Example:
        original_func = api.get_data
        api.get_data = secure(original_func, trust_provider, "read", "data")
    """
    return secure_operation(
        trust_provider, action, resource, authenticate_only, principal_param
    )(func)