"""
JWT Secret Rotation for ECPS-UV SDK.

This module provides automatic JWT secret rotation on startup and periodic rotation
to enhance security for distributed robotic systems.
"""

import asyncio
import logging
import os
import secrets
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Callable, Any
from dataclasses import dataclass
from threading import Lock
import jwt
import json

logger = logging.getLogger("ecps_uv.trust.jwt_rotation")


@dataclass
class JWTSecret:
    """JWT secret with metadata."""
    secret: str
    created_at: datetime
    expires_at: datetime
    key_id: str
    algorithm: str = "HS256"
    
    def is_expired(self) -> bool:
        """Check if the secret has expired."""
        return datetime.utcnow() > self.expires_at
    
    def is_near_expiry(self, threshold_hours: int = 24) -> bool:
        """Check if the secret is near expiry."""
        threshold = datetime.utcnow() + timedelta(hours=threshold_hours)
        return self.expires_at <= threshold


class JWTSecretManager:
    """Manages JWT secret rotation and validation."""
    
    def __init__(
        self,
        rotation_interval_hours: int = 24,
        secret_length: int = 64,
        algorithm: str = "HS256",
        storage_path: Optional[str] = None
    ):
        """
        Initialize JWT secret manager.
        
        Args:
            rotation_interval_hours: Hours between secret rotations
            secret_length: Length of generated secrets in bytes
            algorithm: JWT signing algorithm
            storage_path: Path to store secret metadata (optional)
        """
        self.rotation_interval_hours = rotation_interval_hours
        self.secret_length = secret_length
        self.algorithm = algorithm
        self.storage_path = storage_path or os.path.join(
            os.path.expanduser("~"), ".ecps", "jwt_secrets.json"
        )
        
        self._current_secret: Optional[JWTSecret] = None
        self._previous_secret: Optional[JWTSecret] = None
        self._lock = Lock()
        self._rotation_task: Optional[asyncio.Task] = None
        self._callbacks: Dict[str, Callable[[JWTSecret], None]] = {}
        
        # Ensure storage directory exists
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
    
    def register_rotation_callback(self, name: str, callback: Callable[[JWTSecret], None]) -> None:
        """
        Register a callback to be called when secrets are rotated.
        
        Args:
            name: Unique name for the callback
            callback: Function to call with new secret
        """
        self._callbacks[name] = callback
        logger.debug(f"Registered rotation callback: {name}")
    
    def unregister_rotation_callback(self, name: str) -> None:
        """Unregister a rotation callback."""
        self._callbacks.pop(name, None)
        logger.debug(f"Unregistered rotation callback: {name}")
    
    def generate_secret(self) -> JWTSecret:
        """Generate a new JWT secret."""
        secret_bytes = secrets.token_bytes(self.secret_length)
        secret = secrets.token_urlsafe(self.secret_length)
        key_id = secrets.token_hex(8)
        
        now = datetime.utcnow()
        expires_at = now + timedelta(hours=self.rotation_interval_hours * 2)  # Grace period
        
        jwt_secret = JWTSecret(
            secret=secret,
            created_at=now,
            expires_at=expires_at,
            key_id=key_id,
            algorithm=self.algorithm
        )
        
        logger.info(f"Generated new JWT secret with key_id: {key_id}")
        return jwt_secret
    
    def rotate_secret_on_startup(self) -> JWTSecret:
        """
        Rotate JWT secret on startup.
        
        Returns:
            The new JWT secret
        """
        logger.info("Rotating JWT secret on startup")
        
        with self._lock:
            # Load previous secret if exists
            self._load_secrets_from_storage()
            
            # Store current as previous
            if self._current_secret:
                self._previous_secret = self._current_secret
                logger.debug(f"Moved current secret {self._current_secret.key_id} to previous")
            
            # Generate new current secret
            self._current_secret = self.generate_secret()
            
            # Save to storage
            self._save_secrets_to_storage()
            
            # Notify callbacks
            self._notify_rotation_callbacks()
            
            logger.info(f"JWT secret rotated on startup. New key_id: {self._current_secret.key_id}")
            return self._current_secret
    
    async def start_automatic_rotation(self) -> None:
        """Start automatic JWT secret rotation."""
        if self._rotation_task and not self._rotation_task.done():
            logger.warning("Automatic rotation already running")
            return
        
        logger.info(f"Starting automatic JWT secret rotation every {self.rotation_interval_hours} hours")
        self._rotation_task = asyncio.create_task(self._rotation_loop())
    
    async def stop_automatic_rotation(self) -> None:
        """Stop automatic JWT secret rotation."""
        if self._rotation_task:
            self._rotation_task.cancel()
            try:
                await self._rotation_task
            except asyncio.CancelledError:
                pass
            self._rotation_task = None
            logger.info("Stopped automatic JWT secret rotation")
    
    async def _rotation_loop(self) -> None:
        """Main rotation loop."""
        while True:
            try:
                # Wait for rotation interval
                await asyncio.sleep(self.rotation_interval_hours * 3600)
                
                # Check if rotation is needed
                with self._lock:
                    if (self._current_secret is None or 
                        self._current_secret.is_near_expiry(threshold_hours=self.rotation_interval_hours)):
                        
                        logger.info("Performing scheduled JWT secret rotation")
                        self._perform_rotation()
                
            except asyncio.CancelledError:
                logger.info("JWT rotation loop cancelled")
                break
            except Exception as e:
                logger.error(f"Error in JWT rotation loop: {e}")
                # Continue the loop after error
                await asyncio.sleep(60)  # Wait 1 minute before retrying
    
    def _perform_rotation(self) -> None:
        """Perform secret rotation (must be called with lock held)."""
        # Store current as previous
        if self._current_secret:
            self._previous_secret = self._current_secret
            logger.debug(f"Moved current secret {self._current_secret.key_id} to previous")
        
        # Generate new current secret
        self._current_secret = self.generate_secret()
        
        # Save to storage
        self._save_secrets_to_storage()
        
        # Notify callbacks
        self._notify_rotation_callbacks()
        
        logger.info(f"JWT secret rotated. New key_id: {self._current_secret.key_id}")
    
    def _notify_rotation_callbacks(self) -> None:
        """Notify all registered callbacks of secret rotation."""
        if not self._current_secret:
            return
        
        for name, callback in self._callbacks.items():
            try:
                callback(self._current_secret)
                logger.debug(f"Notified rotation callback: {name}")
            except Exception as e:
                logger.error(f"Error in rotation callback {name}: {e}")
    
    def get_current_secret(self) -> Optional[JWTSecret]:
        """Get the current JWT secret."""
        with self._lock:
            return self._current_secret
    
    def get_previous_secret(self) -> Optional[JWTSecret]:
        """Get the previous JWT secret (for validation during transition)."""
        with self._lock:
            return self._previous_secret
    
    def validate_token(self, token: str) -> Dict[str, Any]:
        """
        Validate a JWT token using current or previous secret.
        
        Args:
            token: JWT token to validate
            
        Returns:
            Decoded token payload
            
        Raises:
            jwt.InvalidTokenError: If token is invalid
        """
        with self._lock:
            secrets_to_try = []
            
            if self._current_secret:
                secrets_to_try.append(self._current_secret)
            
            if self._previous_secret and not self._previous_secret.is_expired():
                secrets_to_try.append(self._previous_secret)
        
        last_error = None
        for jwt_secret in secrets_to_try:
            try:
                payload = jwt.decode(
                    token,
                    jwt_secret.secret,
                    algorithms=[jwt_secret.algorithm]
                )
                logger.debug(f"Token validated with key_id: {jwt_secret.key_id}")
                return payload
            except jwt.InvalidTokenError as e:
                last_error = e
                continue
        
        # If we get here, validation failed with all secrets
        logger.warning("JWT token validation failed with all available secrets")
        raise last_error or jwt.InvalidTokenError("No valid secrets available")
    
    def create_token(self, payload: Dict[str, Any], expires_in_hours: int = 1) -> str:
        """
        Create a JWT token with the current secret.
        
        Args:
            payload: Token payload
            expires_in_hours: Token expiration time in hours
            
        Returns:
            Encoded JWT token
        """
        with self._lock:
            if not self._current_secret:
                raise RuntimeError("No current JWT secret available")
            
            # Add standard claims
            now = datetime.utcnow()
            payload.update({
                'iat': now,
                'exp': now + timedelta(hours=expires_in_hours),
                'kid': self._current_secret.key_id
            })
            
            token = jwt.encode(
                payload,
                self._current_secret.secret,
                algorithm=self._current_secret.algorithm
            )
            
            logger.debug(f"Created JWT token with key_id: {self._current_secret.key_id}")
            return token
    
    def _save_secrets_to_storage(self) -> None:
        """Save secrets to persistent storage."""
        try:
            data = {
                'current': self._secret_to_dict(self._current_secret) if self._current_secret else None,
                'previous': self._secret_to_dict(self._previous_secret) if self._previous_secret else None,
                'updated_at': datetime.utcnow().isoformat()
            }
            
            with open(self.storage_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            # Set restrictive permissions
            os.chmod(self.storage_path, 0o600)
            logger.debug(f"Saved JWT secrets to {self.storage_path}")
            
        except Exception as e:
            logger.error(f"Failed to save JWT secrets: {e}")
    
    def _load_secrets_from_storage(self) -> None:
        """Load secrets from persistent storage."""
        try:
            if not os.path.exists(self.storage_path):
                logger.debug("No existing JWT secrets found")
                return
            
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            if data.get('current'):
                self._current_secret = self._dict_to_secret(data['current'])
                logger.debug(f"Loaded current secret with key_id: {self._current_secret.key_id}")
            
            if data.get('previous'):
                self._previous_secret = self._dict_to_secret(data['previous'])
                logger.debug(f"Loaded previous secret with key_id: {self._previous_secret.key_id}")
                
        except Exception as e:
            logger.error(f"Failed to load JWT secrets: {e}")
    
    def _secret_to_dict(self, secret: JWTSecret) -> Dict[str, Any]:
        """Convert JWTSecret to dictionary for storage."""
        return {
            'secret': secret.secret,
            'created_at': secret.created_at.isoformat(),
            'expires_at': secret.expires_at.isoformat(),
            'key_id': secret.key_id,
            'algorithm': secret.algorithm
        }
    
    def _dict_to_secret(self, data: Dict[str, Any]) -> JWTSecret:
        """Convert dictionary to JWTSecret."""
        return JWTSecret(
            secret=data['secret'],
            created_at=datetime.fromisoformat(data['created_at']),
            expires_at=datetime.fromisoformat(data['expires_at']),
            key_id=data['key_id'],
            algorithm=data['algorithm']
        )


# Global JWT secret manager instance
_jwt_manager: Optional[JWTSecretManager] = None


def get_jwt_manager() -> JWTSecretManager:
    """Get the global JWT secret manager instance."""
    global _jwt_manager
    if _jwt_manager is None:
        _jwt_manager = JWTSecretManager()
    return _jwt_manager


def initialize_jwt_rotation(
    rotation_interval_hours: int = 24,
    secret_length: int = 64,
    algorithm: str = "HS256",
    storage_path: Optional[str] = None
) -> JWTSecret:
    """
    Initialize JWT secret rotation on startup.
    
    Args:
        rotation_interval_hours: Hours between secret rotations
        secret_length: Length of generated secrets in bytes
        algorithm: JWT signing algorithm
        storage_path: Path to store secret metadata
        
    Returns:
        The initial JWT secret
    """
    global _jwt_manager
    _jwt_manager = JWTSecretManager(
        rotation_interval_hours=rotation_interval_hours,
        secret_length=secret_length,
        algorithm=algorithm,
        storage_path=storage_path
    )
    
    return _jwt_manager.rotate_secret_on_startup()


async def start_jwt_rotation() -> None:
    """Start automatic JWT secret rotation."""
    manager = get_jwt_manager()
    await manager.start_automatic_rotation()


async def stop_jwt_rotation() -> None:
    """Stop automatic JWT secret rotation."""
    manager = get_jwt_manager()
    await manager.stop_automatic_rotation()