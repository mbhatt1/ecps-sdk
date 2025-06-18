#!/usr/bin/env python3
"""
Tests for the ECPS UV trust layer.

This module tests the trust functionality including:
- Trust provider configuration
- Principal authentication and authorization
- Secure transport wrapping
- JWT token validation
- Message signing and verification
"""

import asyncio
import os
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

from ecps_uv.serialization.json import JSONSerializer
from ecps_uv.trust import (
    Principal,
    RBACAuthorizer,
    TrustLevel,
    TrustMechanism,
    TrustProvider,
)
from ecps_uv.trust.secure_transport import SecureMessage, SecureTransport


class MockTransport:
    """Mock transport for testing."""
    
    def __init__(self):
        self.serializer = JSONSerializer()
        self.sent_messages = []
        self.started = False
        self.stopped = False
    
    async def start(self):
        self.started = True
        return True
    
    async def stop(self):
        self.stopped = True
        return True
    
    async def send(self, topic, message, **kwargs):
        self.sent_messages.append((topic, message, kwargs))
        return "mock-message-id"
    
    async def receive(self, topics, handler, **kwargs):
        # Not implemented for this mock
        pass


class TestTrustProvider(unittest.TestCase):
    """Test the TrustProvider class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create temporary key files
        self.private_key_file = tempfile.NamedTemporaryFile(delete=False)
        self.public_key_file = tempfile.NamedTemporaryFile(delete=False)
        
        # Write dummy key content for testing
        self.private_key_file.write(b"-----BEGIN PRIVATE KEY-----\nMockPrivateKey\n-----END PRIVATE KEY-----")
        self.public_key_file.write(b"-----BEGIN PUBLIC KEY-----\nMockPublicKey\n-----END PUBLIC KEY-----")
        
        self.private_key_file.close()
        self.public_key_file.close()
        
        # Create a mock authorizer
        self.authorizer = RBACAuthorizer()
        self.authorizer.add_role_permission("admin", "publish", "test-topic")
        self.authorizer.add_role_permission("user", "subscribe", "test-topic")
        
        # Create a trust provider for testing
        self.trust_provider = TrustProvider(
            trust_level=TrustLevel.AUTHORIZATION,
            mechanisms=[TrustMechanism.JWT, TrustMechanism.TLS],
            jwt_secret="test-secret-key-for-jwt-generation-and-validation",
            private_key_path=self.private_key_file.name,
            public_key_path=self.public_key_file.name,
            authorizer=self.authorizer,
        )
        
        # Create test principals
        self.admin_principal = Principal(
            id="admin1",
            name="Admin User",
            roles=["admin"],
            permissions={"publish:test-topic": True},
            attributes={"department": "IT"},
        )
        
        self.user_principal = Principal(
            id="user1",
            name="Regular User",
            roles=["user"],
            permissions={"subscribe:test-topic": True},
            attributes={"department": "Marketing"},
        )
        
        # Add test principals to trust provider
        self.trust_provider.add_principal(self.admin_principal)
        self.trust_provider.add_principal(self.user_principal)
    
    def tearDown(self):
        """Clean up test fixtures."""
        os.unlink(self.private_key_file.name)
        os.unlink(self.public_key_file.name)
    
    def test_trust_provider_initialization(self):
        """Test trust provider initialization with different configurations."""
        # Test with NONE trust level
        none_provider = TrustProvider(
            trust_level=TrustLevel.NONE,
            mechanisms=[],
        )
        self.assertEqual(none_provider.trust_level, TrustLevel.NONE)
        self.assertEqual(none_provider.mechanisms, [])
        
        # Test with ENCRYPTION trust level
        encryption_provider = TrustProvider(
            trust_level=TrustLevel.ENCRYPTION,
            mechanisms=[TrustMechanism.TLS],
        )
        self.assertEqual(encryption_provider.trust_level, TrustLevel.ENCRYPTION)
        self.assertEqual(encryption_provider.mechanisms, [TrustMechanism.TLS])
        
        # Test with AUTHENTICATION trust level
        auth_provider = TrustProvider(
            trust_level=TrustLevel.AUTHENTICATION,
            mechanisms=[TrustMechanism.JWT],
            jwt_secret="test-key",
        )
        self.assertEqual(auth_provider.trust_level, TrustLevel.AUTHENTICATION)
        self.assertEqual(auth_provider.mechanisms, [TrustMechanism.JWT])
        
        # Test our setUp provider
        self.assertEqual(self.trust_provider.trust_level, TrustLevel.AUTHORIZATION)
        self.assertEqual(
            self.trust_provider.mechanisms, 
            [TrustMechanism.JWT, TrustMechanism.TLS]
        )
    
    def test_principal_management(self):
        """Test principal management in trust provider."""
        # Test getting existing principals
        retrieved_admin = self.trust_provider.get_principal("admin1")
        self.assertEqual(retrieved_admin.id, "admin1")
        self.assertEqual(retrieved_admin.name, "Admin User")
        self.assertEqual(retrieved_admin.roles, ["admin"])
        
        retrieved_user = self.trust_provider.get_principal("user1")
        self.assertEqual(retrieved_user.id, "user1")
        self.assertEqual(retrieved_user.roles, ["user"])
        
        # Test getting non-existent principal
        non_existent = self.trust_provider.get_principal("non-existent")
        self.assertIsNone(non_existent)
        
        # Test removing principal
        self.trust_provider.remove_principal("user1")
        self.assertIsNone(self.trust_provider.get_principal("user1"))
        
        # Test clear principals
        self.trust_provider.clear_principals()
        self.assertIsNone(self.trust_provider.get_principal("admin1"))
    
    async def async_test_authentication(self):
        """Test authentication of principals."""
        # Re-add principals for this test
        self.trust_provider.add_principal(self.admin_principal)
        self.trust_provider.add_principal(self.user_principal)
        
        # Test successful authentication
        authenticated_admin = await self.trust_provider.authenticate("admin1")
        self.assertIsNotNone(authenticated_admin)
        self.assertEqual(authenticated_admin.id, "admin1")
        
        # Test failed authentication
        invalid_auth = await self.trust_provider.authenticate("non-existent")
        self.assertIsNone(invalid_auth)
    
    async def async_test_authorization(self):
        """Test authorization of principals for actions."""
        # Re-add principals for this test
        self.trust_provider.add_principal(self.admin_principal)
        self.trust_provider.add_principal(self.user_principal)
        
        # Test successful authorization for admin publishing
        admin_auth, reason = await self.trust_provider.authorize(
            self.admin_principal, "publish", "test-topic"
        )
        self.assertTrue(admin_auth)
        
        # Test failed authorization for user publishing
        user_pub_auth, reason = await self.trust_provider.authorize(
            self.user_principal, "publish", "test-topic"
        )
        self.assertFalse(user_pub_auth)
        
        # Test successful authorization for user subscribing
        user_sub_auth, reason = await self.trust_provider.authorize(
            self.user_principal, "subscribe", "test-topic"
        )
        self.assertTrue(user_sub_auth)
    
    def test_jwt_creation_and_validation(self):
        """Test JWT token creation and validation."""
        # Create JWT for admin principal
        admin_token = self.trust_provider.create_jwt(
            self.admin_principal, 
            expires_in=timedelta(hours=1)
        )
        self.assertIsNotNone(admin_token)
        
        # Validate token
        decoded_claims = self.trust_provider.validate_jwt(admin_token)
        self.assertIsNotNone(decoded_claims)
        self.assertEqual(decoded_claims.get("sub"), self.admin_principal.id)
        self.assertEqual(decoded_claims.get("name"), self.admin_principal.name)
        
        # Test with expired token
        with patch('ecps_uv.trust.trust.datetime') as mock_datetime:
            # Set to a future time beyond token expiration
            mock_datetime.now.return_value = datetime.now() + timedelta(hours=2)
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)
            
            # Validate should fail
            invalid_claims = self.trust_provider.validate_jwt(admin_token)
            self.assertIsNone(invalid_claims)
    
    def test_secure_transport_wrapper(self):
        """Test secure transport wrapping."""
        # Create a mock transport
        mock_transport = MockTransport()
        
        # Wrap with secure transport
        secure_transport = self.trust_provider.secure_transport(mock_transport)
        
        # Verify wrapper properties
        self.assertIsInstance(secure_transport, SecureTransport)
        self.assertEqual(secure_transport.trust_provider, self.trust_provider)
        self.assertEqual(secure_transport.transport, mock_transport)
    
    def test_async_functions(self):
        """Run the async test functions."""
        asyncio.run(self.async_test_authentication())
        asyncio.run(self.async_test_authorization())


class TestSecureTransport(unittest.TestCase):
    """Test the SecureTransport class."""
    
    def setUp(self):
        """Set up test fixtures."""
        # Create a mock authorizer
        self.authorizer = RBACAuthorizer()
        
        # Create a trust provider
        self.trust_provider = TrustProvider(
            trust_level=TrustLevel.AUTHORIZATION,
            mechanisms=[TrustMechanism.JWT],
            jwt_secret="test-secret-key",
            authorizer=self.authorizer,
        )
        
        # Create a test principal
        self.test_principal = Principal(
            id="test1",
            name="Test User",
            roles=["user"],
            permissions={},
        )
        self.trust_provider.add_principal(self.test_principal)
        
        # Create JWT token
        self.token = self.trust_provider.create_jwt(
            self.test_principal,
            expires_in=timedelta(hours=1)
        )
        
        # Create mock transport
        self.mock_transport = MockTransport()
        
        # Create secure transport
        self.secure_transport = self.trust_provider.secure_transport(self.mock_transport)
        
        # Set principal on secure transport
        self.secure_transport.set_principal(self.test_principal.id, self.token)
    
    async def async_test_secure_transport_operations(self):
        """Test secure transport operations."""
        # Test start and stop passthrough
        await self.secure_transport.start()
        self.assertTrue(self.mock_transport.started)
        
        await self.secure_transport.stop()
        self.assertTrue(self.mock_transport.stopped)
        
        # Test message sending with security envelope
        test_message = {"text": "Hello, secure world!", "value": 42}
        await self.secure_transport.send("test-topic", test_message)
        
        # Verify message was sent
        self.assertEqual(len(self.mock_transport.sent_messages), 1)
        
        # Extract sent message
        topic, sent_message, kwargs = self.mock_transport.sent_messages[0]
        self.assertEqual(topic, "test-topic")
        
        # Verify it's a secure message
        self.assertIsInstance(sent_message, SecureMessage)
        
        # Check secure message properties
        self.assertEqual(sent_message.sender_id, self.test_principal.id)
        self.assertIsNotNone(sent_message.timestamp)
        
        # Message content should be present
        self.assertIsNotNone(sent_message.payload)
        
        # If using encryption, payload should be encrypted
        if self.trust_provider.trust_level >= TrustLevel.ENCRYPTION:
            # In a real implementation, we would decrypt and verify content
            pass
        else:
            # For testing, payload is just serialized content
            self.assertEqual(
                self.mock_transport.serializer.deserialize(sent_message.payload),
                test_message
            )
        
        # If using authentication, should have a signature
        if self.trust_provider.trust_level >= TrustLevel.AUTHENTICATION:
            self.assertIsNotNone(sent_message.signature)
        else:
            self.assertIsNone(sent_message.signature)
        
        # Should have a token for authorization
        if self.trust_provider.trust_level >= TrustLevel.AUTHORIZATION:
            self.assertEqual(sent_message.token, self.token)
    
    def test_secure_message(self):
        """Test secure message class."""
        # Create a test message
        message = SecureMessage(
            sender_id="test1",
            token=self.token,
            payload="encrypted-payload",
            signature="message-signature",
            timestamp=datetime.now().isoformat(),
        )
        
        # Test properties
        self.assertEqual(message.sender_id, "test1")
        self.assertEqual(message.token, self.token)
        self.assertEqual(message.payload, "encrypted-payload")
        self.assertEqual(message.signature, "message-signature")
        self.assertIsNotNone(message.timestamp)
    
    def test_async_functions(self):
        """Run the async test functions."""
        asyncio.run(self.async_test_secure_transport_operations())


if __name__ == "__main__":
    unittest.main()