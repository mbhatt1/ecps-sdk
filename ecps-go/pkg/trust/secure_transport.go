// Package trust provides security and trust mechanisms for the ECPS protocol stack.
package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ecps/ecps-go/pkg/core"
)

// SecureMessage wraps a message with security metadata
type SecureMessage struct {
	// Message is the original serialized message
	Message []byte `json:"message"`
	
	// MessageType is the type name of the original message
	MessageType string `json:"message_type"`
	
	// Signature is the message signature (if signed)
	Signature []byte `json:"signature,omitempty"`
	
	// EncryptedKey is the encrypted symmetric key (if encrypted)
	EncryptedKey []byte `json:"encrypted_key,omitempty"`
	
	// IV is the initialization vector for symmetric encryption
	IV []byte `json:"iv,omitempty"`
	
	// SecurityToken is the security token (e.g., JWT)
	SecurityToken string `json:"security_token,omitempty"`
	
	// SenderID is the ID of the sender
	SenderID string `json:"sender_id,omitempty"`
	
	// Timestamp is the message timestamp
	Timestamp int64 `json:"timestamp"`
}

// SecureTransport wraps a transport with security features
type SecureTransport struct {
	transport    core.Transport
	trustProvider *TrustProvider
	principalID   string
	securityToken string
}

// NewSecureTransport creates a new secure transport wrapper
func NewSecureTransport(transport core.Transport, trustProvider *TrustProvider) *SecureTransport {
	return &SecureTransport{
		transport:     transport,
		trustProvider: trustProvider,
	}
}

// SetPrincipal sets the principal ID and security token for the transport
func (t *SecureTransport) SetPrincipal(principalID string, securityToken string) {
	t.principalID = principalID
	t.securityToken = securityToken
}

// Start starts the transport
func (t *SecureTransport) Start(ctx context.Context) error {
	return t.transport.Start(ctx)
}

// Close closes the transport
func (t *SecureTransport) Close() error {
	return t.transport.Close()
}

// IsStarted checks if the transport is started
func (t *SecureTransport) IsStarted() bool {
	return t.transport.IsStarted()
}

// IsConnected checks if the transport is connected
func (t *SecureTransport) IsConnected() bool {
	return t.transport.IsConnected()
}

// Publish publishes a message with security features
func (t *SecureTransport) Publish(ctx context.Context, topic string, message interface{}, qos map[string]interface{}) error {
	// Skip security if trust level is none
	if t.trustProvider.trustLevel == TrustLevelNone {
		return t.transport.Publish(ctx, topic, message, qos)
	}
	
	// Get serializer from transport
	serializer, ok := t.transport.(interface{ Serializer() core.Serializer })
	if !ok {
		return errors.New("transport does not provide access to serializer")
	}
	
	// Serialize original message
	messageBytes, err := serializer.Serializer().Serialize(message, false)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}
	
	// Create secure message
	secureMsg := &SecureMessage{
		Message:     messageBytes,
		MessageType: fmt.Sprintf("%T", message),
		SenderID:    t.principalID,
		Timestamp:   time.Now().UnixNano(),
	}
	
	// Add security token if available
	if t.securityToken != "" {
		secureMsg.SecurityToken = t.securityToken
	}
	
	// Sign message if trust level requires it
	if t.trustProvider.trustLevel >= TrustLevelAuthenticated {
		signature, err := t.trustProvider.SignMessage(messageBytes)
		if err != nil {
			return fmt.Errorf("failed to sign message: %w", err)
		}
		secureMsg.Signature = signature
	}
	
	// Encrypt message if trust level requires it
	if t.trustProvider.trustLevel >= TrustLevelEncryption {
		// In a real implementation, we would use a hybrid encryption scheme:
		// 1. Generate a random symmetric key
		// 2. Encrypt the message with the symmetric key
		// 3. Encrypt the symmetric key with the recipient's public key
		// 4. Include the encrypted key and IV in the secure message
		
		// For this example, we'll just note that encryption would happen here
		// and leave the original message intact
		
		// In a real implementation:
		// encryptedMsg, encryptedKey, iv, err := t.encryptWithHybridScheme(messageBytes)
		// secureMsg.Message = encryptedMsg
		// secureMsg.EncryptedKey = encryptedKey
		// secureMsg.IV = iv
	}
	
	// Publish secure message
	return t.transport.Publish(ctx, topic, secureMsg, qos)
}

// Subscribe subscribes to a topic with security features
func (t *SecureTransport) Subscribe(
	ctx context.Context,
	topic string,
	messageType interface{},
	handler interface{},
	qos map[string]interface{},
) error {
	// Skip security if trust level is none
	if t.trustProvider.trustLevel == TrustLevelNone {
		return t.transport.Subscribe(ctx, topic, messageType, handler, qos)
	}
	
	// Get serializer from transport
	serializer, ok := t.transport.(interface{ Serializer() core.Serializer })
	if !ok {
		return errors.New("transport does not provide access to serializer")
	}
	
	// Create secure message handler
	secureHandler := func(ctx context.Context, secureMsg *SecureMessage) error {
		// Verify signature if trust level requires it
		if t.trustProvider.trustLevel >= TrustLevelAuthenticated && secureMsg.Signature != nil {
			if err := t.trustProvider.VerifyMessage(secureMsg.Message, secureMsg.Signature); err != nil {
				return fmt.Errorf("message signature verification failed: %w", err)
			}
		}
		
		// Decrypt message if trust level requires it
		messageBytes := secureMsg.Message
		if t.trustProvider.trustLevel >= TrustLevelEncryption && secureMsg.EncryptedKey != nil {
			// In a real implementation, we would:
			// 1. Decrypt the symmetric key with our private key
			// 2. Decrypt the message with the symmetric key and IV
			
			// For this example, we'll just note that decryption would happen here
			// messageBytes, err = t.decryptWithHybridScheme(secureMsg)
			// if err != nil {
			//     return fmt.Errorf("message decryption failed: %w", err)
			// }
		}
		
		// Authenticate sender if trust level requires it
		var principal *Principal
		if t.trustProvider.trustLevel >= TrustLevelAuthenticated && secureMsg.SecurityToken != "" {
			var err error
			principal, err = t.trustProvider.ValidateJWT(secureMsg.SecurityToken)
			if err != nil {
				return fmt.Errorf("security token validation failed: %w", err)
			}
			
			// Check if sender ID matches the token subject
			if secureMsg.SenderID != "" && secureMsg.SenderID != principal.ID {
				return errors.New("sender ID does not match security token subject")
			}
		}
		
		// Authorize action if trust level requires it
		if t.trustProvider.trustLevel >= TrustLevelAuthorized && principal != nil {
			authorized, err := t.trustProvider.Authorize(ctx, principal, "subscribe", topic)
			if err != nil {
				return fmt.Errorf("authorization check failed: %w", err)
			}
			if !authorized {
				return errors.New("sender is not authorized to publish to this topic")
			}
		}
		
		// Deserialize original message
		origMsg, err := serializer.Serializer().Deserialize(messageBytes, messageType)
		if err != nil {
			return fmt.Errorf("failed to deserialize original message: %w", err)
		}
		
		// Add security context to the context
		if principal != nil {
			ctx = context.WithValue(ctx, "principal", principal)
		}
		
		// Call original handler with the deserialized message
		switch h := handler.(type) {
		case func(context.Context, interface{}) error:
			return h(ctx, origMsg)
		default:
			// Use reflection to call the handler with the correct type
			return errors.New("unsupported handler type")
		}
	}
	
	// Subscribe with secure handler
	return t.transport.Subscribe(ctx, topic, &SecureMessage{}, secureHandler, qos)
}

// Request sends a request with security features
func (t *SecureTransport) Request(
	ctx context.Context,
	service string,
	request interface{},
	timeout int64,
	qos map[string]interface{},
) (interface{}, error) {
	// Not implementing security for request/response yet
	// In a real implementation, we would wrap the request in a SecureMessage
	// and unwrap the response
	return t.transport.Request(ctx, service, request, timeout, qos)
}

// StreamRequest sends a streaming request with security features
func (t *SecureTransport) StreamRequest(
	ctx context.Context,
	service string,
	request interface{},
	handler interface{},
	timeout int64,
	qos map[string]interface{},
) error {
	// Not implementing security for streaming request yet
	// In a real implementation, we would wrap the request in a SecureMessage
	// and unwrap the responses
	return t.transport.StreamRequest(ctx, service, request, handler, timeout, qos)
}

// RegisterService registers a service with security features
func (t *SecureTransport) RegisterService(
	ctx context.Context,
	service string,
	handler interface{},
	requestType interface{},
	responseType interface{},
	qos map[string]interface{},
) error {
	// Not implementing security for service registration yet
	// In a real implementation, we would unwrap incoming SecureMessage objects
	// and wrap outgoing responses
	return t.transport.RegisterService(ctx, service, handler, requestType, responseType, qos)
}

// RegisterStreamService registers a streaming service with security features
func (t *SecureTransport) RegisterStreamService(
	ctx context.Context,
	service string,
	handler interface{},
	requestType interface{},
	responseType interface{},
	qos map[string]interface{},
) error {
	// Not implementing security for streaming service registration yet
	// In a real implementation, we would unwrap incoming SecureMessage objects
	// and wrap outgoing responses
	return t.transport.RegisterStreamService(ctx, service, handler, requestType, responseType, qos)
}