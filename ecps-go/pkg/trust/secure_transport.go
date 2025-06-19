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
		// Generate a random symmetric key (AES-256)
		symmetricKey := make([]byte, 32)
		if _, err := rand.Read(symmetricKey); err != nil {
			return fmt.Errorf("failed to generate symmetric key: %w", err)
		}
		
		// Generate IV for AES-CBC
		iv := make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			return fmt.Errorf("failed to generate IV: %w", err)
		}
		
		// Encrypt the message with AES-CBC
		block, err := aes.NewCipher(symmetricKey)
		if err != nil {
			return fmt.Errorf("failed to create AES cipher: %w", err)
		}
		
		// Pad the message to block size
		blockSize := aes.BlockSize
		paddingLength := blockSize - (len(messageBytes) % blockSize)
		paddedMessage := make([]byte, len(messageBytes)+paddingLength)
		copy(paddedMessage, messageBytes)
		for i := len(messageBytes); i < len(paddedMessage); i++ {
			paddedMessage[i] = byte(paddingLength)
		}
		
		// Encrypt with CBC mode
		mode := cipher.NewCBCEncrypter(block, iv)
		encryptedMessage := make([]byte, len(paddedMessage))
		mode.CryptBlocks(encryptedMessage, paddedMessage)
		
		// Encrypt the symmetric key with RSA public key (if available)
		if t.trustProvider.publicKey != nil {
			encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, t.trustProvider.publicKey, symmetricKey, nil)
			if err != nil {
				return fmt.Errorf("failed to encrypt symmetric key: %w", err)
			}
			secureMsg.EncryptedKey = encryptedKey
		}
		
		secureMsg.Message = encryptedMessage
		secureMsg.IV = iv
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
			// Decrypt the symmetric key with our private key
			if t.trustProvider.privateKey == nil {
				return errors.New("no private key available for decryption")
			}
			
			symmetricKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, t.trustProvider.privateKey, secureMsg.EncryptedKey, nil)
			if err != nil {
				return fmt.Errorf("failed to decrypt symmetric key: %w", err)
			}
			
			// Decrypt the message with AES-CBC
			if secureMsg.IV == nil || len(secureMsg.IV) != aes.BlockSize {
				return errors.New("invalid or missing IV for decryption")
			}
			
			block, err := aes.NewCipher(symmetricKey)
			if err != nil {
				return fmt.Errorf("failed to create AES cipher for decryption: %w", err)
			}
			
			if len(secureMsg.Message)%aes.BlockSize != 0 {
				return errors.New("encrypted message is not a multiple of block size")
			}
			
			mode := cipher.NewCBCDecrypter(block, secureMsg.IV)
			decryptedMessage := make([]byte, len(secureMsg.Message))
			mode.CryptBlocks(decryptedMessage, secureMsg.Message)
			
			// Remove padding
			if len(decryptedMessage) == 0 {
				return errors.New("decrypted message is empty")
			}
			
			paddingLength := int(decryptedMessage[len(decryptedMessage)-1])
			if paddingLength > len(decryptedMessage) || paddingLength == 0 {
				return errors.New("invalid padding in decrypted message")
			}
			
			messageBytes = decryptedMessage[:len(decryptedMessage)-paddingLength]
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
	// Skip security if trust level is none
	if t.trustProvider.trustLevel == TrustLevelNone {
		return t.transport.Request(ctx, service, request, timeout, qos)
	}
	
	// Get serializer from transport
	serializer, ok := t.transport.(interface{ Serializer() core.Serializer })
	if !ok {
		return nil, errors.New("transport does not provide access to serializer")
	}
	
	// Serialize the request
	requestBytes, err := serializer.Serializer().Serialize(request)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize request: %w", err)
	}
	
	// Create secure message
	secureMsg, err := t.createSecureMessage(requestBytes, request)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure message: %w", err)
	}
	
	// Send secure request
	secureResponse, err := t.transport.Request(ctx, service, secureMsg, timeout, qos)
	if err != nil {
		return nil, err
	}
	
	// Unwrap secure response if it's a SecureMessage
	if secureMsg, ok := secureResponse.(*SecureMessage); ok {
		return t.unwrapSecureMessage(secureMsg, serializer.Serializer())
	}
	
	return secureResponse, nil
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
	// Skip security if trust level is none
	if t.trustProvider.trustLevel == TrustLevelNone {
		return t.transport.StreamRequest(ctx, service, request, handler, timeout, qos)
	}
	
	// Get serializer from transport
	serializer, ok := t.transport.(interface{ Serializer() core.Serializer })
	if !ok {
		return errors.New("transport does not provide access to serializer")
	}
	
	// Create secure handler wrapper
	secureHandler := func(ctx context.Context, response interface{}) error {
		// Unwrap secure response if it's a SecureMessage
		if secureMsg, ok := response.(*SecureMessage); ok {
			unwrappedResponse, err := t.unwrapSecureMessage(secureMsg, serializer.Serializer())
			if err != nil {
				return fmt.Errorf("failed to unwrap secure response: %w", err)
			}
			
			// Call original handler with unwrapped response
			switch h := handler.(type) {
			case func(context.Context, interface{}) error:
				return h(ctx, unwrappedResponse)
			default:
				return errors.New("unsupported handler type")
			}
		} else {
			// Direct response, call handler as-is
			switch h := handler.(type) {
			case func(context.Context, interface{}) error:
				return h(ctx, response)
			default:
				return errors.New("unsupported handler type")
			}
		}
	}
	
	// Serialize the request
	requestBytes, err := serializer.Serializer().Serialize(request)
	if err != nil {
		return fmt.Errorf("failed to serialize request: %w", err)
	}
	
	// Create secure message
	secureMsg, err := t.createSecureMessage(requestBytes, request)
	if err != nil {
		return fmt.Errorf("failed to create secure message: %w", err)
	}
	
	// Send secure streaming request
	return t.transport.StreamRequest(ctx, service, secureMsg, secureHandler, timeout, qos)
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
	// Skip security if trust level is none
	if t.trustProvider.trustLevel == TrustLevelNone {
		return t.transport.RegisterService(ctx, service, handler, requestType, responseType, qos)
	}
	
	// Get serializer from transport
	serializer, ok := t.transport.(interface{ Serializer() core.Serializer })
	if !ok {
		return errors.New("transport does not provide access to serializer")
	}
	
	// Create secure handler wrapper
	secureHandler := func(ctx context.Context, request interface{}) (interface{}, error) {
		// Unwrap secure request if it's a SecureMessage
		if secureMsg, ok := request.(*SecureMessage); ok {
			unwrappedRequest, err := t.unwrapSecureMessage(secureMsg, serializer.Serializer())
			if err != nil {
				return nil, fmt.Errorf("failed to unwrap secure request: %w", err)
			}
			
			// Call original handler with unwrapped request
			var response interface{}
			var handlerErr error
			
			switch h := handler.(type) {
			case func(context.Context, interface{}) (interface{}, error):
				response, handlerErr = h(ctx, unwrappedRequest)
			default:
				return nil, errors.New("unsupported handler type")
			}
			
			if handlerErr != nil {
				return nil, handlerErr
			}
			
			// Wrap response in secure message if not nil
			if response != nil {
				responseBytes, err := serializer.Serializer().Serialize(response)
				if err != nil {
					return nil, fmt.Errorf("failed to serialize response: %w", err)
				}
				
				secureResponse, err := t.createSecureMessage(responseBytes, response)
				if err != nil {
					return nil, fmt.Errorf("failed to create secure response: %w", err)
				}
				
				return secureResponse, nil
			}
			
			return nil, nil
		} else {
			// Direct request, call handler as-is
			switch h := handler.(type) {
			case func(context.Context, interface{}) (interface{}, error):
				return h(ctx, request)
			default:
				return nil, errors.New("unsupported handler type")
			}
		}
	}
	
	return t.transport.RegisterService(ctx, service, secureHandler, &SecureMessage{}, &SecureMessage{}, qos)
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
	// Skip security if trust level is none
	if t.trustProvider.trustLevel == TrustLevelNone {
		return t.transport.RegisterStreamService(ctx, service, handler, requestType, responseType, qos)
	}
	
	// Get serializer from transport
	serializer, ok := t.transport.(interface{ Serializer() core.Serializer })
	if !ok {
		return errors.New("transport does not provide access to serializer")
	}
	
	// Create secure streaming handler wrapper
	secureStreamingHandler := func(ctx context.Context, request interface{}, responseHandler func(context.Context, interface{}) error) error {
		// Create secure response handler
		secureResponseHandler := func(ctx context.Context, response interface{}) error {
			if response != nil {
				responseBytes, err := serializer.Serializer().Serialize(response)
				if err != nil {
					return fmt.Errorf("failed to serialize response: %w", err)
				}
				
				secureResponse, err := t.createSecureMessage(responseBytes, response)
				if err != nil {
					return fmt.Errorf("failed to create secure response: %w", err)
				}
				
				return responseHandler(ctx, secureResponse)
			}
			return responseHandler(ctx, nil)
		}
		
		// Unwrap secure request if it's a SecureMessage
		if secureMsg, ok := request.(*SecureMessage); ok {
			unwrappedRequest, err := t.unwrapSecureMessage(secureMsg, serializer.Serializer())
			if err != nil {
				return fmt.Errorf("failed to unwrap secure request: %w", err)
			}
			
			// Call original handler with unwrapped request
			switch h := handler.(type) {
			case func(context.Context, interface{}, func(context.Context, interface{}) error) error:
				return h(ctx, unwrappedRequest, secureResponseHandler)
			default:
				return errors.New("unsupported handler type")
			}
		} else {
			// Direct request, call handler as-is
			switch h := handler.(type) {
			case func(context.Context, interface{}, func(context.Context, interface{}) error) error:
				return h(ctx, request, responseHandler)
			default:
				return errors.New("unsupported handler type")
			}
		}
	}
	
	return t.transport.RegisterStreamService(ctx, service, secureStreamingHandler, &SecureMessage{}, &SecureMessage{}, qos)
}

// createSecureMessage creates a secure message with encryption and signing if required
func (t *SecureTransport) createSecureMessage(messageBytes []byte, originalMsg interface{}) (*SecureMessage, error) {
	secureMsg := &SecureMessage{
		Message:     messageBytes,
		MessageType: fmt.Sprintf("%T", originalMsg),
		SenderID:    t.trustProvider.principal.ID,
		Timestamp:   time.Now().UnixNano(),
	}
	
	// Add signature if trust level requires it
	if t.trustProvider.trustLevel >= TrustLevelAuthenticated {
		signature, err := t.trustProvider.SignMessage(messageBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to sign message: %w", err)
		}
		secureMsg.Signature = signature
	}
	
	// Add encryption if trust level requires it
	if t.trustProvider.trustLevel >= TrustLevelEncryption {
		// Generate a random symmetric key (AES-256)
		symmetricKey := make([]byte, 32)
		if _, err := rand.Read(symmetricKey); err != nil {
			return nil, fmt.Errorf("failed to generate symmetric key: %w", err)
		}
		
		// Generate IV for AES-CBC
		iv := make([]byte, aes.BlockSize)
		if _, err := rand.Read(iv); err != nil {
			return nil, fmt.Errorf("failed to generate IV: %w", err)
		}
		
		// Encrypt the message with AES-CBC
		block, err := aes.NewCipher(symmetricKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		
		// Pad the message to block size
		blockSize := aes.BlockSize
		paddingLength := blockSize - (len(messageBytes) % blockSize)
		paddedMessage := make([]byte, len(messageBytes)+paddingLength)
		copy(paddedMessage, messageBytes)
		for i := len(messageBytes); i < len(paddedMessage); i++ {
			paddedMessage[i] = byte(paddingLength)
		}
		
		// Encrypt with CBC mode
		mode := cipher.NewCBCEncrypter(block, iv)
		encryptedMessage := make([]byte, len(paddedMessage))
		mode.CryptBlocks(encryptedMessage, paddedMessage)
		
		// Encrypt the symmetric key with RSA public key (if available)
		if t.trustProvider.publicKey != nil {
			encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, t.trustProvider.publicKey, symmetricKey, nil)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt symmetric key: %w", err)
			}
			secureMsg.EncryptedKey = encryptedKey
		}
		
		secureMsg.Message = encryptedMessage
		secureMsg.IV = iv
	}
	
	return secureMsg, nil
}

// unwrapSecureMessage unwraps a secure message, verifying signature and decrypting if needed
func (t *SecureTransport) unwrapSecureMessage(secureMsg *SecureMessage, serializer core.Serializer) (interface{}, error) {
	messageBytes := secureMsg.Message
	
	// Verify signature if present
	if secureMsg.Signature != nil {
		if err := t.trustProvider.VerifyMessage(messageBytes, secureMsg.Signature); err != nil {
			return nil, fmt.Errorf("signature verification failed: %w", err)
		}
	}
	
	// Decrypt if encrypted
	if secureMsg.EncryptedKey != nil && secureMsg.IV != nil {
		// Decrypt the symmetric key with our private key
		if t.trustProvider.privateKey == nil {
			return nil, errors.New("no private key available for decryption")
		}
		
		symmetricKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, t.trustProvider.privateKey, secureMsg.EncryptedKey, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt symmetric key: %w", err)
		}
		
		// Decrypt the message with AES-CBC
		if len(secureMsg.IV) != aes.BlockSize {
			return nil, errors.New("invalid IV size for decryption")
		}
		
		block, err := aes.NewCipher(symmetricKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher for decryption: %w", err)
		}
		
		if len(secureMsg.Message)%aes.BlockSize != 0 {
			return nil, errors.New("encrypted message is not a multiple of block size")
		}
		
		mode := cipher.NewCBCDecrypter(block, secureMsg.IV)
		decryptedMessage := make([]byte, len(secureMsg.Message))
		mode.CryptBlocks(decryptedMessage, secureMsg.Message)
		
		// Remove padding
		if len(decryptedMessage) == 0 {
			return nil, errors.New("decrypted message is empty")
		}
		
		paddingLength := int(decryptedMessage[len(decryptedMessage)-1])
		if paddingLength > len(decryptedMessage) || paddingLength == 0 {
			return nil, errors.New("invalid padding in decrypted message")
		}
		
		messageBytes = decryptedMessage[:len(decryptedMessage)-paddingLength]
	}
	
	// Deserialize the original message
	return serializer.Deserialize(messageBytes, nil)
}