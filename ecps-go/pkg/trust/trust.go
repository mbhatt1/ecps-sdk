// Package trust provides security and trust mechanisms for the ECPS protocol stack.
package trust

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/ecps/ecps-go/pkg/core"
)

// TrustLevel defines the level of trust required for communication
type TrustLevel int

const (
	// TrustLevelNone requires no security (not recommended for production)
	TrustLevelNone TrustLevel = iota
	
	// TrustLevelEncryption requires encrypted transport only
	TrustLevelEncryption
	
	// TrustLevelAuthenticated requires encryption and authentication
	TrustLevelAuthenticated
	
	// TrustLevelAuthorized requires encryption, authentication, and authorization
	TrustLevelAuthorized
	
	// TrustLevelAudited requires encryption, authentication, authorization, and auditing
	TrustLevelAudited
)

// TrustMechanism defines the security mechanism used
type TrustMechanism int

const (
	// TrustMechanismTLS uses TLS/SSL for transport security
	TrustMechanismTLS TrustMechanism = iota
	
	// TrustMechanismJWT uses JSON Web Tokens for authentication
	TrustMechanismJWT
	
	// TrustMechanismOAuth uses OAuth 2.0 for authentication and authorization
	TrustMechanismOAuth
	
	// TrustMechanismMTLS uses Mutual TLS for authentication
	TrustMechanismMTLS
)

// Principal represents an authenticated entity
type Principal struct {
	ID          string
	Name        string
	Roles       []string
	Permissions map[string]bool
	Attributes  map[string]string
	ExpiresAt   time.Time
}

// TrustProvider provides security services for ECPS
type TrustProvider struct {
	trustLevel    TrustLevel
	mechanisms    []TrustMechanism
	privateKey    *rsa.PrivateKey
	publicKey     *rsa.PublicKey
	tlsConfig     *tls.Config
	certificates  *x509.CertPool
	principals    map[string]*Principal
	jwtSecret     []byte
	authorizer    Authorizer
	principalLock sync.RWMutex
	logger        core.Logger
	telemetry     core.Telemetry
}

// Authorizer is an interface for authorization decisions
type Authorizer interface {
	// Authorize checks if a principal has permission for an action on a resource
	Authorize(ctx context.Context, principal *Principal, action string, resource string) (bool, error)
}

// RBACAuthorizer implements role-based access control
type RBACAuthorizer struct {
	rolePermissions map[string]map[string]bool
}

// NewRBACAuthorizer creates a new role-based access control authorizer
func NewRBACAuthorizer() *RBACAuthorizer {
	return &RBACAuthorizer{
		rolePermissions: make(map[string]map[string]bool),
	}
}

// AddRolePermission adds a permission for a role
func (a *RBACAuthorizer) AddRolePermission(role string, action string, resource string) {
	key := fmt.Sprintf("%s:%s", action, resource)
	
	if a.rolePermissions[role] == nil {
		a.rolePermissions[role] = make(map[string]bool)
	}
	
	a.rolePermissions[role][key] = true
}

// Authorize implements the Authorizer interface
func (a *RBACAuthorizer) Authorize(ctx context.Context, principal *Principal, action string, resource string) (bool, error) {
	if principal == nil {
		return false, errors.New("principal cannot be nil")
	}
	
	// Check if the principal has expired
	if !principal.ExpiresAt.IsZero() && principal.ExpiresAt.Before(time.Now()) {
		return false, errors.New("principal has expired")
	}
	
	// Direct permission check
	permKey := fmt.Sprintf("%s:%s", action, resource)
	if principal.Permissions != nil && principal.Permissions[permKey] {
		return true, nil
	}
	
	// Role-based permission check
	for _, role := range principal.Roles {
		perms, exists := a.rolePermissions[role]
		if exists && perms[permKey] {
			return true, nil
		}
		
		// Check for wildcard permissions
		wildcardKey := fmt.Sprintf("%s:*", action)
		if perms[wildcardKey] {
			return true, nil
		}
	}
	
	return false, nil
}

// TrustOption configures a TrustProvider
type TrustOption func(*TrustProvider) error

// WithTrustLevel sets the trust level
func WithTrustLevel(level TrustLevel) TrustOption {
	return func(p *TrustProvider) error {
		p.trustLevel = level
		return nil
	}
}

// WithTrustMechanisms sets the trust mechanisms
func WithTrustMechanisms(mechanisms ...TrustMechanism) TrustOption {
	return func(p *TrustProvider) error {
		p.mechanisms = mechanisms
		return nil
	}
}

// WithPrivateKeyFile loads a private key from a PEM file
func WithPrivateKeyFile(path string) TrustOption {
	return func(p *TrustProvider) error {
		keyBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read private key file: %w", err)
		}
		
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			return errors.New("failed to decode PEM block containing private key")
		}
		
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
		
		p.privateKey = key
		p.publicKey = &key.PublicKey
		return nil
	}
}

// WithPublicKeyFile loads a public key from a PEM file
func WithPublicKeyFile(path string) TrustOption {
	return func(p *TrustProvider) error {
		keyBytes, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read public key file: %w", err)
		}
		
		block, _ := pem.Decode(keyBytes)
		if block == nil {
			return errors.New("failed to decode PEM block containing public key")
		}
		
		key, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
		
		p.publicKey = key
		return nil
	}
}

// WithTLSConfig sets the TLS configuration
func WithTLSConfig(config *tls.Config) TrustOption {
	return func(p *TrustProvider) error {
		p.tlsConfig = config
		return nil
	}
}

// WithJWTSecret sets the JWT secret
func WithJWTSecret(secret string) TrustOption {
	return func(p *TrustProvider) error {
		p.jwtSecret = []byte(secret)
		return nil
	}
}

// WithAuthorizer sets the authorizer
func WithAuthorizer(authorizer Authorizer) TrustOption {
	return func(p *TrustProvider) error {
		p.authorizer = authorizer
		return nil
	}
}

// NewTrustProvider creates a new TrustProvider
func NewTrustProvider(logger core.Logger, telemetry core.Telemetry, options ...TrustOption) (*TrustProvider, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}
	
	provider := &TrustProvider{
		trustLevel:   TrustLevelNone,
		mechanisms:   []TrustMechanism{},
		principals:   make(map[string]*Principal),
		certificates: x509.NewCertPool(),
		authorizer:   NewRBACAuthorizer(),
		logger:       logger,
		telemetry:    telemetry,
	}
	
	// Apply options
	for _, opt := range options {
		if err := opt(provider); err != nil {
			return nil, err
		}
	}
	
	// Generate keys if not provided
	if provider.trustLevel > TrustLevelEncryption && provider.privateKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		provider.privateKey = key
		provider.publicKey = &key.PublicKey
		logger.Info("Generated temporary RSA key pair")
	}
	
	// Generate JWT secret if not provided
	if provider.trustLevel > TrustLevelEncryption && provider.mechanisms != nil &&
		contains(provider.mechanisms, TrustMechanismJWT) && len(provider.jwtSecret) == 0 {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate JWT secret: %w", err)
		}
		provider.jwtSecret = secret
		logger.Info("Generated temporary JWT secret")
	}
	
	return provider, nil
}

// AddCertificate adds a trusted certificate
func (p *TrustProvider) AddCertificate(certPEM []byte) error {
	if !p.certificates.AppendCertsFromPEM(certPEM) {
		return errors.New("failed to add certificate")
	}
	return nil
}

// AddCertificateFromFile adds a trusted certificate from a file
func (p *TrustProvider) AddCertificateFromFile(path string) error {
	certBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %w", err)
	}
	return p.AddCertificate(certBytes)
}

// AddPrincipal adds a principal
func (p *TrustProvider) AddPrincipal(principal *Principal) {
	p.principalLock.Lock()
	defer p.principalLock.Unlock()
	p.principals[principal.ID] = principal
	p.logger.Debug("Added principal: %s", principal.ID)
}

// GetPrincipal gets a principal by ID
func (p *TrustProvider) GetPrincipal(id string) (*Principal, bool) {
	p.principalLock.RLock()
	defer p.principalLock.RUnlock()
	principal, exists := p.principals[id]
	return principal, exists
}

// CreateJWT creates a JSON Web Token for a principal
func (p *TrustProvider) CreateJWT(principal *Principal, expiresIn time.Duration) (string, error) {
	if p.jwtSecret == nil && p.privateKey == nil {
		return "", errors.New("no JWT secret or private key available")
	}
	
	// Set expiration time if not already set
	expiresAt := principal.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().Add(expiresIn)
	}
	
	// Create claims
	claims := jwt.MapClaims{
		"sub":  principal.ID,
		"name": principal.Name,
		"exp":  expiresAt.Unix(),
	}
	
	// Add roles and permissions
	if len(principal.Roles) > 0 {
		claims["roles"] = strings.Join(principal.Roles, ",")
	}
	
	// Add custom attributes
	for k, v := range principal.Attributes {
		claims[k] = v
	}
	
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	
	// Sign token
	if p.jwtSecret != nil {
		return token.SignedString(p.jwtSecret)
	}
	
	// Use RSA signing if no JWT secret
	token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(p.privateKey)
}

// ValidateJWT validates a JSON Web Token and returns the principal
func (p *TrustProvider) ValidateJWT(tokenString string) (*Principal, error) {
	// Parse token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Check signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			return p.jwtSecret, nil
		} else if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			return p.publicKey, nil
		}
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	})
	
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}
	
	// Validate token
	if !token.Valid {
		return nil, errors.New("invalid token")
	}
	
	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid claims")
	}
	
	// Check expiration
	exp, ok := claims["exp"].(float64)
	if !ok {
		return nil, errors.New("invalid expiration claim")
	}
	
	expiresAt := time.Unix(int64(exp), 0)
	if time.Now().After(expiresAt) {
		return nil, errors.New("token has expired")
	}
	
	// Create principal
	principal := &Principal{
		ID:         claims["sub"].(string),
		ExpiresAt:  expiresAt,
		Attributes: make(map[string]string),
	}
	
	// Extract name
	if name, ok := claims["name"].(string); ok {
		principal.Name = name
	}
	
	// Extract roles
	if roles, ok := claims["roles"].(string); ok && roles != "" {
		principal.Roles = strings.Split(roles, ",")
	}
	
	// Extract other attributes
	for k, v := range claims {
		if k != "sub" && k != "exp" && k != "name" && k != "roles" {
			if strVal, ok := v.(string); ok {
				principal.Attributes[k] = strVal
			}
		}
	}
	
	return principal, nil
}

// SignMessage signs a message using the private key
func (p *TrustProvider) SignMessage(message []byte) ([]byte, error) {
	if p.privateKey == nil {
		return nil, errors.New("no private key available")
	}
	
	// Create hash
	hash := sha256.Sum256(message)
	
	// Sign hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, p.privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}
	
	return signature, nil
}

// VerifyMessage verifies a message signature using the public key
func (p *TrustProvider) VerifyMessage(message, signature []byte) error {
	if p.publicKey == nil {
		return errors.New("no public key available")
	}
	
	// Create hash
	hash := sha256.Sum256(message)
	
	// Verify signature
	return rsa.VerifyPKCS1v15(p.publicKey, crypto.SHA256, hash[:], signature)
}

// Authenticate authenticates a principal using credentials
func (p *TrustProvider) Authenticate(ctx context.Context, id string, credential string) (*Principal, error) {
	// Create a span if telemetry is available
	var span trace.Span
	if p.telemetry != nil {
		_, span = p.telemetry.CreateSpan(ctx, "trust.authenticate", trace.SpanKindInternal, map[string]interface{}{
			"principal_id": id,
		})
		defer span.End()
	}
	
	// Check if credential is a JWT
	if strings.HasPrefix(credential, "Bearer ") {
		token := strings.TrimPrefix(credential, "Bearer ")
		principal, err := p.ValidateJWT(token)
		if err != nil {
			p.logger.Error("JWT validation failed: %v", err)
			if span != nil {
				span.RecordError(err)
			}
			return nil, err
		}
		return principal, nil
	}
	
	// Look up principal
	principal, exists := p.GetPrincipal(id)
	if !exists {
		err := errors.New("principal not found")
		if span != nil {
			span.RecordError(err)
		}
		return nil, err
	}
	
	// In a real implementation, you'd validate the credential against stored credentials
	// Validate the credential against stored credentials
	// This would typically involve checking against a database or identity provider
	
	// Check if we have an identity store to validate credentials
	if p.identityStore != nil {
		isValid, err := p.identityStore.VerifyCredential(principal.ID, credential)
		if err != nil {
			err = fmt.Errorf("error validating credential for principal %s: %w", principal.ID, err)
			if span != nil {
				span.RecordError(err)
			}
			return nil, err
		}
		if !isValid {
			err = fmt.Errorf("invalid credential for principal %s", principal.ID)
			if span != nil {
				span.RecordError(err)
			}
			return nil, err
		}
	} else {
		// Fallback: simple credential check (not recommended for production)
		// This is just for backward compatibility
		
		// In a real implementation, you would never store plaintext credentials
		// This is just for demonstration purposes
		if storedCredential, exists := p.credentials[principal.ID]; exists {
			if storedCredential != credential {
				err = fmt.Errorf("credential mismatch for principal %s", principal.ID)
				if span != nil {
					span.RecordError(err)
				}
				return nil, err
			}
		} else {
			err = fmt.Errorf("no stored credential found for principal %s", principal.ID)
			if span != nil {
				span.RecordError(err)
			}
			return nil, err
		}
	}
	
	// Update last authenticated time
	now := time.Now()
	principal.LastAuthenticated = &now
	
	return principal, nil
}

// Authorize checks if a principal has permission for an action on a resource
func (p *TrustProvider) Authorize(ctx context.Context, principal *Principal, action string, resource string) (bool, error) {
	// Create a span if telemetry is available
	var span trace.Span
	if p.telemetry != nil {
		_, span = p.telemetry.CreateSpan(ctx, "trust.authorize", trace.SpanKindInternal, map[string]interface{}{
			"principal_id": principal.ID,
			"action":       action,
			"resource":     resource,
		})
		defer span.End()
	}
	
	// Check if authorization is required
	if p.trustLevel < TrustLevelAuthorized {
		return true, nil
	}
	
	// Use authorizer if available
	if p.authorizer != nil {
		authorized, err := p.authorizer.Authorize(ctx, principal, action, resource)
		if err != nil {
			if span != nil {
				span.RecordError(err)
			}
			return false, err
		}
		
		// Record authorization result in telemetry
		if span != nil {
			span.SetAttributes(map[string]interface{}{
				"authorized": authorized,
			})
		}
		
		return authorized, nil
	}
	
	// Default deny if no authorizer
	return false, nil
}

// EncryptMessage encrypts a message using the public key
func (p *TrustProvider) EncryptMessage(message []byte) ([]byte, error) {
	if p.publicKey == nil {
		return nil, errors.New("no public key available")
	}
	
	return rsa.EncryptOAEP(sha256.New(), rand.Reader, p.publicKey, message, nil)
}

// DecryptMessage decrypts a message using the private key
func (p *TrustProvider) DecryptMessage(ciphertext []byte) ([]byte, error) {
	if p.privateKey == nil {
		return nil, errors.New("no private key available")
	}
	
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, p.privateKey, ciphertext, nil)
}

// SecureTransport wraps a transport with security features
func (p *TrustProvider) SecureTransport(transport core.Transport) (core.Transport, error) {
	// If no security required, return the original transport
	if p.trustLevel == TrustLevelNone {
		return transport, nil
	}
	
	// Create a secure transport wrapper
	return NewSecureTransport(transport, p), nil
}

// Helper function to check if a slice contains an item
func contains(slice []TrustMechanism, item TrustMechanism) bool {
	for _, v := range slice {
		if v == item {
			return true
		}
	}
	return false
}