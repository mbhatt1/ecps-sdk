// Package trust provides security and trust mechanisms for the ECPS protocol stack.
package trust

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
)

// IdentityType defines the type of identity
type IdentityType string

const (
	// IdentityTypeUser represents a human user
	IdentityTypeUser IdentityType = "user"

	// IdentityTypeService represents a service or application
	IdentityTypeService IdentityType = "service"

	// IdentityTypeDevice represents an IoT device
	IdentityTypeDevice IdentityType = "device"

	// IdentityTypeRobot represents a robot
	IdentityTypeRobot IdentityType = "robot"
)

// Identity represents an entity that can be authenticated
type Identity struct {
	ID              string
	Name            string
	Type            IdentityType
	CreatedAt       time.Time
	LastAuthenticated *time.Time
	Attributes      map[string]string
	Enabled         bool
}

// IsUser checks if this is a user identity
func (i *Identity) IsUser() bool {
	return i.Type == IdentityTypeUser
}

// IsService checks if this is a service identity
func (i *Identity) IsService() bool {
	return i.Type == IdentityTypeService
}

// IsDevice checks if this is a device identity
func (i *Identity) IsDevice() bool {
	return i.Type == IdentityTypeDevice
}

// IsRobot checks if this is a robot identity
func (i *Identity) IsRobot() bool {
	return i.Type == IdentityTypeRobot
}

// IdentityStore manages identities and their credentials
type IdentityStore struct {
	identities       map[string]*Identity
	credentials      map[string]string // Simple credential store (id -> password)
	identityPrincipals map[string]string // Mapping from identity ID to principal ID
	mu               sync.RWMutex
}

// NewIdentityStore creates a new identity store
func NewIdentityStore() *IdentityStore {
	return &IdentityStore{
		identities:       make(map[string]*Identity),
		credentials:      make(map[string]string),
		identityPrincipals: make(map[string]string),
	}
}

// CreateIdentity creates a new identity
func (s *IdentityStore) CreateIdentity(name string, idType IdentityType, attributes map[string]string, id string) (*Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate ID if not provided
	identityID := id
	if identityID == "" {
		identityID = fmt.Sprintf("%s-%s", idType, uuid.New().String())
	}

	// Check if identity already exists
	if _, exists := s.identities[identityID]; exists {
		return nil, fmt.Errorf("identity with ID %s already exists", identityID)
	}

	// Create new identity
	identity := &Identity{
		ID:         identityID,
		Name:       name,
		Type:       idType,
		CreatedAt:  time.Now(),
		Attributes: attributes,
		Enabled:    true,
	}

	s.identities[identityID] = identity
	return identity, nil
}

// GetIdentity gets an identity by ID
func (s *IdentityStore) GetIdentity(id string) (*Identity, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	identity, exists := s.identities[id]
	if !exists {
		return nil, fmt.Errorf("identity not found: %s", id)
	}

	return identity, nil
}

// UpdateIdentity updates an existing identity
func (s *IdentityStore) UpdateIdentity(identity *Identity) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[identity.ID]; !exists {
		return fmt.Errorf("identity not found: %s", identity.ID)
	}

	s.identities[identity.ID] = identity
	return nil
}

// DeleteIdentity deletes an identity
func (s *IdentityStore) DeleteIdentity(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[id]; !exists {
		return fmt.Errorf("identity not found: %s", id)
	}

	delete(s.identities, id)
	delete(s.credentials, id)
	delete(s.identityPrincipals, id)
	return nil
}

// SetCredential sets a credential for an identity
func (s *IdentityStore) SetCredential(identityID string, credential string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[identityID]; !exists {
		return fmt.Errorf("identity not found: %s", identityID)
	}

	// Generate a random salt
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash the credential using PBKDF2 with SHA-256
	hashedCredential := pbkdf2.Key([]byte(credential), salt, 100000, 32, sha256.New)

	// Store salt + hash
	storedCredential := make([]byte, 64)
	copy(storedCredential[:32], salt)
	copy(storedCredential[32:], hashedCredential)

	s.credentials[identityID] = string(storedCredential)
	return nil
}

// VerifyCredential verifies a credential for an identity
func (s *IdentityStore) VerifyCredential(identityID string, credential string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	identity, exists := s.identities[identityID]
	if !exists {
		return false, fmt.Errorf("identity not found: %s", identityID)
	}

	if !identity.Enabled {
		return false, errors.New("identity is disabled")
	}

	storedCredential, exists := s.credentials[identityID]
	if !exists {
		return false, errors.New("no credential set for identity")
	}

	// Extract salt and hash from stored credential
	storedBytes := []byte(storedCredential)
	if len(storedBytes) < 64 { // 32 bytes salt + 32 bytes hash
		return false, errors.New("invalid stored credential format")
	}

	salt := storedBytes[:32]
	storedHash := storedBytes[32:]

	// Hash the provided credential with the same salt
	candidateHash := pbkdf2.Key([]byte(credential), salt, 100000, 32, sha256.New)

	// Use constant-time comparison to prevent timing attacks
	isValid := subtle.ConstantTimeCompare(storedHash, candidateHash) == 1

	// Update last authenticated time if valid
	if isValid {
		now := time.Now()
		identity.LastAuthenticated = &now
		s.identities[identityID] = identity
	}

	return isValid, nil
}

// AssociatePrincipal associates an identity with a principal
func (s *IdentityStore) AssociatePrincipal(identityID string, principalID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.identities[identityID]; !exists {
		return fmt.Errorf("identity not found: %s", identityID)
	}

	s.identityPrincipals[identityID] = principalID
	return nil
}

// GetPrincipalID gets the principal ID associated with an identity
func (s *IdentityStore) GetPrincipalID(identityID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	principalID, exists := s.identityPrincipals[identityID]
	if !exists {
		return "", fmt.Errorf("no principal associated with identity: %s", identityID)
	}

	return principalID, nil
}

// ListIdentities lists all identities, optionally filtered by type
func (s *IdentityStore) ListIdentities(idType *IdentityType) []*Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var identities []*Identity
	for _, identity := range s.identities {
		if idType == nil || identity.Type == *idType {
			identities = append(identities, identity)
		}
	}

	return identities
}

// IdentityProvider manages identity authentication and integration with external providers
type IdentityProvider struct {
	identityStore *IdentityStore
	jwtSecret     []byte
	trustProvider *TrustProvider
}

// NewIdentityProvider creates a new identity provider
func NewIdentityProvider(identityStore *IdentityStore, jwtSecret string, trustProvider *TrustProvider) *IdentityProvider {
	return &IdentityProvider{
		identityStore: identityStore,
		jwtSecret:     []byte(jwtSecret),
		trustProvider: trustProvider,
	}
}

// Authenticate authenticates an identity using credentials
func (p *IdentityProvider) Authenticate(ctx context.Context, identityID string, credential string) (*Identity, error) {
	// Verify the credential
	isValid, err := p.identityStore.VerifyCredential(identityID, credential)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, errors.New("invalid credentials")
	}

	// Get the identity
	identity, err := p.identityStore.GetIdentity(identityID)
	if err != nil {
		return nil, err
	}

	// Check if the identity is enabled
	if !identity.Enabled {
		return nil, errors.New("identity is disabled")
	}

	return identity, nil
}

// CreateIdentityToken creates a JWT token for an identity
func (p *IdentityProvider) CreateIdentityToken(identity *Identity, expiresIn time.Duration) (string, error) {
	if len(p.jwtSecret) == 0 {
		return "", errors.New("no JWT secret available")
	}

	// Set expiration time
	claims := jwt.MapClaims{
		"sub":  identity.ID,
		"name": identity.Name,
		"type": string(identity.Type),
	}

	if expiresIn > 0 {
		claims["exp"] = time.Now().Add(expiresIn).Unix()
	}

	// Add custom attributes
	for k, v := range identity.Attributes {
		claims[k] = v
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(p.jwtSecret)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return tokenString, nil
}

// ValidateIdentityToken validates a JWT token and extracts the identity
func (p *IdentityProvider) ValidateIdentityToken(tokenString string) (*Identity, error) {
	if len(p.jwtSecret) == 0 {
		return nil, errors.New("no JWT secret available")
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract identity information
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Get subject (identity ID)
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, errors.New("missing subject claim in token")
	}

	// Get the stored identity
	identity, err := p.identityStore.GetIdentity(sub)
	if err != nil {
		return nil, err
	}

	// Update last authenticated time
	now := time.Now()
	identity.LastAuthenticated = &now
	err = p.identityStore.UpdateIdentity(identity)
	if err != nil {
		return nil, err
	}

	return identity, nil
}

// IdentityToPrincipal converts an identity to a principal
func (p *IdentityProvider) IdentityToPrincipal(ctx context.Context, identity *Identity) (*Principal, error) {
	principalID, err := p.identityStore.GetPrincipalID(identity.ID)
	if err != nil {
		return nil, err
	}

	principal := p.trustProvider.GetPrincipal(principalID)
	if principal == nil {
		return nil, fmt.Errorf("principal not found: %s", principalID)
	}

	return principal, nil
}

// CreateDefaultIdentityProvider creates a default identity store and provider with sample identities
func CreateDefaultIdentityProvider(trustProvider *TrustProvider) (*IdentityStore, *IdentityProvider, error) {
	// Create identity store
	identityStore := NewIdentityStore()

	// Create identity provider
	identityProvider := NewIdentityProvider(
		identityStore,
		"default-identity-jwt-secret",
		trustProvider,
	)

	// Create sample user identity
	userAttrs := map[string]string{"email": "user@example.com"}
	user, err := identityStore.CreateIdentity("Sample User", IdentityTypeUser, userAttrs, "")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.SetCredential(user.ID, "password123")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.AssociatePrincipal(user.ID, "user1")
	if err != nil {
		return nil, nil, err
	}

	// Create sample service identity
	serviceAttrs := map[string]string{"service_type": "api"}
	service, err := identityStore.CreateIdentity("API Service", IdentityTypeService, serviceAttrs, "")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.SetCredential(service.ID, "service-api-key")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.AssociatePrincipal(service.ID, "service1")
	if err != nil {
		return nil, nil, err
	}

	// Create sample device identity
	deviceAttrs := map[string]string{"device_type": "sensor", "location": "lab"}
	device, err := identityStore.CreateIdentity("IoT Sensor", IdentityTypeDevice, deviceAttrs, "")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.SetCredential(device.ID, "device-secret")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.AssociatePrincipal(device.ID, "device1")
	if err != nil {
		return nil, nil, err
	}

	// Create sample robot identity
	robotAttrs := map[string]string{"model": "UR5", "location": "factory"}
	robot, err := identityStore.CreateIdentity("Robot Arm", IdentityTypeRobot, robotAttrs, "")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.SetCredential(robot.ID, "robot-token")
	if err != nil {
		return nil, nil, err
	}
	err = identityStore.AssociatePrincipal(robot.ID, "robot1")
	if err != nil {
		return nil, nil, err
	}

	return identityStore, identityProvider, nil
}