// Package trust provides identity forwarding capabilities for ECPS.
//
// This package implements identity forwarding that allows establishing
// identity once and forwarding it through request chains, avoiding the need
// to sign every individual request.
package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// IdentityContext contains identity information that can be forwarded.
//
// This context is established once during authentication and then
// forwarded through subsequent requests without requiring re-signing.
type IdentityContext struct {
	// The authenticated identity
	Identity *Identity `json:"identity"`
	// Associated principal ID
	PrincipalID string `json:"principal_id"`
	// Session ID for this identity context
	SessionID string `json:"session_id"`
	// When this context was established
	EstablishedAt time.Time `json:"established_at"`
	// When this context expires
	ExpiresAt time.Time `json:"expires_at"`
	// Capabilities granted to this identity
	Capabilities map[string]bool `json:"capabilities"`
	// Additional context attributes
	Attributes map[string]interface{} `json:"attributes"`
}

// IsExpired checks if this context has expired.
func (ic *IdentityContext) IsExpired() bool {
	return time.Now().After(ic.ExpiresAt)
}

// TimeRemaining gets time remaining before expiration.
func (ic *IdentityContext) TimeRemaining() time.Duration {
	return time.Until(ic.ExpiresAt)
}

// HasCapability checks if this context has a specific capability.
func (ic *IdentityContext) HasCapability(capability string) bool {
	return ic.Capabilities[capability]
}

// AddCapability adds a capability to this context.
func (ic *IdentityContext) AddCapability(capability string) {
	if ic.Capabilities == nil {
		ic.Capabilities = make(map[string]bool)
	}
	ic.Capabilities[capability] = true
}

// RemoveCapability removes a capability from this context.
func (ic *IdentityContext) RemoveCapability(capability string) {
	delete(ic.Capabilities, capability)
}

// ForwardedRequest represents a request with forwarded identity context.
//
// Instead of signing each request, we forward the identity context
// that was established during initial authentication.
type ForwardedRequest struct {
	// The original request payload
	Payload interface{} `json:"payload"`
	// Forwarded identity context
	IdentityContext *IdentityContext `json:"identity_context"`
	// Request ID for tracking
	RequestID string `json:"request_id"`
	// Timestamp when request was created
	Timestamp time.Time `json:"timestamp"`
	// Chain of services this request has passed through
	ServiceChain []string `json:"service_chain"`
}

// NewForwardedRequest creates a new forwarded request.
func NewForwardedRequest(payload interface{}, identityContext *IdentityContext) *ForwardedRequest {
	return &ForwardedRequest{
		Payload:         payload,
		IdentityContext: identityContext,
		RequestID:       uuid.New().String(),
		Timestamp:       time.Now(),
		ServiceChain:    make([]string, 0),
	}
}

// AddToChain adds a service to the forwarding chain.
func (fr *ForwardedRequest) AddToChain(serviceName string) {
	fr.ServiceChain = append(fr.ServiceChain, serviceName)
}

// ToJSON converts the forwarded request to JSON.
func (fr *ForwardedRequest) ToJSON() ([]byte, error) {
	return json.Marshal(fr)
}

// FromJSON creates a forwarded request from JSON.
func (fr *ForwardedRequest) FromJSON(data []byte) error {
	return json.Unmarshal(data, fr)
}

// IdentityForwardingManager manages identity forwarding for ECPS requests.
//
// This manager handles:
// 1. Establishing identity contexts during authentication
// 2. Forwarding identity contexts through request chains
// 3. Validating forwarded contexts at each hop
// 4. Managing context lifecycle and expiration
type IdentityForwardingManager struct {
	identityProvider       *IdentityProvider
	trustProvider          *TrustProvider
	defaultSessionDuration time.Duration

	// Active identity contexts by session ID
	activeContexts map[string]*IdentityContext
	contextsMutex  sync.RWMutex

	// Context cleanup
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupDone   chan struct{}
}

// NewIdentityForwardingManager creates a new identity forwarding manager.
func NewIdentityForwardingManager(
	identityProvider *IdentityProvider,
	trustProvider *TrustProvider,
	defaultSessionDuration time.Duration,
) *IdentityForwardingManager {
	if defaultSessionDuration == 0 {
		defaultSessionDuration = 8 * time.Hour
	}

	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())

	manager := &IdentityForwardingManager{
		identityProvider:       identityProvider,
		trustProvider:          trustProvider,
		defaultSessionDuration: defaultSessionDuration,
		activeContexts:         make(map[string]*IdentityContext),
		cleanupCtx:             cleanupCtx,
		cleanupCancel:          cleanupCancel,
		cleanupDone:            make(chan struct{}),
	}

	// Start cleanup goroutine
	go manager.cleanupExpiredContexts()

	return manager
}

// cleanupExpiredContexts periodically cleans up expired contexts.
func (ifm *IdentityForwardingManager) cleanupExpiredContexts() {
	defer close(ifm.cleanupDone)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ifm.cleanupCtx.Done():
			return
		case <-ticker.C:
			ifm.contextsMutex.Lock()
			for sessionID, context := range ifm.activeContexts {
				if context.IsExpired() {
					delete(ifm.activeContexts, sessionID)
				}
			}
			ifm.contextsMutex.Unlock()
		}
	}
}

// EstablishIdentityContext establishes an identity context through authentication.
//
// This is done once at the beginning of a session, replacing
// the need to sign every individual request.
func (ifm *IdentityForwardingManager) EstablishIdentityContext(
	ctx context.Context,
	identityID string,
	credential string,
	capabilities map[string]bool,
	sessionDuration *time.Duration,
) (*IdentityContext, error) {
	// Authenticate the identity
	identity, err := ifm.identityProvider.Authenticate(ctx, identityID, credential)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}
	if identity == nil {
		return nil, fmt.Errorf("authentication failed: invalid credentials")
	}

	// Get associated principal
	principalID, err := ifm.identityProvider.IdentityToPrincipal(ctx, identity)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal: %w", err)
	}
	if principalID == "" {
		return nil, fmt.Errorf("no principal associated with identity")
	}

	// Create identity context
	sessionID := uuid.New().String()
	duration := ifm.defaultSessionDuration
	if sessionDuration != nil {
		duration = *sessionDuration
	}

	if capabilities == nil {
		capabilities = make(map[string]bool)
	}

	identityContext := &IdentityContext{
		Identity:      identity,
		PrincipalID:   principalID,
		SessionID:     sessionID,
		EstablishedAt: time.Now(),
		ExpiresAt:     time.Now().Add(duration),
		Capabilities:  capabilities,
		Attributes:    make(map[string]interface{}),
	}

	// Store active context
	ifm.contextsMutex.Lock()
	ifm.activeContexts[sessionID] = identityContext
	ifm.contextsMutex.Unlock()

	return identityContext, nil
}

// CreateForwardedRequest creates a request with forwarded identity context.
func (ifm *IdentityForwardingManager) CreateForwardedRequest(
	payload interface{},
	identityContext *IdentityContext,
) *ForwardedRequest {
	return NewForwardedRequest(payload, identityContext)
}

// ValidateForwardedRequest validates a forwarded request.
func (ifm *IdentityForwardingManager) ValidateForwardedRequest(
	ctx context.Context,
	forwardedRequest *ForwardedRequest,
	requiredCapability string,
	serviceName string,
) (bool, string) {
	context := forwardedRequest.IdentityContext

	// Check if context is expired
	if context.IsExpired() {
		return false, "Identity context has expired"
	}

	// Check if session is still active
	ifm.contextsMutex.RLock()
	storedContext, exists := ifm.activeContexts[context.SessionID]
	ifm.contextsMutex.RUnlock()

	if !exists {
		return false, "Identity session is no longer active"
	}

	// Verify context matches stored context
	if storedContext.Identity.ID != context.Identity.ID ||
		storedContext.PrincipalID != context.PrincipalID {
		return false, "Identity context mismatch"
	}

	// Check required capability
	if requiredCapability != "" && !context.HasCapability(requiredCapability) {
		return false, fmt.Sprintf("Missing required capability: %s", requiredCapability)
	}

	// Add service to chain if provided
	if serviceName != "" {
		forwardedRequest.AddToChain(serviceName)
	}

	return true, ""
}

// AuthorizeForwardedRequest authorizes a forwarded request using the trust provider.
func (ifm *IdentityForwardingManager) AuthorizeForwardedRequest(
	ctx context.Context,
	forwardedRequest *ForwardedRequest,
	action string,
	resource string,
) (bool, string, error) {
	context := forwardedRequest.IdentityContext

	// Get principal for authorization
	principal := &Principal{
		ID:   context.PrincipalID,
		Name: context.Identity.Name,
		Type: string(context.Identity.Type),
	}

	// Use trust provider for authorization
	return ifm.trustProvider.Authorize(ctx, principal, action, resource)
}

// RefreshContext refreshes an identity context to extend its lifetime.
func (ifm *IdentityForwardingManager) RefreshContext(
	sessionID string,
	additionalDuration *time.Duration,
) bool {
	ifm.contextsMutex.Lock()
	defer ifm.contextsMutex.Unlock()

	context, exists := ifm.activeContexts[sessionID]
	if !exists {
		return false
	}

	duration := ifm.defaultSessionDuration
	if additionalDuration != nil {
		duration = *additionalDuration
	}

	// Extend expiration time
	context.ExpiresAt = time.Now().Add(duration)

	return true
}

// RevokeContext revokes an identity context.
func (ifm *IdentityForwardingManager) RevokeContext(sessionID string) bool {
	ifm.contextsMutex.Lock()
	defer ifm.contextsMutex.Unlock()

	if _, exists := ifm.activeContexts[sessionID]; exists {
		delete(ifm.activeContexts, sessionID)
		return true
	}
	return false
}

// GetActiveContexts gets all active identity contexts.
func (ifm *IdentityForwardingManager) GetActiveContexts() []*IdentityContext {
	ifm.contextsMutex.RLock()
	defer ifm.contextsMutex.RUnlock()

	var contexts []*IdentityContext
	for _, context := range ifm.activeContexts {
		if !context.IsExpired() {
			contexts = append(contexts, context)
		}
	}

	return contexts
}

// GetContextBySession gets an identity context by session ID.
func (ifm *IdentityForwardingManager) GetContextBySession(sessionID string) *IdentityContext {
	ifm.contextsMutex.RLock()
	defer ifm.contextsMutex.RUnlock()

	context, exists := ifm.activeContexts[sessionID]
	if exists && !context.IsExpired() {
		return context
	}
	return nil
}

// Shutdown shuts down the identity forwarding manager.
func (ifm *IdentityForwardingManager) Shutdown() {
	ifm.cleanupCancel()
	<-ifm.cleanupDone

	ifm.contextsMutex.Lock()
	ifm.activeContexts = make(map[string]*IdentityContext)
	ifm.contextsMutex.Unlock()
}

// CreateDefaultIdentityForwardingManager creates a default identity forwarding manager.
func CreateDefaultIdentityForwardingManager(
	identityProvider *IdentityProvider,
	trustProvider *TrustProvider,
) *IdentityForwardingManager {
	return NewIdentityForwardingManager(
		identityProvider,
		trustProvider,
		8*time.Hour,
	)
}