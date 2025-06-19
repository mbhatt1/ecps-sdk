// Package trust provides comprehensive security management for ECPS-Go SDK
package trust

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc/credentials"
)

// Principal represents an authenticated entity
type Principal struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Roles       []string          `json:"roles"`
	Permissions map[string]bool   `json:"permissions"`
	Attributes  map[string]string `json:"attributes"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

// IsExpired checks if the principal has expired
func (p *Principal) IsExpired() bool {
	if p.ExpiresAt == nil {
		return false
	}
	return time.Now().UTC().After(*p.ExpiresAt)
}

// Authorizer interface for authorization decisions
type Authorizer interface {
	Authorize(principal *Principal, action, resource string) (bool, string)
}

// RBACAuthorizer implements role-based access control
type RBACAuthorizer struct {
	rolePermissions map[string]map[string]bool
	mutex           sync.RWMutex
}

// NewRBACAuthorizer creates a new RBAC authorizer
func NewRBACAuthorizer() *RBACAuthorizer {
	return &RBACAuthorizer{
		rolePermissions: make(map[string]map[string]bool),
	}
}

// AddRolePermission adds a permission for a role
func (r *RBACAuthorizer) AddRolePermission(role, action, resource string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	key := fmt.Sprintf("%s:%s", action, resource)

	if r.rolePermissions[role] == nil {
		r.rolePermissions[role] = make(map[string]bool)
	}

	r.rolePermissions[role][key] = true
	log.Printf("Added permission %s to role %s", key, role)
}

// Authorize checks if a principal has permission for an action on a resource
func (r *RBACAuthorizer) Authorize(principal *Principal, action, resource string) (bool, string) {
	if principal == nil {
		return false, "Principal cannot be nil"
	}

	// Check if the principal has expired
	if principal.IsExpired() {
		return false, "Principal has expired"
	}

	// Direct permission check
	permKey := fmt.Sprintf("%s:%s", action, resource)
	if principal.Permissions != nil {
		if allowed, exists := principal.Permissions[permKey]; exists && allowed {
			return true, ""
		}
	}

	// Role-based permission check
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	for _, role := range principal.Roles {
		if perms, exists := r.rolePermissions[role]; exists {
			// Exact permission match
			if allowed, exists := perms[permKey]; exists && allowed {
				return true, ""
			}

			// Wildcard resource match
			wildcardKey := fmt.Sprintf("%s:*", action)
			if allowed, exists := perms[wildcardKey]; exists && allowed {
				return true, ""
			}

			// Full wildcard match
			if allowed, exists := perms["*:*"]; exists && allowed {
				return true, ""
			}
		}
	}

	return false, fmt.Sprintf("Permission denied for action '%s' on resource '%s'", action, resource)
}

// SecurityConfig holds configuration for ECPS security features
type SecurityConfig struct {
	JWTRotationEnabled        bool          `json:"jwt_rotation_enabled"`
	JWTRotationIntervalHours  int           `json:"jwt_rotation_interval_hours"`
	MTLSEnabled               bool          `json:"mtls_enabled"`
	HSMEnabled                bool          `json:"hsm_enabled"`
	TPMEnabled                bool          `json:"tpm_enabled"`
	FuzzingEnabled            bool          `json:"fuzzing_enabled"`
	NodeIdentity              *NodeIdentity `json:"node_identity,omitempty"`
	CertDir                   string        `json:"cert_dir,omitempty"`
}

// ECPSSecurityManager provides comprehensive security management for ECPS
type ECPSSecurityManager struct {
	config       *SecurityConfig
	jwtManager   *JWTSecretManager
	mtlsTransport *MTLSTransport
	authorizer   Authorizer
	initialized  bool
	mutex        sync.RWMutex
}

// NewECPSSecurityManager creates a new security manager
func NewECPSSecurityManager(config *SecurityConfig) *ECPSSecurityManager {
	return &ECPSSecurityManager{
		config: config,
	}
}

// Initialize initializes all security components
func (s *ECPSSecurityManager) Initialize() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.initialized {
		log.Println("Security manager already initialized")
		return nil
	}

	log.Println("Initializing ECPS security components...")

	// Initialize JWT rotation
	if s.config.JWTRotationEnabled {
		if err := s.initializeJWTRotation(); err != nil {
			return fmt.Errorf("failed to initialize JWT rotation: %w", err)
		}
	}

	// Initialize mTLS
	if s.config.MTLSEnabled && s.config.NodeIdentity != nil {
		if err := s.initializeMTLS(); err != nil {
			return fmt.Errorf("failed to initialize mTLS: %w", err)
		}
	}

	// Initialize authorization
	s.initializeAuthorization()

	// Load hardware security configuration
	s.loadHardwareSecurityConfig()

	s.initialized = true
	log.Println("ECPS security initialization completed")
	return nil
}

// initializeJWTRotation initializes JWT secret rotation
func (s *ECPSSecurityManager) initializeJWTRotation() error {
	log.Println("Initializing JWT secret rotation...")

	secret, err := InitializeJWTRotation(
		s.config.JWTRotationIntervalHours,
		64, // secret length
		"HS256",
		"", // use default storage path
	)
	if err != nil {
		return err
	}

	StartJWTRotation()
	s.jwtManager = GetJWTManager()

	log.Printf("JWT rotation initialized with key_id: %s", secret.KeyID)
	return nil
}

// initializeMTLS initializes mutual TLS
func (s *ECPSSecurityManager) initializeMTLS() error {
	log.Println("Initializing mTLS...")

	_, err := InitializeMTLS(s.config.NodeIdentity, s.config.CertDir, nil)
	if err != nil {
		return err
	}

	s.mtlsTransport = GetMTLSTransport()
	log.Printf("mTLS initialized for node: %s", s.config.NodeIdentity.NodeID)
	return nil
}

// initializeAuthorization initializes the authorization system
func (s *ECPSSecurityManager) initializeAuthorization() {
	log.Println("Initializing authorization...")

	authorizer := NewRBACAuthorizer()
	s.setupDefaultPermissions(authorizer)
	s.authorizer = authorizer

	log.Println("Authorization system initialized")
}

// setupDefaultPermissions sets up default RBAC permissions
func (s *ECPSSecurityManager) setupDefaultPermissions(authorizer *RBACAuthorizer) {
	// Robot operator role
	authorizer.AddRolePermission("robot_operator", "move", "robot")
	authorizer.AddRolePermission("robot_operator", "grip", "gripper")
	authorizer.AddRolePermission("robot_operator", "sense", "sensors")

	// Robot administrator role
	authorizer.AddRolePermission("robot_admin", "move", "robot")
	authorizer.AddRolePermission("robot_admin", "grip", "gripper")
	authorizer.AddRolePermission("robot_admin", "sense", "sensors")
	authorizer.AddRolePermission("robot_admin", "configure", "robot")
	authorizer.AddRolePermission("robot_admin", "update", "firmware")

	// System administrator role
	authorizer.AddRolePermission("system_admin", "*", "*") // Full access

	log.Println("Default RBAC permissions configured")
}

// loadHardwareSecurityConfig loads HSM/TPM configuration if available
func (s *ECPSSecurityManager) loadHardwareSecurityConfig() {
	homeDir, _ := os.UserHomeDir()
	configPath := filepath.Join(homeDir, ".ecps", "hardware_security_config.json")

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Println("No hardware security configuration found")
		return
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: failed to read hardware security config: %v", err)
		return
	}

	var hwConfig map[string]interface{}
	if err := json.Unmarshal(data, &hwConfig); err != nil {
		log.Printf("Warning: failed to parse hardware security config: %v", err)
		return
	}

	if hwSecurity, ok := hwConfig["hardware_security"].(map[string]interface{}); ok {
		if hsm, ok := hwSecurity["hsm"].(map[string]interface{}); ok {
			if enabled, ok := hsm["enabled"].(bool); ok && enabled {
				s.config.HSMEnabled = true
				log.Println("HSM support enabled")
			}
		}

		if tpm, ok := hwSecurity["tpm"].(map[string]interface{}); ok {
			if enabled, ok := tpm["enabled"].(bool); ok && enabled {
				s.config.TPMEnabled = true
				log.Println("TPM support enabled")
			}
		}
	}
}

// Shutdown shuts down security components
func (s *ECPSSecurityManager) Shutdown() {
	log.Println("Shutting down ECPS security components...")

	// Stop JWT rotation
	if s.config.JWTRotationEnabled {
		StopJWTRotation()
		log.Println("JWT rotation stopped")
	}

	s.mutex.Lock()
	s.initialized = false
	s.mutex.Unlock()

	log.Println("ECPS security shutdown completed")
}

// CreateToken creates a JWT token
func (s *ECPSSecurityManager) CreateToken(payload jwt.MapClaims, expiresInHours int) (string, error) {
	if s.jwtManager == nil {
		return "", fmt.Errorf("JWT manager not initialized")
	}
	return s.jwtManager.CreateToken(payload, expiresInHours)
}

// ValidateToken validates a JWT token
func (s *ECPSSecurityManager) ValidateToken(token string) (jwt.MapClaims, error) {
	if s.jwtManager == nil {
		return nil, fmt.Errorf("JWT manager not initialized")
	}
	return s.jwtManager.ValidateToken(token)
}

// AuthorizeAction authorizes an action for a principal
func (s *ECPSSecurityManager) AuthorizeAction(principal *Principal, action, resource string) (bool, string) {
	if s.authorizer == nil {
		return false, "Authorizer not initialized"
	}
	return s.authorizer.Authorize(principal, action, resource)
}

// GetMTLSServerCredentials gets mTLS server credentials for gRPC
func (s *ECPSSecurityManager) GetMTLSServerCredentials() (credentials.TransportCredentials, error) {
	if s.mtlsTransport == nil {
		return nil, fmt.Errorf("mTLS transport not initialized")
	}
	return s.mtlsTransport.CreateGRPCServerCredentials()
}

// GetMTLSClientCredentials gets mTLS client credentials for gRPC
func (s *ECPSSecurityManager) GetMTLSClientCredentials() (credentials.TransportCredentials, error) {
	if s.mtlsTransport == nil {
		return nil, fmt.Errorf("mTLS transport not initialized")
	}
	return s.mtlsTransport.CreateGRPCClientCredentials()
}

// GetSecurityStatus gets current security status
func (s *ECPSSecurityManager) GetSecurityStatus() map[string]interface{} {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	status := map[string]interface{}{
		"initialized": s.initialized,
		"jwt_rotation": map[string]interface{}{
			"enabled":           s.config.JWTRotationEnabled,
			"manager_available": s.jwtManager != nil,
		},
		"mtls": map[string]interface{}{
			"enabled":            s.config.MTLSEnabled,
			"transport_available": s.mtlsTransport != nil,
		},
		"authorization": map[string]interface{}{
			"enabled": s.authorizer != nil,
		},
		"hardware_security": map[string]interface{}{
			"hsm_enabled": s.config.HSMEnabled,
			"tpm_enabled": s.config.TPMEnabled,
		},
	}

	// Add JWT secret status if available
	if s.jwtManager != nil {
		currentSecret := s.jwtManager.GetCurrentSecret()
		if currentSecret != nil {
			jwtStatus := status["jwt_rotation"].(map[string]interface{})
			jwtStatus["current_key_id"] = currentSecret.KeyID
			jwtStatus["expires_at"] = currentSecret.ExpiresAt.Format(time.RFC3339)
		}
	}

	return status
}

// Global security manager instance
var globalSecurityManager *ECPSSecurityManager

// InitializeSecurity initializes ECPS security with the given configuration
func InitializeSecurity(config *SecurityConfig) (*ECPSSecurityManager, error) {
	globalSecurityManager = NewECPSSecurityManager(config)
	if err := globalSecurityManager.Initialize(); err != nil {
		return nil, err
	}
	return globalSecurityManager, nil
}

// GetSecurityManager returns the global security manager instance
func GetSecurityManager() *ECPSSecurityManager {
	return globalSecurityManager
}

// ShutdownSecurity shuts down the global security manager
func ShutdownSecurity() {
	if globalSecurityManager != nil {
		globalSecurityManager.Shutdown()
		globalSecurityManager = nil
	}
}