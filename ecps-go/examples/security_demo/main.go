// Package main demonstrates ECPS-Go security hardening features
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ecps/ecps-go/pkg/trust"
)

func main() {
	log.Println("Starting ECPS-Go Security Hardening Demo")

	// Create node identity
	nodeIdentity := &trust.NodeIdentity{
		NodeID:             "demo_robot_001",
		CommonName:         "demo-robot-001.local",
		Organization:       "ECPS Demo",
		OrganizationalUnit: "Demo Robots",
		Country:            "US",
		State:              "California",
		Locality:           "San Francisco",
		DNSNames:           []string{"demo-robot-001.local"},
		IPAddresses:        []string{"127.0.0.1"},
	}

	// Create security configuration
	config := &trust.SecurityConfig{
		JWTRotationEnabled:       true,
		JWTRotationIntervalHours: 24,
		MTLSEnabled:              true,
		HSMEnabled:               false, // Disabled for demo
		TPMEnabled:               false, // Disabled for demo
		FuzzingEnabled:           true,
		NodeIdentity:             nodeIdentity,
	}

	// Initialize security
	log.Println("Initializing security components...")
	securityManager, err := trust.InitializeSecurity(config)
	if err != nil {
		log.Fatalf("Failed to initialize security: %v", err)
	}
	defer trust.ShutdownSecurity()

	log.Println("Security initialization completed")

	// Run demos
	demoSecurityStatus(securityManager)
	demoJWTRotation(securityManager)
	demoMTLS(securityManager)
	demoAuthorization(securityManager)

	log.Println("All demos completed successfully")
}

// demoSecurityStatus shows security system status
func demoSecurityStatus(securityManager *trust.ECPSSecurityManager) {
	log.Println("=== Security Status ===")

	status := securityManager.GetSecurityStatus()

	log.Printf("Security Component Status:")
	log.Printf("  Initialized: %v", status["initialized"])
	log.Printf("  JWT Rotation: %v", status["jwt_rotation"])
	log.Printf("  mTLS: %v", status["mtls"])
	log.Printf("  Authorization: %v", status["authorization"])
	log.Printf("  Hardware Security: %v", status["hardware_security"])
}

// demoJWTRotation demonstrates JWT secret rotation
func demoJWTRotation(securityManager *trust.ECPSSecurityManager) {
	log.Println("=== JWT Secret Rotation Demo ===")

	// Create a token
	payload := jwt.MapClaims{
		"user_id":     "robot_001",
		"roles":       []string{"robot_operator"},
		"permissions": map[string]bool{"move:robot": true},
	}

	token, err := securityManager.CreateToken(payload, 1)
	if err != nil {
		log.Printf("Failed to create token: %v", err)
		return
	}

	log.Printf("Created JWT token: %s...", token[:50])

	// Validate the token
	decoded, err := securityManager.ValidateToken(token)
	if err != nil {
		log.Printf("Token validation failed: %v", err)
		return
	}

	log.Printf("Token validated successfully: %v", decoded["user_id"])

	// Show current secret info
	jwtManager := trust.GetJWTManager()
	if jwtManager != nil {
		currentSecret := jwtManager.GetCurrentSecret()
		if currentSecret != nil {
			log.Printf("Current secret key_id: %s", currentSecret.KeyID)
			log.Printf("Secret expires at: %s", currentSecret.ExpiresAt.Format(time.RFC3339))
		}
	}
}

// demoMTLS demonstrates mTLS functionality
func demoMTLS(securityManager *trust.ECPSSecurityManager) {
	log.Println("=== mTLS Demo ===")

	// Get server credentials
	serverCreds, err := securityManager.GetMTLSServerCredentials()
	if err != nil {
		log.Printf("Failed to get server credentials: %v", err)
		return
	}

	log.Printf("mTLS server credentials created successfully: %T", serverCreds)

	// Get client credentials
	clientCreds, err := securityManager.GetMTLSClientCredentials()
	if err != nil {
		log.Printf("Failed to get client credentials: %v", err)
		return
	}

	log.Printf("mTLS client credentials created successfully: %T", clientCreds)
	log.Println("mTLS is ready for secure communication")
}

// demoAuthorization demonstrates authorization system
func demoAuthorization(securityManager *trust.ECPSSecurityManager) {
	log.Println("=== Authorization Demo ===")

	// Create test principals
	robotOperator := &trust.Principal{
		ID:          "user_001",
		Name:        "Robot Operator",
		Roles:       []string{"robot_operator"},
		Permissions: map[string]bool{},
	}

	robotAdmin := &trust.Principal{
		ID:          "admin_001",
		Name:        "Robot Administrator",
		Roles:       []string{"robot_admin"},
		Permissions: map[string]bool{},
	}

	// Test authorization
	testCases := []struct {
		principal *trust.Principal
		action    string
		resource  string
	}{
		{robotOperator, "move", "robot"},
		{robotOperator, "configure", "robot"}, // Should fail
		{robotAdmin, "move", "robot"},
		{robotAdmin, "configure", "robot"},
	}

	for _, tc := range testCases {
		authorized, reason := securityManager.AuthorizeAction(tc.principal, tc.action, tc.resource)
		status := "ALLOWED"
		if !authorized {
			status = "DENIED"
		}

		log.Printf("%s: %s on %s -> %s", tc.principal.Name, tc.action, tc.resource, status)
		if reason != "" {
			log.Printf("  Reason: %s", reason)
		}
	}
}