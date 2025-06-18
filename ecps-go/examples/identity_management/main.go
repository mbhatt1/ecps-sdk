package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ecps/ecps-go/pkg/trust"
)

func main() {
	log.Println("=== ECPS Go SDK Identity Management Demo ===")

	// Set up trust system
	trustSystem, err := setupTrustSystem()
	if err != nil {
		log.Fatalf("Failed to set up trust system: %v", err)
	}

	// Create identities
	identities, err := createIdentities(trustSystem.identityStore)
	if err != nil {
		log.Fatalf("Failed to create identities: %v", err)
	}

	// Authenticate identities
	err = authenticateIdentities(trustSystem.identityProvider, identities)
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Identity management operations
	err = identityManagementOperations(trustSystem.identityStore, trustSystem.identityProvider)
	if err != nil {
		log.Fatalf("Identity management operations failed: %v", err)
	}

	log.Println("\nIdentity management demo completed successfully!")
}

// TrustSystem holds all components of the trust system
type TrustSystem struct {
	trustProvider    *trust.TrustProvider
	identityStore    *trust.IdentityStore
	identityProvider *trust.IdentityProvider
}

// Identities holds all created identities
type Identities struct {
	user    *trust.Identity
	service *trust.Identity
	device  *trust.Identity
	robot   *trust.Identity
}

func setupTrustSystem() (*TrustSystem, error) {
	log.Println("Setting up trust system...")

	// Create RBAC authorizer
	authorizer := trust.NewRBACAuthorizer()

	// Add permissions for roles
	authorizer.AddRolePermission("admin", "manage", "identities")
	authorizer.AddRolePermission("admin", "read", "all_data")
	authorizer.AddRolePermission("admin", "write", "all_data")
	authorizer.AddRolePermission("user", "read", "user_data")
	authorizer.AddRolePermission("user", "write", "user_data")
	authorizer.AddRolePermission("device", "write", "sensor_data")
	authorizer.AddRolePermission("robot", "control", "actuators")

	// Create trust provider
	trustProvider := &trust.TrustProvider{
		TrustLevel: trust.TrustLevelAuthorized,
		Mechanisms: []trust.TrustMechanism{trust.TrustMechanismJWT},
		JWTSecret:  []byte("demo-jwt-secret"),
		Authorizer: authorizer,
	}

	// Create principals
	adminPrincipal := &trust.Principal{
		ID:    "admin1",
		Name:  "Administrator",
		Roles: []string{"admin"},
		Permissions: map[string]bool{
			"manage:system": true,
		},
	}
	trustProvider.AddPrincipal(adminPrincipal)

	userPrincipal := &trust.Principal{
		ID:    "user1",
		Name:  "Regular User",
		Roles: []string{"user"},
		Permissions: map[string]bool{},
	}
	trustProvider.AddPrincipal(userPrincipal)

	devicePrincipal := &trust.Principal{
		ID:    "device1",
		Name:  "IoT Sensor",
		Roles: []string{"device"},
		Permissions: map[string]bool{},
	}
	trustProvider.AddPrincipal(devicePrincipal)

	robotPrincipal := &trust.Principal{
		ID:    "robot1",
		Name:  "Robot Arm",
		Roles: []string{"robot"},
		Permissions: map[string]bool{},
	}
	trustProvider.AddPrincipal(robotPrincipal)

	// Create identity store
	identityStore := trust.NewIdentityStore()

	// Create identity provider
	identityProvider := trust.NewIdentityProvider(
		identityStore,
		"demo-jwt-secret",
		trustProvider,
	)

	return &TrustSystem{
		trustProvider:    trustProvider,
		identityStore:    identityStore,
		identityProvider: identityProvider,
	}, nil
}

func createIdentities(identityStore *trust.IdentityStore) (*Identities, error) {
	log.Println("Creating different types of identities...")

	// Create user identity
	userAttrs := map[string]string{
		"email":      "john.doe@example.com",
		"department": "Engineering",
	}
	user, err := identityStore.CreateIdentity("John Doe", trust.IdentityTypeUser, userAttrs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create user identity: %w", err)
	}
	err = identityStore.SetCredential(user.ID, "user-password")
	if err != nil {
		return nil, err
	}
	err = identityStore.AssociatePrincipal(user.ID, "user1")
	if err != nil {
		return nil, err
	}
	log.Printf("Created user identity: %s (%s)", user.ID, user.Name)

	// Create service identity
	serviceAttrs := map[string]string{
		"service_type": "api",
		"version":      "1.0",
	}
	service, err := identityStore.CreateIdentity("API Service", trust.IdentityTypeService, serviceAttrs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create service identity: %w", err)
	}
	err = identityStore.SetCredential(service.ID, "api-key-12345")
	if err != nil {
		return nil, err
	}
	err = identityStore.AssociatePrincipal(service.ID, "admin1") // Services often have admin privileges
	if err != nil {
		return nil, err
	}
	log.Printf("Created service identity: %s (%s)", service.ID, service.Name)

	// Create device identity
	deviceAttrs := map[string]string{
		"device_type": "sensor",
		"location":    "server-room",
	}
	device, err := identityStore.CreateIdentity("Temperature Sensor", trust.IdentityTypeDevice, deviceAttrs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create device identity: %w", err)
	}
	err = identityStore.SetCredential(device.ID, "device-token-xyz")
	if err != nil {
		return nil, err
	}
	err = identityStore.AssociatePrincipal(device.ID, "device1")
	if err != nil {
		return nil, err
	}
	log.Printf("Created device identity: %s (%s)", device.ID, device.Name)

	// Create robot identity
	robotAttrs := map[string]string{
		"model":    "UR10",
		"location": "assembly-line-1",
	}
	robot, err := identityStore.CreateIdentity("Assembly Robot", trust.IdentityTypeRobot, robotAttrs, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create robot identity: %w", err)
	}
	err = identityStore.SetCredential(robot.ID, "robot-secret-abc")
	if err != nil {
		return nil, err
	}
	err = identityStore.AssociatePrincipal(robot.ID, "robot1")
	if err != nil {
		return nil, err
	}
	log.Printf("Created robot identity: %s (%s)", robot.ID, robot.Name)

	return &Identities{
		user:    user,
		service: service,
		device:  device,
		robot:   robot,
	}, nil
}

func authenticateIdentities(provider *trust.IdentityProvider, identities *Identities) error {
	log.Println("\nAuthenticating identities...")
	ctx := context.Background()

	// Authenticate user
	authUser, err := provider.Authenticate(ctx, identities.user.ID, "user-password")
	if err != nil {
		log.Printf("User authentication failed: %v", err)
	} else {
		log.Printf("User authenticated: %s", authUser.Name)

		// Create token
		token, err := provider.CreateIdentityToken(authUser, time.Hour)
		if err != nil {
			return fmt.Errorf("failed to create user token: %w", err)
		}
		log.Printf("User token created: %s...", token[:20])

		// Validate token
		validatedUser, err := provider.ValidateIdentityToken(token)
		if err != nil {
			return fmt.Errorf("failed to validate user token: %w", err)
		}
		log.Printf("User token validated for: %s", validatedUser.Name)

		// Get associated principal
		principal, err := provider.IdentityToPrincipal(ctx, validatedUser)
		if err != nil {
			log.Printf("Failed to get principal for user: %v", err)
		} else {
			log.Printf("User maps to principal: %s", principal.ID)
		}
	}

	// Authenticate service with wrong credential (should fail)
	_, err = provider.Authenticate(ctx, identities.service.ID, "wrong-key")
	if err != nil {
		log.Printf("Service authentication failed with wrong credential (expected): %v", err)
	} else {
		log.Printf("ERROR: Service authenticated with wrong credential!")
	}

	// Authenticate service with correct credential
	authService, err := provider.Authenticate(ctx, identities.service.ID, "api-key-12345")
	if err != nil {
		log.Printf("Service authentication failed: %v", err)
	} else {
		log.Printf("Service authenticated: %s", authService.Name)
		token, err := provider.CreateIdentityToken(authService, 30*24*time.Hour) // 30 days
		if err != nil {
			return fmt.Errorf("failed to create service token: %w", err)
		}
		log.Printf("Service token created: %s...", token[:20])
	}

	// Authenticate device
	authDevice, err := provider.Authenticate(ctx, identities.device.ID, "device-token-xyz")
	if err != nil {
		log.Printf("Device authentication failed: %v", err)
	} else {
		log.Printf("Device authenticated: %s", authDevice.Name)
		token, err := provider.CreateIdentityToken(authDevice, 90*24*time.Hour) // 90 days
		if err != nil {
			return fmt.Errorf("failed to create device token: %w", err)
		}
		log.Printf("Device token created: %s...", token[:20])
	}

	// Authenticate robot
	authRobot, err := provider.Authenticate(ctx, identities.robot.ID, "robot-secret-abc")
	if err != nil {
		log.Printf("Robot authentication failed: %v", err)
	} else {
		log.Printf("Robot authenticated: %s", authRobot.Name)
		token, err := provider.CreateIdentityToken(authRobot, 7*24*time.Hour) // 7 days
		if err != nil {
			return fmt.Errorf("failed to create robot token: %w", err)
		}
		log.Printf("Robot token created: %s...", token[:20])
	}

	return nil
}

func identityManagementOperations(identityStore *trust.IdentityStore, identityProvider *trust.IdentityProvider) error {
	log.Println("\nDemonstrating identity management operations...")

	// List all identities
	var noFilter *trust.IdentityType
	allIdentities := identityStore.ListIdentities(noFilter)
	log.Printf("Total identities: %d", len(allIdentities))

	// List by type
	userType := trust.IdentityTypeUser
	userIdentities := identityStore.ListIdentities(&userType)
	log.Printf("User identities: %d", len(userIdentities))

	deviceType := trust.IdentityTypeDevice
	deviceIdentities := identityStore.ListIdentities(&deviceType)
	log.Printf("Device identities: %d", len(deviceIdentities))

	// Update an identity
	if len(userIdentities) > 0 {
		user := userIdentities[0]
		user.Attributes["department"] = "Research"
		user.Attributes["role"] = "Senior Engineer"
		err := identityStore.UpdateIdentity(user)
		if err != nil {
			return fmt.Errorf("failed to update user identity: %w", err)
		}
		log.Printf("Updated user identity: %s with new attributes", user.ID)

		// Verify update
		updatedUser, err := identityStore.GetIdentity(user.ID)
		if err != nil {
			return fmt.Errorf("failed to get updated user: %w", err)
		}
		log.Printf("Updated user department: %s", updatedUser.Attributes["department"])
	}

	// Disable an identity
	if len(allIdentities) > 3 {
		identityToDisable := allIdentities[3]
		identityToDisable.Enabled = false
		err := identityStore.UpdateIdentity(identityToDisable)
		if err != nil {
			return fmt.Errorf("failed to disable identity: %w", err)
		}
		log.Printf("Disabled identity: %s (%s)", identityToDisable.ID, identityToDisable.Name)

		// Try to authenticate (should fail)
		ctx := context.Background()
		_, err = identityProvider.Authenticate(ctx, identityToDisable.ID, "any-credential")
		if err != nil {
			log.Printf("Correctly rejected authentication for disabled identity: %v", err)
		} else {
			log.Printf("ERROR: Disabled identity was authenticated!")
		}
	}

	// Delete an identity
	if len(allIdentities) > 0 {
		identityToDelete := allIdentities[0]
		err := identityStore.DeleteIdentity(identityToDelete.ID)
		if err != nil {
			return fmt.Errorf("failed to delete identity: %w", err)
		}
		log.Printf("Deleted identity: %s", identityToDelete.ID)

		// Verify deletion
		remainingIdentities := identityStore.ListIdentities(noFilter)
		log.Printf("Remaining identities: %d", len(remainingIdentities))
	}

	return nil
}