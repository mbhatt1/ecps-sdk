// Example of secure communication using the ECPS trust layer
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/core"
	"github.com/ecps/ecps-go/pkg/transport"
	"github.com/ecps/ecps-go/pkg/trust"
	pb "github.com/ecps/ecps-go/proto"
)

const (
	MessageTopic = "secure_messages"
)

var (
	// Command line flags
	role        = flag.String("role", "client", "Role: client or server")
	trustLevel  = flag.Int("trust", 3, "Trust level (0-4): 0=None, 1=Encryption, 2=Authentication, 3=Authorization, 4=Audited")
	keyFile     = flag.String("key", "", "Private key file (PEM format)")
	certFile    = flag.String("cert", "", "Certificate file (PEM format)")
	jwtSecret   = flag.String("secret", "your-256-bit-secret", "JWT secret")
	principalID = flag.String("principal", "user1", "Principal ID")
)

func main() {
	// Parse command line flags
	flag.Parse()

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling for graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signalChan
		log.Println("Received shutdown signal, exiting...")
		cancel()
	}()

	// Create trust provider
	trustProvider, err := createTrustProvider()
	if err != nil {
		log.Fatalf("Failed to create trust provider: %v", err)
	}

	// Create transport
	transportImpl, err := createSecureTransport(ctx, trustProvider)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	// Run as client or server
	if *role == "server" {
		runServer(ctx, transportImpl, trustProvider)
	} else {
		runClient(ctx, transportImpl, trustProvider)
	}
}

// createTrustProvider creates and configures a trust provider
func createTrustProvider() (*trust.TrustProvider, error) {
	// Create logger
	logger := core.NewDefaultLogger()
	logger.SetLevel(core.LogLevelInfo)

	// Configure trust options
	options := []trust.TrustOption{
		trust.WithTrustLevel(trust.TrustLevel(*trustLevel)),
		trust.WithTrustMechanisms(trust.TrustMechanismJWT, trust.TrustMechanismTLS),
		trust.WithJWTSecret(*jwtSecret),
	}

	// Load private key if specified
	if *keyFile != "" {
		options = append(options, trust.WithPrivateKeyFile(*keyFile))
	}

	// Create an RBAC authorizer
	authorizer := trust.NewRBACAuthorizer()

	// Add permissions for roles
	authorizer.AddRolePermission("admin", "publish", MessageTopic)
	authorizer.AddRolePermission("admin", "subscribe", MessageTopic)
	authorizer.AddRolePermission("user", "subscribe", MessageTopic)

	options = append(options, trust.WithAuthorizer(authorizer))

	// Create the trust provider
	provider, err := trust.NewTrustProvider(logger, nil, options...)
	if err != nil {
		return nil, fmt.Errorf("failed to create trust provider: %w", err)
	}

	// Add some test principals
	adminPrincipal := &trust.Principal{
		ID:    "admin1",
		Name:  "Administrator",
		Roles: []string{"admin"},
		Permissions: map[string]bool{
			"publish:secure_messages": true,
		},
		Attributes: map[string]string{
			"department": "IT",
		},
	}
	provider.AddPrincipal(adminPrincipal)

	userPrincipal := &trust.Principal{
		ID:    "user1",
		Name:  "Regular User",
		Roles: []string{"user"},
		Permissions: map[string]bool{
			"subscribe:secure_messages": true,
		},
		Attributes: map[string]string{
			"department": "Marketing",
		},
	}
	provider.AddPrincipal(userPrincipal)

	return provider, nil
}

// createSecureTransport creates a transport with security
func createSecureTransport(ctx context.Context, trustProvider *trust.TrustProvider) (core.Transport, error) {
	// Create base transport (using DDS for this example)
	baseTransport, err := transport.NewDDSTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create DDS transport: %w", err)
	}

	// Wrap with secure transport
	secureTransport, err := trustProvider.SecureTransport(baseTransport)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure transport: %w", err)
	}

	// Set principal for the transport if we're in client mode
	if *role == "client" {
		// Authenticate principal
		principal, err := trustProvider.Authenticate(ctx, *principalID, "")
		if err != nil {
			return nil, fmt.Errorf("authentication failed: %w", err)
		}

		// Create JWT for the principal
		token, err := trustProvider.CreateJWT(principal, 1*time.Hour)
		if err != nil {
			return nil, fmt.Errorf("failed to create JWT: %w", err)
		}

		// Set principal on secure transport
		secureTransport.(*trust.SecureTransport).SetPrincipal(principal.ID, token)
	}

	return secureTransport, nil
}

// runServer runs the server role
func runServer(ctx context.Context, transportImpl core.Transport, trustProvider *trust.TrustProvider) {
	log.Println("Starting secure server...")

	// Create MCP handler for messages
	mcpHandler, err := cognition.NewMCPHandler(
		transportImpl,
		core.NewProtobufSerializer(),
		nil,
		core.NewDefaultLogger(),
	)
	if err != nil {
		log.Fatalf("Failed to create MCP handler: %v", err)
	}

	// Start the transport
	if err := transportImpl.Start(ctx); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}
	defer transportImpl.Close()

	// Listen for messages
	err = mcpHandler.Listen(ctx, []func(context.Context, *pb.MCP) error{
		func(ctx context.Context, mcp *pb.MCP) error {
			// Get principal from context if available
			var principalInfo string
			if principal, ok := ctx.Value("principal").(*trust.Principal); ok {
				principalInfo = fmt.Sprintf(" from %s (%s)", principal.Name, principal.ID)
			}

			log.Printf("Received secure message%s: %s", principalInfo, mcp.Prompt)

			// Extract any metadata
			if len(mcp.Meta) > 0 {
				log.Printf("Message metadata: %v", mcp.Meta)
			}

			// Send a response if appropriate
			if !mcpHandler.IsResponse(mcp) {
				log.Printf("Sending response to message ID: %s", mcp.Id)
				return mcpHandler.SendResponse(
					ctx,
					mcp.Id,
					fmt.Sprintf("Secure echo: %s", mcp.Prompt),
					nil,
					map[string]string{"server_time": time.Now().Format(time.RFC3339)},
					nil,
				)
			}
			return nil
		},
	}, nil)
	if err != nil {
		log.Fatalf("Failed to listen for messages: %v", err)
	}

	log.Printf("Server listening for secure messages on topic: %s", MessageTopic)
	log.Println("Press Ctrl+C to exit")

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Server shutting down")
}

// runClient runs the client role
func runClient(ctx context.Context, transportImpl core.Transport, trustProvider *trust.TrustProvider) {
	log.Println("Starting secure client...")

	// Create MCP handler for messages
	mcpHandler, err := cognition.NewMCPHandler(
		transportImpl,
		core.NewProtobufSerializer(),
		nil,
		core.NewDefaultLogger(),
		cognition.WithTopic(MessageTopic),
	)
	if err != nil {
		log.Fatalf("Failed to create MCP handler: %v", err)
	}

	// Start the transport
	if err := transportImpl.Start(ctx); err != nil {
		log.Fatalf("Failed to start transport: %v", err)
	}
	defer transportImpl.Close()

	// Listen for responses
	err = mcpHandler.Listen(ctx, []func(context.Context, *pb.MCP) error{
		func(ctx context.Context, mcp *pb.MCP) error {
			// Only process responses
			if mcpHandler.IsResponse(mcp) {
				log.Printf("Received response: %s", mcp.Prompt)
				if len(mcp.Meta) > 0 {
					log.Printf("Response metadata: %v", mcp.Meta)
				}
			}
			return nil
		},
	}, nil)
	if err != nil {
		log.Fatalf("Failed to listen for responses: %v", err)
	}

	// Get authenticated principal
	principal, err := trustProvider.Authenticate(ctx, *principalID, "")
	if err != nil {
		log.Fatalf("Authentication failed: %v", err)
	}

	// Check authorization
	authorized, err := trustProvider.Authorize(ctx, principal, "publish", MessageTopic)
	if err != nil {
		log.Fatalf("Authorization check failed: %v", err)
	}

	if !authorized {
		log.Fatalf("Principal %s is not authorized to publish to %s", principal.ID, MessageTopic)
	}

	// Send secure messages periodically
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	messageCount := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			messageCount++
			message := fmt.Sprintf("Secure message #%d from %s", messageCount, principal.ID)
			
			// Send message
			messageID, err := mcpHandler.Send(
				ctx,
				message,
				"",
				nil,
				map[string]string{
					"sender":    principal.Name,
					"timestamp": time.Now().Format(time.RFC3339),
				},
				nil,
			)
			if err != nil {
				log.Printf("Error sending message: %v", err)
			} else {
				log.Printf("Sent secure message with ID: %s", messageID)
			}
		}
	}
}