package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/ecps/ecps-go/proto"
)

// Client is the interface for the ECPS client.
type Client interface {
	// SendMCP sends a Model Context Protocol (MCP) message.
	SendMCP(ctx context.Context, prompt string, toolJSON []byte, meta map[string]string) (string, error)

	// StoreMemory stores a memory embedding using Memory Exchange Protocol (MEP).
	StoreMemory(ctx context.Context, tensorZstd []byte, shape []uint32, dtype string, frameID string, timestampNS uint64) (bool, string, error)

	// QueryMemory queries memory embeddings using Memory Exchange Protocol (MEP).
	QueryMemory(ctx context.Context, queryEmbedding *proto.LTP, k uint32, minSim float32) ([]*proto.LTP, error)

	// SendAction sends an Embodied Action Protocol (EAP) message.
	SendAction(ctx context.Context, actionType string, actionData interface{}, stateSHA []byte, meta map[string]string) (string, error)

	// SendUnified sends any type of ECPS message using the unified API.
	SendUnified(ctx context.Context, operation string, params map[string]interface{}) (interface{}, error)

	// ListenUnified listens for unified messages with operation-specific handlers.
	ListenUnified(ctx context.Context, handlers map[string][]func(context.Context, interface{}) error, qos map[string]interface{}) error

	// QueryUnified queries any type of stored data.
	QueryUnified(ctx context.Context, dataType string, queryParams map[string]interface{}) ([]interface{}, error)

	// EstablishIdentity establishes an identity context for this client (enables identity forwarding).
	EstablishIdentity(ctx context.Context, identityID, credential string, capabilities []string) error

	// RefreshIdentity refreshes the current identity context to extend its lifetime.
	RefreshIdentity(ctx context.Context, additionalHours int) error

	// RevokeIdentity revokes the current identity context.
	RevokeIdentity(ctx context.Context) error

	// GetIdentityStatus gets the current identity context status.
	GetIdentityStatus() map[string]interface{}

	// Close closes the client and releases resources.
	Close() error
}

// ECPSClient is the main implementation of the ECPS client.
type ECPSClient struct {
	config           *Config
	transport        Transport
	serializer       Serializer
	telemetry        Telemetry
	logger           Logger
	initialized      bool
	messagingHandler MessageHandler
}

// NewClient creates a new ECPS client with the given configuration.
func NewClient(config *Config) (Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	client := &ECPSClient{
		config:      config,
		logger:      config.Logger,
		initialized: false,
	}

	if err := client.initialize(); err != nil {
		return nil, err
	}

	return client, nil
}

// initialize initializes the client components.
func (c *ECPSClient) initialize() error {
	var err error

	// Create serializer
	c.serializer, err = newSerializer(c.config)
	if err != nil {
		return err
	}

	// Create telemetry if enabled
	if c.config.ObservabilityEnabled {
		c.telemetry, err = newTelemetry(c.config)
		if err != nil {
			return err
		}
	}

	// Create transport
	c.transport, err = newTransport(c.config, c.serializer, c.telemetry)
	if err != nil {
		return err
	}

	// Create messaging handler
	c.messagingHandler, err = newMessageHandler(c.config, c.transport, c.serializer, c.telemetry)
	if err != nil {
		return err
	}

	c.initialized = true
	c.logger.Info("ECPS client initialized")
	return nil
}

// SendMCP sends a Model Context Protocol (MCP) message.
func (c *ECPSClient) SendMCP(ctx context.Context, prompt string, toolJSON []byte, meta map[string]string) (string, error) {
	if !c.initialized {
		return "", errors.New("client not initialized")
	}

	return c.messagingHandler.SendMCP(ctx, prompt, toolJSON, meta)
}

// StoreMemory stores a memory embedding using Memory Exchange Protocol (MEP).
func (c *ECPSClient) StoreMemory(ctx context.Context, tensorZstd []byte, shape []uint32, dtype string, frameID string, timestampNS uint64) (bool, string, error) {
	if !c.initialized {
		return false, "", errors.New("client not initialized")
	}

	return c.messagingHandler.StoreLTP(ctx, tensorZstd, shape, dtype, frameID, timestampNS)
}

// QueryMemory queries memory embeddings using Memory Exchange Protocol (MEP).
func (c *ECPSClient) QueryMemory(ctx context.Context, queryEmbedding *proto.LTP, k uint32, minSim float32) ([]*proto.LTP, error) {
	if !c.initialized {
		return nil, errors.New("client not initialized")
	}

	return c.messagingHandler.QueryLTP(ctx, queryEmbedding, k, minSim)
}

// SendAction sends an Embodied Action Protocol (EAP) message.
func (c *ECPSClient) SendAction(ctx context.Context, actionType string, actionData interface{}, stateSHA []byte, meta map[string]string) (string, error) {
	if !c.initialized {
		return "", errors.New("client not initialized")
	}

	return c.messagingHandler.SendEAP(ctx, actionType, actionData, stateSHA, meta)
}

// SendUnified sends any type of ECPS message using the unified API.
func (c *ECPSClient) SendUnified(ctx context.Context, operation string, params map[string]interface{}) (interface{}, error) {
	if !c.initialized {
		return nil, errors.New("client not initialized")
	}

	// Route to appropriate protocol based on operation
	switch operation {
	case "prompt":
		prompt, _ := params["prompt"].(string)
		toolJSON, _ := params["tool_json"].([]byte)
		meta, _ := params["meta"].(map[string]string)
		return c.SendMCP(ctx, prompt, toolJSON, meta)
		
	case "memory_put":
		tensorZstd, _ := params["tensor_zstd"].([]byte)
		shape, _ := params["shape"].([]uint32)
		dtype, _ := params["dtype"].(string)
		frameID, _ := params["frame_id"].(string)
		timestampNS, _ := params["timestamp_ns"].(uint64)
		success, messageID, err := c.StoreMemory(ctx, tensorZstd, shape, dtype, frameID, timestampNS)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"success": success, "message_id": messageID}, nil
		
	case "memory_query":
		// For now, return a placeholder - would need proper LTP message construction
		return nil, errors.New("memory_query not yet implemented in unified API")
		
	case "action":
		actionType, _ := params["action_type"].(string)
		actionData := params["action_data"]
		stateSHA, _ := params["state_sha"].([]byte)
		meta, _ := params["meta"].(map[string]string)
		return c.SendAction(ctx, actionType, actionData, stateSHA, meta)
		
	default:
		return nil, fmt.Errorf("unknown operation: %s", operation)
	}
}

// ListenUnified listens for unified messages with operation-specific handlers.
func (c *ECPSClient) ListenUnified(ctx context.Context, handlers map[string][]func(context.Context, interface{}) error, qos map[string]interface{}) error {
	if !c.initialized {
		return errors.New("client not initialized")
	}

	// For now, return a placeholder implementation
	// In a full implementation, this would set up subscriptions for all protocol types
	c.logger.Info("ListenUnified called with %d handler types", len(handlers))
	return errors.New("ListenUnified not yet fully implemented")
}

// QueryUnified queries any type of stored data.
func (c *ECPSClient) QueryUnified(ctx context.Context, dataType string, queryParams map[string]interface{}) ([]interface{}, error) {
	if !c.initialized {
		return nil, errors.New("client not initialized")
	}

	// Route to appropriate query method based on data type
	switch dataType {
	case "memory":
		// For now, return placeholder - would need proper query implementation
		return nil, errors.New("memory queries not yet implemented in unified API")
	case "actions":
		// Return placeholder action data
		return []interface{}{
			map[string]interface{}{
				"id":   "action_1",
				"type": "move",
				"status": "completed",
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown data type: %s", dataType)
	}
}

// EstablishIdentity establishes an identity context for this client (enables identity forwarding).
func (c *ECPSClient) EstablishIdentity(ctx context.Context, identityID, credential string, capabilities []string) error {
	if !c.initialized {
		return errors.New("client not initialized")
	}

	// For now, store identity information in client
	// In a full implementation, this would integrate with the trust system
	c.logger.Info("Establishing identity for %s with capabilities: %v", identityID, capabilities)
	
	// Placeholder implementation - would integrate with actual identity forwarding
	return nil
}

// RefreshIdentity refreshes the current identity context to extend its lifetime.
func (c *ECPSClient) RefreshIdentity(ctx context.Context, additionalHours int) error {
	if !c.initialized {
		return errors.New("client not initialized")
	}

	c.logger.Info("Refreshing identity context for %d additional hours", additionalHours)
	
	// Placeholder implementation
	return nil
}

// RevokeIdentity revokes the current identity context.
func (c *ECPSClient) RevokeIdentity(ctx context.Context) error {
	if !c.initialized {
		return errors.New("client not initialized")
	}

	c.logger.Info("Revoking identity context")
	
	// Placeholder implementation
	return nil
}

// GetIdentityStatus gets the current identity context status.
func (c *ECPSClient) GetIdentityStatus() map[string]interface{} {
	if !c.initialized {
		return map[string]interface{}{"authenticated": false, "reason": "client not initialized"}
	}

	// Placeholder implementation - return basic status
	return map[string]interface{}{
		"authenticated": true,
		"identity_id":   "placeholder_identity",
		"capabilities":  []string{"read", "write"},
		"expires_at":    "2024-12-31T23:59:59Z",
	}
}
// Close closes the client and releases resources.
func (c *ECPSClient) Close() error {
	if !c.initialized {
		return nil
	}

	if c.telemetry != nil {
		if err := c.telemetry.Shutdown(context.Background()); err != nil {
			c.logger.Error("Failed to shut down telemetry: %v", err)
		}
	}

	if err := c.transport.Close(); err != nil {
		c.logger.Error("Failed to close transport: %v", err)
		return err
	}

	c.initialized = false
	c.logger.Info("ECPS client closed")
	return nil
}

// Helper functions to create components based on configuration
func newSerializer(config *Config) (Serializer, error) {
	// Implementation will be provided in serialization package
	return nil, nil
}

func newTelemetry(config *Config) (Telemetry, error) {
	// Implementation will be provided in observability package
	return nil, nil
}

func newTransport(config *Config, serializer Serializer, telemetry Telemetry) (Transport, error) {
	// Implementation will be provided in transport package
	return nil, nil
}

func newMessageHandler(config *Config, transport Transport, serializer Serializer, telemetry Telemetry) (MessageHandler, error) {
	// Implementation will be created later
	return nil, nil
}