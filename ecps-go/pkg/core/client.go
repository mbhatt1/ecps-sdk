package core

import (
	"context"
	"errors"

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