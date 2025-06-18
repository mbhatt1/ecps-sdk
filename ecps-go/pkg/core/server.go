package core

import (
	"context"
	"errors"

	"github.com/ecps/ecps-go/proto"
)

// MCPHandler is a handler for MCP messages.
type MCPHandler func(context.Context, *proto.MCP) error

// EAPHandler is a handler for EAP messages.
type EAPHandler func(context.Context, *proto.EAP) error

// Server is the interface for the ECPS server.
type Server interface {
	// OnMCP registers a handler for MCP messages.
	OnMCP(handler MCPHandler) error

	// OnEAP registers a handler for EAP messages.
	OnEAP(handler EAPHandler) error

	// StartMEPService starts the MEP service for memory storage and retrieval.
	StartMEPService(storageBackend interface{}) error

	// Start starts the server and begins listening for messages.
	Start(ctx context.Context) error

	// Stop stops the server and releases resources.
	Stop(ctx context.Context) error
}

// ECPSServer is the main implementation of the ECPS server.
type ECPSServer struct {
	config           *Config
	transport        Transport
	serializer       Serializer
	telemetry        Telemetry
	logger           Logger
	initialized      bool
	mcpHandlers      []MCPHandler
	eapHandlers      []EAPHandler
	mepService       MEPService
	messagingHandler MessageHandler
}

// NewServer creates a new ECPS server with the given configuration.
func NewServer(config *Config) (Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if err := config.Validate(); err != nil {
		return nil, err
	}

	server := &ECPSServer{
		config:      config,
		logger:      config.Logger,
		mcpHandlers: make([]MCPHandler, 0),
		eapHandlers: make([]EAPHandler, 0),
		initialized: false,
	}

	if err := server.initialize(); err != nil {
		return nil, err
	}

	return server, nil
}

// initialize initializes the server components.
func (s *ECPSServer) initialize() error {
	var err error

	// Create serializer
	s.serializer, err = newSerializer(s.config)
	if err != nil {
		return err
	}

	// Create telemetry if enabled
	if s.config.ObservabilityEnabled {
		s.telemetry, err = newTelemetry(s.config)
		if err != nil {
			return err
		}
	}

	// Create transport for server (with isServer=true)
	s.transport, err = newTransportServer(s.config, s.serializer, s.telemetry)
	if err != nil {
		return err
	}

	// Create messaging handler
	s.messagingHandler, err = newMessageHandler(s.config, s.transport, s.serializer, s.telemetry)
	if err != nil {
		return err
	}

	s.initialized = true
	s.logger.Info("ECPS server initialized")
	return nil
}

// OnMCP registers a handler for MCP messages.
func (s *ECPSServer) OnMCP(handler MCPHandler) error {
	if !s.initialized {
		return errors.New("server not initialized")
	}

	s.mcpHandlers = append(s.mcpHandlers, handler)
	return nil
}

// OnEAP registers a handler for EAP messages.
func (s *ECPSServer) OnEAP(handler EAPHandler) error {
	if !s.initialized {
		return errors.New("server not initialized")
	}

	s.eapHandlers = append(s.eapHandlers, handler)
	return nil
}

// StartMEPService starts the MEP service for memory storage and retrieval.
func (s *ECPSServer) StartMEPService(storageBackend interface{}) error {
	if !s.initialized {
		return errors.New("server not initialized")
	}

	var err error
	s.mepService, err = newMEPService(s.config, s.transport, s.serializer, s.telemetry, storageBackend)
	if err != nil {
		return err
	}

	return nil
}

// Start starts the server and begins listening for messages.
func (s *ECPSServer) Start(ctx context.Context) error {
	if !s.initialized {
		return errors.New("server not initialized")
	}

	// Start the transport
	if err := s.transport.Start(ctx); err != nil {
		return err
	}

	// Start the MEP service if initialized
	if s.mepService != nil {
		if err := s.mepService.Start(ctx); err != nil {
			return err
		}
	}

	// Register handlers for MCP messages
	if err := s.messagingHandler.ListenMCP(ctx, s.handleMCP); err != nil {
		return err
	}

	// Register handlers for EAP messages
	if err := s.messagingHandler.ListenEAP(ctx, s.handleEAP); err != nil {
		return err
	}

	s.logger.Info("ECPS server started")
	return nil
}

// Stop stops the server and releases resources.
func (s *ECPSServer) Stop(ctx context.Context) error {
	if !s.initialized {
		return nil
	}

	// Stop the MEP service if running
	if s.mepService != nil {
		if err := s.mepService.Stop(ctx); err != nil {
			s.logger.Error("Failed to stop MEP service: %v", err)
		}
	}

	// Stop telemetry if enabled
	if s.telemetry != nil {
		if err := s.telemetry.Shutdown(ctx); err != nil {
			s.logger.Error("Failed to shut down telemetry: %v", err)
		}
	}

	// Close the transport
	if err := s.transport.Close(); err != nil {
		s.logger.Error("Failed to close transport: %v", err)
		return err
	}

	s.initialized = false
	s.logger.Info("ECPS server stopped")
	return nil
}

// handleMCP is the internal handler for MCP messages that calls all registered handlers.
func (s *ECPSServer) handleMCP(ctx context.Context, msg *proto.MCP) error {
	for _, handler := range s.mcpHandlers {
		if err := handler(ctx, msg); err != nil {
			s.logger.Error("Error in MCP handler: %v", err)
		}
	}
	return nil
}

// handleEAP is the internal handler for EAP messages that calls all registered handlers.
func (s *ECPSServer) handleEAP(ctx context.Context, msg *proto.EAP) error {
	for _, handler := range s.eapHandlers {
		if err := handler(ctx, msg); err != nil {
			s.logger.Error("Error in EAP handler: %v", err)
		}
	}
	return nil
}

// Helper functions
func newTransportServer(config *Config, serializer Serializer, telemetry Telemetry) (Transport, error) {
	// Implementation will be provided in transport package
	return nil, nil
}

func newMEPService(config *Config, transport Transport, serializer Serializer, telemetry Telemetry, storageBackend interface{}) (MEPService, error) {
	// Implementation will be provided in cognition package
	return nil, nil
}