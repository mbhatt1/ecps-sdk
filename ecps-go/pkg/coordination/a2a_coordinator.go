// Package coordination provides agent-to-agent coordination capabilities for ECPS.
package coordination

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ecps/ecps-go/pkg/core"
	pb "github.com/ecps/ecps-go/proto"
)

// CoordinationRequest represents a coordination request between agents.
type CoordinationRequest struct {
	ID           string                 `json:"id"`
	FromAgent    string                 `json:"from_agent"`
	ToAgents     []string               `json:"to_agents"`
	RequestType  string                 `json:"request_type"`
	Capabilities []string               `json:"capabilities"`
	Data         map[string]interface{} `json:"data"`
	Priority     int                    `json:"priority"`
	Timestamp    time.Time              `json:"timestamp"`
	ExpiresAt    time.Time              `json:"expires_at"`
}

// CoordinationResponse represents a response to a coordination request.
type CoordinationResponse struct {
	RequestID    string                 `json:"request_id"`
	FromAgent    string                 `json:"from_agent"`
	Status       string                 `json:"status"` // "accepted", "rejected", "completed"
	Capabilities []string               `json:"capabilities"`
	Data         map[string]interface{} `json:"data"`
	Timestamp    time.Time              `json:"timestamp"`
}

// AgentCapability represents a capability that an agent can provide.
type AgentCapability struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Available   bool                   `json:"available"`
}

// A2ACoordinator handles agent-to-agent coordination.
type A2ACoordinator struct {
	agentID      string
	transport    core.Transport
	serializer   core.Serializer
	logger       core.Logger
	
	// State management
	mu                sync.RWMutex
	capabilities      map[string]*AgentCapability
	pendingRequests   map[string]*CoordinationRequest
	activeRequests    map[string]*CoordinationRequest
	knownAgents       map[string]map[string]*AgentCapability
	
	// Handlers
	requestHandlers  []func(context.Context, *CoordinationRequest) (*CoordinationResponse, error)
	responseHandlers []func(context.Context, *CoordinationResponse) error
	
	// Configuration
	requestTimeout   time.Duration
	heartbeatInterval time.Duration
	
	// Channels for coordination
	requestChan  chan *CoordinationRequest
	responseChan chan *CoordinationResponse
	stopChan     chan struct{}
}

// NewA2ACoordinator creates a new agent-to-agent coordinator.
func NewA2ACoordinator(
	agentID string,
	transport core.Transport,
	serializer core.Serializer,
	logger core.Logger,
) *A2ACoordinator {
	return &A2ACoordinator{
		agentID:           agentID,
		transport:         transport,
		serializer:        serializer,
		logger:            logger,
		capabilities:      make(map[string]*AgentCapability),
		pendingRequests:   make(map[string]*CoordinationRequest),
		activeRequests:    make(map[string]*CoordinationRequest),
		knownAgents:       make(map[string]map[string]*AgentCapability),
		requestTimeout:    30 * time.Second,
		heartbeatInterval: 10 * time.Second,
		requestChan:       make(chan *CoordinationRequest, 100),
		responseChan:      make(chan *CoordinationResponse, 100),
		stopChan:          make(chan struct{}),
	}
}

// RegisterCapability registers a capability that this agent can provide.
func (c *A2ACoordinator) RegisterCapability(capability *AgentCapability) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.capabilities[capability.Name] = capability
	c.logger.Info("Registered capability: %s", capability.Name)
	
	// Broadcast capability update
	return c.broadcastCapabilities()
}

// UnregisterCapability removes a capability from this agent.
func (c *A2ACoordinator) UnregisterCapability(capabilityName string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	delete(c.capabilities, capabilityName)
	c.logger.Info("Unregistered capability: %s", capabilityName)
	
	// Broadcast capability update
	return c.broadcastCapabilities()
}

// RequestCoordination sends a coordination request to other agents.
func (c *A2ACoordinator) RequestCoordination(
	ctx context.Context,
	toAgents []string,
	requestType string,
	requiredCapabilities []string,
	data map[string]interface{},
	priority int,
) (*CoordinationRequest, error) {
	request := &CoordinationRequest{
		ID:           uuid.New().String(),
		FromAgent:    c.agentID,
		ToAgents:     toAgents,
		RequestType:  requestType,
		Capabilities: requiredCapabilities,
		Data:         data,
		Priority:     priority,
		Timestamp:    time.Now(),
		ExpiresAt:    time.Now().Add(c.requestTimeout),
	}
	
	c.mu.Lock()
	c.pendingRequests[request.ID] = request
	c.mu.Unlock()
	
	// Send request to target agents
	for _, agentID := range toAgents {
		topic := fmt.Sprintf("coordination/request/%s", agentID)
		if err := c.transport.Publish(ctx, topic, request, nil); err != nil {
			c.logger.Error("Failed to send coordination request to %s: %v", agentID, err)
		}
	}
	
	c.logger.Info("Sent coordination request %s to agents: %v", request.ID, toAgents)
	return request, nil
}

// RespondToRequest sends a response to a coordination request.
func (c *A2ACoordinator) RespondToRequest(
	ctx context.Context,
	requestID string,
	status string,
	capabilities []string,
	data map[string]interface{},
) error {
	response := &CoordinationResponse{
		RequestID:    requestID,
		FromAgent:    c.agentID,
		Status:       status,
		Capabilities: capabilities,
		Data:         data,
		Timestamp:    time.Now(),
	}
	
	// Find the original request to get the requesting agent
	c.mu.RLock()
	var targetAgent string
	for _, req := range c.activeRequests {
		if req.ID == requestID {
			targetAgent = req.FromAgent
			break
		}
	}
	c.mu.RUnlock()
	
	if targetAgent == "" {
		return errors.New("original request not found")
	}
	
	topic := fmt.Sprintf("coordination/response/%s", targetAgent)
	if err := c.transport.Publish(ctx, topic, response, nil); err != nil {
		return fmt.Errorf("failed to send coordination response: %w", err)
	}
	
	c.logger.Info("Sent coordination response for request %s to agent %s", requestID, targetAgent)
	return nil
}

// GetKnownAgents returns a map of known agents and their capabilities.
func (c *A2ACoordinator) GetKnownAgents() map[string]map[string]*AgentCapability {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	// Create a deep copy
	result := make(map[string]map[string]*AgentCapability)
	for agentID, capabilities := range c.knownAgents {
		result[agentID] = make(map[string]*AgentCapability)
		for capName, cap := range capabilities {
			result[agentID][capName] = cap
		}
	}
	
	return result
}

// FindAgentsWithCapability finds agents that have a specific capability.
func (c *A2ACoordinator) FindAgentsWithCapability(capabilityName string) []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	var agents []string
	for agentID, capabilities := range c.knownAgents {
		if cap, exists := capabilities[capabilityName]; exists && cap.Available {
			agents = append(agents, agentID)
		}
	}
	
	return agents
}

// OnCoordinationRequest registers a handler for incoming coordination requests.
func (c *A2ACoordinator) OnCoordinationRequest(handler func(context.Context, *CoordinationRequest) (*CoordinationResponse, error)) {
	c.requestHandlers = append(c.requestHandlers, handler)
}

// OnCoordinationResponse registers a handler for incoming coordination responses.
func (c *A2ACoordinator) OnCoordinationResponse(handler func(context.Context, *CoordinationResponse) error) {
	c.responseHandlers = append(c.responseHandlers, handler)
}

// Start starts the coordination service.
func (c *A2ACoordinator) Start(ctx context.Context) error {
	// Subscribe to coordination requests
	requestTopic := fmt.Sprintf("coordination/request/%s", c.agentID)
	if err := c.transport.Subscribe(ctx, requestTopic, &CoordinationRequest{}, c.handleCoordinationRequest, nil); err != nil {
		return fmt.Errorf("failed to subscribe to coordination requests: %w", err)
	}
	
	// Subscribe to coordination responses
	responseTopic := fmt.Sprintf("coordination/response/%s", c.agentID)
	if err := c.transport.Subscribe(ctx, responseTopic, &CoordinationResponse{}, c.handleCoordinationResponse, nil); err != nil {
		return fmt.Errorf("failed to subscribe to coordination responses: %w", err)
	}
	
	// Subscribe to capability broadcasts
	capabilityTopic := "coordination/capabilities"
	if err := c.transport.Subscribe(ctx, capabilityTopic, &map[string]*AgentCapability{}, c.handleCapabilityBroadcast, nil); err != nil {
		return fmt.Errorf("failed to subscribe to capability broadcasts: %w", err)
	}
	
	// Start background goroutines
	go c.processRequests(ctx)
	go c.processResponses(ctx)
	go c.heartbeat(ctx)
	
	c.logger.Info("A2A coordinator started for agent %s", c.agentID)
	return nil
}

// Stop stops the coordination service.
func (c *A2ACoordinator) Stop() error {
	close(c.stopChan)
	c.logger.Info("A2A coordinator stopped for agent %s", c.agentID)
	return nil
}

// broadcastCapabilities broadcasts this agent's capabilities to other agents.
func (c *A2ACoordinator) broadcastCapabilities() error {
	topic := "coordination/capabilities"
	message := map[string]interface{}{
		"agent_id":     c.agentID,
		"capabilities": c.capabilities,
		"timestamp":    time.Now(),
	}
	
	return c.transport.Publish(context.Background(), topic, message, nil)
}

// handleCoordinationRequest handles incoming coordination requests.
func (c *A2ACoordinator) handleCoordinationRequest(ctx context.Context, request interface{}) error {
	req, ok := request.(*CoordinationRequest)
	if !ok {
		return errors.New("invalid coordination request type")
	}
	
	c.mu.Lock()
	c.activeRequests[req.ID] = req
	c.mu.Unlock()
	
	// Process request with registered handlers
	for _, handler := range c.requestHandlers {
		if response, err := handler(ctx, req); err != nil {
			c.logger.Error("Error processing coordination request %s: %v", req.ID, err)
		} else if response != nil {
			// Send response back
			return c.RespondToRequest(ctx, req.ID, response.Status, response.Capabilities, response.Data)
		}
	}
	
	return nil
}

// handleCoordinationResponse handles incoming coordination responses.
func (c *A2ACoordinator) handleCoordinationResponse(ctx context.Context, response interface{}) error {
	resp, ok := response.(*CoordinationResponse)
	if !ok {
		return errors.New("invalid coordination response type")
	}
	
	// Process response with registered handlers
	for _, handler := range c.responseHandlers {
		if err := handler(ctx, resp); err != nil {
			c.logger.Error("Error processing coordination response %s: %v", resp.RequestID, err)
		}
	}
	
	return nil
}

// handleCapabilityBroadcast handles capability broadcasts from other agents.
func (c *A2ACoordinator) handleCapabilityBroadcast(ctx context.Context, broadcast interface{}) error {
	data, ok := broadcast.(*map[string]interface{})
	if !ok {
		return errors.New("invalid capability broadcast type")
	}
	
	agentID, ok := (*data)["agent_id"].(string)
	if !ok {
		return errors.New("missing agent_id in capability broadcast")
	}
	
	capabilities, ok := (*data)["capabilities"].(map[string]*AgentCapability)
	if !ok {
		return errors.New("invalid capabilities in broadcast")
	}
	
	c.mu.Lock()
	c.knownAgents[agentID] = capabilities
	c.mu.Unlock()
	
	c.logger.Debug("Updated capabilities for agent %s", agentID)
	return nil
}

// processRequests processes coordination requests in the background.
func (c *A2ACoordinator) processRequests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case request := <-c.requestChan:
			// Process request
			c.logger.Debug("Processing coordination request %s", request.ID)
		}
	}
}

// processResponses processes coordination responses in the background.
func (c *A2ACoordinator) processResponses(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case response := <-c.responseChan:
			// Process response
			c.logger.Debug("Processing coordination response for request %s", response.RequestID)
		}
	}
}

// heartbeat sends periodic heartbeats and cleans up expired requests.
func (c *A2ACoordinator) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(c.heartbeatInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stopChan:
			return
		case <-ticker.C:
			// Broadcast capabilities
			if err := c.broadcastCapabilities(); err != nil {
				c.logger.Error("Failed to broadcast capabilities: %v", err)
			}
			
			// Clean up expired requests
			c.cleanupExpiredRequests()
		}
	}
}

// cleanupExpiredRequests removes expired coordination requests.
func (c *A2ACoordinator) cleanupExpiredRequests() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	now := time.Now()
	for id, request := range c.pendingRequests {
		if now.After(request.ExpiresAt) {
			delete(c.pendingRequests, id)
			c.logger.Debug("Cleaned up expired request %s", id)
		}
	}
	
	for id, request := range c.activeRequests {
		if now.After(request.ExpiresAt) {
			delete(c.activeRequests, id)
			c.logger.Debug("Cleaned up expired active request %s", id)
		}
	}
}