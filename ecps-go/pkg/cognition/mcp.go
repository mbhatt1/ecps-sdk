// Package cognition provides implementations for the Cognition Layer (L6).
package cognition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ecps/ecps-go/pkg/core"
	pb "github.com/ecps/ecps-go/proto"
)

// Maximum prompt size in bytes (16 KiB)
const MaxPromptSize = 16 * 1024

// MCPHandler handles Model Context Protocol (MCP) messages.
type MCPHandler struct {
	transport  core.Transport
	serializer core.Serializer
	telemetry  core.Telemetry
	logger     core.Logger
	topic      string
}

// NewMCPHandler creates a new MCPHandler.
func NewMCPHandler(
	transport core.Transport,
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	options ...MCPOption,
) (*MCPHandler, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}

	// Default configuration
	handler := &MCPHandler{
		transport:  transport,
		serializer: serializer,
		telemetry:  telemetry,
		logger:     logger,
		topic:      "mcp", // Default topic
	}

	// Apply options
	for _, opt := range options {
		opt(handler)
	}

	return handler, nil
}

// MCPOption is a function that configures an MCPHandler.
type MCPOption func(*MCPHandler)

// WithTopic sets the topic for MCP messages.
func WithTopic(topic string) MCPOption {
	return func(h *MCPHandler) {
		h.topic = topic
	}
}

// CreateMCPMessage creates an MCP message.
func (h *MCPHandler) CreateMCPMessage(
	prompt string,
	messageID string,
	toolJSON []byte,
	meta map[string]string,
) (*pb.MCP, error) {
	// Check prompt size
	promptBytes := []byte(prompt)
	if len(promptBytes) > MaxPromptSize {
		h.logger.Warn(
			"Prompt size (%d bytes) exceeds max size (%d bytes), truncating",
			len(promptBytes),
			MaxPromptSize,
		)
		// Truncate to fit within limit
		// Note: This is a simplified approach that doesn't handle UTF-8 character boundaries
		// A more robust solution would decode UTF-8 and truncate at character boundaries
		promptBytes = promptBytes[:MaxPromptSize]
		prompt = string(promptBytes)
	}

	// Generate message ID if not provided
	if messageID == "" {
		uuid, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		messageID = uuid.String()
	}

	// Create MCP message
	mcp := &pb.MCP{
		Spec:     "mcp/1.0",
		Id:       messageID,
		Prompt:   prompt,
		ToolJson: toolJSON,
	}

	// Add metadata if provided
	if meta != nil {
		mcp.Meta = meta
	}

	// Record metrics if telemetry is available
	if h.telemetry != nil {
		attrs := map[string]string{
			"id":         messageID,
			"has_tool":   fmt.Sprintf("%t", len(toolJSON) > 0),
			"meta_count": fmt.Sprintf("%d", len(meta)),
		}
		h.telemetry.RecordMCPPromptSize(len(prompt), attrs)
	}

	return mcp, nil
}

// Send sends an MCP message.
func (h *MCPHandler) Send(
	ctx context.Context,
	prompt string,
	messageID string,
	toolJSON []byte,
	meta map[string]string,
	qos map[string]interface{},
) (string, error) {
	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "mcp.send", trace.SpanKindProducer, map[string]interface{}{
			"topic":         h.topic,
			"prompt_length": len(prompt),
			"has_tool":      len(toolJSON) > 0,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create MCP message
	mcp, err := h.CreateMCPMessage(prompt, messageID, toolJSON, meta)
	if err != nil {
		return "", fmt.Errorf("failed to create MCP message: %w", err)
	}

	// Publish message
	if err := h.transport.Publish(ctx, h.topic, mcp, qos); err != nil {
		return "", fmt.Errorf("failed to publish MCP message: %w", err)
	}

	h.logger.Info("Sent MCP message with ID %s", mcp.Id)
	return mcp.Id, nil
}

// Listen starts listening for MCP messages.
func (h *MCPHandler) Listen(
	ctx context.Context,
	handlers []func(context.Context, *pb.MCP) error,
	qos map[string]interface{},
) error {
	if len(handlers) == 0 {
		return errors.New("no handlers provided")
	}

	// Define message handler
	mcpHandler := func(ctx context.Context, mcpMessage *pb.MCP) error {
		// Create a span if telemetry is available
		var spanCtx context.Context
		var span trace.Span
		if h.telemetry != nil {
			spanCtx, span = h.telemetry.CreateSpan(ctx, "mcp.receive", trace.SpanKindConsumer, map[string]interface{}{
				"topic":         h.topic,
				"message_id":    mcpMessage.Id,
				"prompt_length": len(mcpMessage.Prompt),
				"has_tool":      len(mcpMessage.ToolJson) > 0,
			})
			defer span.End()
			ctx = spanCtx
		}

		// Call all handlers
		for _, handler := range handlers {
			if err := handler(ctx, mcpMessage); err != nil {
				h.logger.Error("Error in MCP handler: %v", err)
				if span != nil {
					span.RecordError(err)
				}
			}
		}

		return nil
	}

	// Subscribe to topic
	if err := h.transport.Subscribe(ctx, h.topic, &pb.MCP{}, mcpHandler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to MCP topic: %w", err)
	}

	h.logger.Info("Listening for MCP messages on topic %s", h.topic)
	return nil
}

// ValidateMCPMessage validates an MCP message.
func (h *MCPHandler) ValidateMCPMessage(mcpMessage *pb.MCP) error {
	if mcpMessage == nil {
		return errors.New("MCP message cannot be nil")
	}

	if mcpMessage.Spec != "mcp/1.0" {
		return fmt.Errorf("invalid MCP spec: %s", mcpMessage.Spec)
	}

	if mcpMessage.Id == "" {
		return errors.New("MCP message ID cannot be empty")
	}

	if len(mcpMessage.Prompt) == 0 {
		return errors.New("MCP prompt cannot be empty")
	}

	if len(mcpMessage.Prompt) > MaxPromptSize {
		return fmt.Errorf("MCP prompt exceeds maximum size: %d bytes", MaxPromptSize)
	}

	return nil
}

// ExtractToolJSON extracts and parses the tool JSON from an MCP message.
func (h *MCPHandler) ExtractToolJSON(mcpMessage *pb.MCP) (map[string]interface{}, error) {
	if mcpMessage == nil {
		return nil, errors.New("MCP message cannot be nil")
	}

	if len(mcpMessage.ToolJson) == 0 {
		return nil, nil
	}

	// Parse JSON
	var toolData map[string]interface{}
	if err := json.Unmarshal(mcpMessage.ToolJson, &toolData); err != nil {
		return nil, fmt.Errorf("failed to parse tool JSON: %w", err)
	}

	return toolData, nil
}

// CreateMCPResponse creates an MCP response message.
func (h *MCPHandler) CreateMCPResponse(
	requestID string,
	response string,
	toolResult []byte,
	meta map[string]string,
) (*pb.MCP, error) {
	// Create response MCP message
	// Note: We're using the same MCP message type for responses
	// In a real implementation, you might want a separate MCPResponse type
	mcp := &pb.MCP{
		Spec:     "mcp/1.0",
		Id:       requestID,
		Prompt:   response,
		ToolJson: toolResult,
	}

	// Add metadata if provided
	if meta == nil {
		meta = make(map[string]string)
	}
	
	// Add response indicator to metadata
	meta["is_response"] = "true"
	mcp.Meta = meta

	return mcp, nil
}

// SendResponse sends an MCP response message.
func (h *MCPHandler) SendResponse(
	ctx context.Context,
	requestID string,
	response string,
	toolResult []byte,
	meta map[string]string,
	qos map[string]interface{},
) error {
	// Create response topic (for directed responses)
	responseTopic := fmt.Sprintf("%s/response/%s", h.topic, requestID)

	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "mcp.send_response", trace.SpanKindProducer, map[string]interface{}{
			"topic":            responseTopic,
			"request_id":       requestID,
			"response_length":  len(response),
			"has_tool_result":  len(toolResult) > 0,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create MCP response
	mcpResponse, err := h.CreateMCPResponse(requestID, response, toolResult, meta)
	if err != nil {
		return fmt.Errorf("failed to create MCP response: %w", err)
	}

	// Publish response
	if err := h.transport.Publish(ctx, responseTopic, mcpResponse, qos); err != nil {
		return fmt.Errorf("failed to publish MCP response: %w", err)
	}

	h.logger.Info("Sent MCP response for request ID %s", requestID)
	return nil
}

// ListenForResponses starts listening for MCP response messages.
func (h *MCPHandler) ListenForResponses(
	ctx context.Context,
	requestID string,
	handler func(context.Context, *pb.MCP) error,
	qos map[string]interface{},
) error {
	// Create response topic
	responseTopic := fmt.Sprintf("%s/response/%s", h.topic, requestID)

	// Subscribe to response topic
	if err := h.transport.Subscribe(ctx, responseTopic, &pb.MCP{}, handler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to MCP response topic: %w", err)
	}

	h.logger.Info("Listening for MCP responses on topic %s", responseTopic)
	return nil
}

// IsResponse checks if an MCP message is a response.
func (h *MCPHandler) IsResponse(mcpMessage *pb.MCP) bool {
	if mcpMessage == nil || mcpMessage.Meta == nil {
		return false
	}

	if isResponse, ok := mcpMessage.Meta["is_response"]; ok && isResponse == "true" {
		return true
	}

	return false
}

// Close closes the MCP handler and releases any resources.
func (h *MCPHandler) Close() error {
	// Currently no resources to release
	return nil
}