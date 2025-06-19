// Package cognition provides implementations for the Cognition Layer (L6).
package cognition

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ecps/ecps-go/pkg/core"
	pb "github.com/ecps/ecps-go/proto"
)

// UEP operation types - consolidating all protocols
const (
	UEPOperationPrompt      = "prompt"        // MCP
	UEPOperationMemoryPut   = "memory_put"    // MEP
	UEPOperationMemoryQuery = "memory_query"  // MEP
	UEPOperationMemoryDelete = "memory_delete" // MEP
	UEPOperationAction      = "action"        // EAP
	UEPOperationPerception  = "perception"    // LTP
	UEPOperationCoordinate  = "coordinate"    // A2A
	UEPOperationTrust       = "trust"         // Trust/Security
	UEPOperationTelemetry   = "telemetry"     // Observability
)

// Maximum sizes
const (
	MaxPromptSizeUEP = 16 * 1024      // 16 KiB
	MaxActionSizeUEP = 64 * 1024      // 64 KiB
	MaxTensorSizeUEP = 16 * 1024 * 1024 // 16 MiB
)

// UnifiedStorage handles all data types in a single storage backend.
type UnifiedStorage struct {
	maxSize int
	mu      sync.RWMutex

	// Separate stores for different data types
	memoryEmbeddings  []MemoryEmbedding
	perceptionData    map[string]PerceptionEntry
	actionHistory     []ActionEntry
	coordinationState map[string]CoordinationEntry
	trustCredentials  map[string]TrustEntry
	telemetryData     []TelemetryEntry
}

// Data entry types
type MemoryEmbedding struct {
	Tensor    []byte                 `json:"tensor"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

type PerceptionEntry struct {
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

type ActionEntry struct {
	Key       string                 `json:"key"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

type CoordinationEntry struct {
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

type TrustEntry struct {
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

type TelemetryEntry struct {
	Key       string                 `json:"key"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
	Timestamp time.Time              `json:"timestamp"`
}

// NewUnifiedStorage creates a new unified storage backend.
func NewUnifiedStorage(maxSize int) *UnifiedStorage {
	return &UnifiedStorage{
		maxSize:           maxSize,
		memoryEmbeddings:  make([]MemoryEmbedding, 0),
		perceptionData:    make(map[string]PerceptionEntry),
		actionHistory:     make([]ActionEntry, 0),
		coordinationState: make(map[string]CoordinationEntry),
		trustCredentials:  make(map[string]TrustEntry),
		telemetryData:     make([]TelemetryEntry, 0),
	}
}

// Store stores data of any type.
func (s *UnifiedStorage) Store(dataType, key string, data interface{}, metadata map[string]interface{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	
	switch dataType {
	case "memory":
		if len(s.memoryEmbeddings) >= s.maxSize {
			s.memoryEmbeddings = s.memoryEmbeddings[1:] // LRU
		}
		
		var tensorData []byte
		if td, ok := data.([]byte); ok {
			tensorData = td
		}
		
		s.memoryEmbeddings = append(s.memoryEmbeddings, MemoryEmbedding{
			Tensor:    tensorData,
			Metadata:  metadata,
			Timestamp: now,
		})

	case "perception":
		s.perceptionData[key] = PerceptionEntry{
			Data:      data,
			Metadata:  metadata,
			Timestamp: now,
		}

	case "action":
		if len(s.actionHistory) >= s.maxSize {
			s.actionHistory = s.actionHistory[1:] // LRU
		}
		s.actionHistory = append(s.actionHistory, ActionEntry{
			Key:       key,
			Data:      data,
			Metadata:  metadata,
			Timestamp: now,
		})

	case "coordination":
		s.coordinationState[key] = CoordinationEntry{
			Data:      data,
			Metadata:  metadata,
			Timestamp: now,
		}

	case "trust":
		s.trustCredentials[key] = TrustEntry{
			Data:      data,
			Metadata:  metadata,
			Timestamp: now,
		}

	case "telemetry":
		if len(s.telemetryData) >= s.maxSize {
			s.telemetryData = s.telemetryData[1:] // LRU
		}
		s.telemetryData = append(s.telemetryData, TelemetryEntry{
			Key:       key,
			Data:      data,
			Metadata:  metadata,
			Timestamp: now,
		})

	default:
		return fmt.Errorf("unknown data type: %s", dataType)
	}

	return nil
}

// Query queries data of any type.
func (s *UnifiedStorage) Query(dataType string, queryParams map[string]interface{}) ([]interface{}, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	switch dataType {
	case "memory":
		return s.queryMemory(queryParams)
	case "perception":
		return s.queryPerception(queryParams)
	case "action":
		return s.queryActions(queryParams)
	case "coordination":
		return s.queryCoordination(queryParams)
	case "trust":
		return s.queryTrust(queryParams)
	case "telemetry":
		return s.queryTelemetry(queryParams)
	default:
		return nil, fmt.Errorf("unknown data type: %s", dataType)
	}
}

func (s *UnifiedStorage) queryMemory(params map[string]interface{}) ([]interface{}, error) {
	// Simplified memory query - in practice would do vector similarity
	k := 10
	if kVal, ok := params["k"].(int); ok {
		k = kVal
	}

	var results []interface{}
	count := 0
	for _, embedding := range s.memoryEmbeddings {
		if count >= k {
			break
		}
		results = append(results, embedding)
		count++
	}

	return results, nil
}

func (s *UnifiedStorage) queryPerception(params map[string]interface{}) ([]interface{}, error) {
	frameID, hasFrameID := params["frame_id"].(string)
	
	var results []interface{}
	if hasFrameID {
		if entry, exists := s.perceptionData[frameID]; exists {
			results = append(results, entry)
		}
	} else {
		for _, entry := range s.perceptionData {
			results = append(results, entry)
		}
	}

	return results, nil
}

func (s *UnifiedStorage) queryActions(params map[string]interface{}) ([]interface{}, error) {
	limit := 100
	if limitVal, ok := params["limit"].(int); ok {
		limit = limitVal
	}

	actionType, hasActionType := params["action_type"].(string)
	
	var results []interface{}
	for _, action := range s.actionHistory {
		if hasActionType {
			if at, ok := action.Metadata["action_type"].(string); !ok || at != actionType {
				continue
			}
		}
		results = append(results, action)
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

func (s *UnifiedStorage) queryCoordination(params map[string]interface{}) ([]interface{}, error) {
	agentID, hasAgentID := params["agent_id"].(string)
	
	var results []interface{}
	if hasAgentID {
		if entry, exists := s.coordinationState[agentID]; exists {
			results = append(results, entry)
		}
	} else {
		for _, entry := range s.coordinationState {
			results = append(results, entry)
		}
	}

	return results, nil
}

func (s *UnifiedStorage) queryTrust(params map[string]interface{}) ([]interface{}, error) {
	identity, hasIdentity := params["identity"].(string)
	
	var results []interface{}
	if hasIdentity {
		if entry, exists := s.trustCredentials[identity]; exists {
			results = append(results, entry)
		}
	} else {
		for _, entry := range s.trustCredentials {
			results = append(results, entry)
		}
	}

	return results, nil
}

func (s *UnifiedStorage) queryTelemetry(params map[string]interface{}) ([]interface{}, error) {
	limit := 100
	if limitVal, ok := params["limit"].(int); ok {
		limit = limitVal
	}

	metricType, hasMetricType := params["metric_type"].(string)
	
	var results []interface{}
	for _, telemetry := range s.telemetryData {
		if hasMetricType {
			if mt, ok := telemetry.Metadata["metric_type"].(string); !ok || mt != metricType {
				continue
			}
		}
		results = append(results, telemetry)
		if len(results) >= limit {
			break
		}
	}

	return results, nil
}

// UEPHandler handles Unified ECPS Protocol (UEP) messages.
// This consolidates ALL ECPS protocols into a single unified API.
type UEPHandler struct {
	transport     core.Transport
	serializer    core.Serializer
	telemetry     core.Telemetry
	logger        core.Logger
	topic         string
	serviceName   string
	storage       *UnifiedStorage
	trustManager  core.TrustManager
}

// NewUEPHandler creates a new UEPHandler.
func NewUEPHandler(
	transport core.Transport,
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	options ...UEPOption,
) (*UEPHandler, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}

	// Default configuration
	handler := &UEPHandler{
		transport:   transport,
		serializer:  serializer,
		telemetry:   telemetry,
		logger:      logger,
		topic:       "uep", // Unified ECPS Protocol topic
		serviceName: "UnifiedECPSService",
		storage:     NewUnifiedStorage(10000),
	}

	// Apply options
	for _, opt := range options {
		opt(handler)
	}

	return handler, nil
}

// UEPOption is a function that configures a UEPHandler.
type UEPOption func(*UEPHandler)

// WithUEPTopic sets the topic for UEP messages.
func WithUEPTopic(topic string) UEPOption {
	return func(h *UEPHandler) {
		h.topic = topic
	}
}

// WithUEPServiceName sets the service name for UEP operations.
func WithUEPServiceName(serviceName string) UEPOption {
	return func(h *UEPHandler) {
		h.serviceName = serviceName
	}
}

// WithUEPStorage sets a custom storage backend.
func WithUEPStorage(storage *UnifiedStorage) UEPOption {
	return func(h *UEPHandler) {
		h.storage = storage
	}
}

// WithTrustManager sets the trust manager.
func WithTrustManager(trustManager core.TrustManager) UEPOption {
	return func(h *UEPHandler) {
		h.trustManager = trustManager
	}
}

// ========== UNIFIED OPERATIONS ==========

// SendPrompt sends a prompt to AI agents (MCP operation).
func (h *UEPHandler) SendPrompt(
	ctx context.Context,
	prompt string,
	messageID string,
	toolJSON []byte,
	meta map[string]string,
	qos map[string]interface{},
) (string, error) {
	data := map[string]interface{}{
		"prompt":     prompt,
		"message_id": messageID,
		"tool_json":  toolJSON,
		"meta":       meta,
	}
	
	return h.executeOperation(ctx, UEPOperationPrompt, data, qos)
}

// StoreMemory stores a memory embedding (MEP operation).
func (h *UEPHandler) StoreMemory(
	ctx context.Context,
	tensorZstd []byte,
	shape []int32,
	dtype string,
	frameID string,
	timestampNs int64,
	qos map[string]interface{},
) (bool, string, error) {
	data := map[string]interface{}{
		"tensor_zstd":  tensorZstd,
		"shape":        shape,
		"dtype":        dtype,
		"frame_id":     frameID,
		"timestamp_ns": timestampNs,
	}
	
	messageID, err := h.executeOperation(ctx, UEPOperationMemoryPut, data, qos)
	if err != nil {
		return false, "", err
	}
	
	return true, messageID, nil
}

// QueryMemory queries for similar embeddings (MEP operation).
func (h *UEPHandler) QueryMemory(
	ctx context.Context,
	queryEmbedding interface{},
	k int,
	minSim float32,
	qos map[string]interface{},
) ([]interface{}, error) {
	data := map[string]interface{}{
		"query_embedding": queryEmbedding,
		"k":               k,
		"min_sim":         minSim,
	}
	
	_, err := h.executeOperation(ctx, UEPOperationMemoryQuery, data, qos)
	if err != nil {
		return nil, err
	}
	
	// Query local storage
	queryParams := map[string]interface{}{
		"k":       k,
		"min_sim": minSim,
	}
	
	return h.storage.Query("memory", queryParams)
}

// SendAction sends an action command (EAP operation).
func (h *UEPHandler) SendAction(
	ctx context.Context,
	actionType string,
	actionData interface{},
	stateSHA []byte,
	meta map[string]string,
	qos map[string]interface{},
) (string, error) {
	data := map[string]interface{}{
		"action_type": actionType,
		"action_data": actionData,
		"state_sha":   stateSHA,
		"meta":        meta,
	}
	
	return h.executeOperation(ctx, UEPOperationAction, data, qos)
}

// SendPerception sends perception data (LTP operation).
func (h *UEPHandler) SendPerception(
	ctx context.Context,
	tensorZstd []byte,
	shape []int32,
	dtype string,
	frameID string,
	timestampNs int64,
	qos map[string]interface{},
) (string, error) {
	data := map[string]interface{}{
		"tensor_zstd":  tensorZstd,
		"shape":        shape,
		"dtype":        dtype,
		"frame_id":     frameID,
		"timestamp_ns": timestampNs,
	}
	
	return h.executeOperation(ctx, UEPOperationPerception, data, qos)
}

// CoordinateAgents coordinates with other agents (A2A operation).
func (h *UEPHandler) CoordinateAgents(
	ctx context.Context,
	coordinationType string,
	agentIDs []string,
	coordinationData interface{},
	meta map[string]string,
	qos map[string]interface{},
) (string, error) {
	data := map[string]interface{}{
		"coordination_type": coordinationType,
		"agent_ids":         agentIDs,
		"coordination_data": coordinationData,
		"meta":              meta,
	}
	
	return h.executeOperation(ctx, UEPOperationCoordinate, data, qos)
}

// ManageTrust manages trust and security operations.
func (h *UEPHandler) ManageTrust(
	ctx context.Context,
	trustOperation string,
	identity string,
	trustData interface{},
	meta map[string]string,
	qos map[string]interface{},
) (string, error) {
	data := map[string]interface{}{
		"trust_operation": trustOperation,
		"identity":        identity,
		"trust_data":      trustData,
		"meta":            meta,
	}
	
	return h.executeOperation(ctx, UEPOperationTrust, data, qos)
}

// SendTelemetry sends telemetry data.
func (h *UEPHandler) SendTelemetry(
	ctx context.Context,
	metricType string,
	metricData interface{},
	timestampNs int64,
	meta map[string]string,
	qos map[string]interface{},
) (string, error) {
	data := map[string]interface{}{
		"metric_type":  metricType,
		"metric_data":  metricData,
		"timestamp_ns": timestampNs,
		"meta":         meta,
	}
	
	return h.executeOperation(ctx, UEPOperationTelemetry, data, qos)
}

// ========== CORE EXECUTION ENGINE ==========

func (h *UEPHandler) executeOperation(
	ctx context.Context,
	operation string,
	data map[string]interface{},
	qos map[string]interface{},
) (string, error) {
	// Generate message ID
	uuid, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}
	messageID := uuid.String()

	// Create unified message wrapper
	wrapper := &pb.MCP{
		Spec:   "uep/1.0", // Unified ECPS Protocol version
		Id:     messageID,
		Prompt: fmt.Sprintf("UEP %s operation", operation),
		Meta: map[string]string{
			"uep_operation": operation,
			"timestamp":     fmt.Sprintf("%d", time.Now().UnixNano()),
		},
	}

	// Serialize operation data as tool_json
	dataBytes, err := h.serializer.Serialize(data)
	if err != nil {
		return "", fmt.Errorf("failed to serialize operation data: %w", err)
	}
	wrapper.ToolJson = dataBytes

	// Handle operation-specific logic
	if operation == UEPOperationPrompt {
		if prompt, ok := data["prompt"].(string); ok {
			wrapper.Prompt = prompt
		}
		if toolJSON, ok := data["tool_json"].([]byte); ok {
			wrapper.ToolJson = toolJSON
		}
		if meta, ok := data["meta"].(map[string]string); ok {
			for k, v := range meta {
				wrapper.Meta[k] = v
			}
		}
	}

	// Create telemetry span
	var spanCtx context.Context
	var span trace.Span
	startTime := time.Now()
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, fmt.Sprintf("uep.%s", operation), trace.SpanKindClient, map[string]interface{}{
			"operation":   operation,
			"message_id":  messageID,
			"data_size":   len(wrapper.ToolJson),
		})
		defer span.End()
		ctx = spanCtx
	}

	// Store locally if applicable
	if err := h.storeLocally(operation, messageID, data); err != nil {
		h.logger.Warn("Failed to store %s data locally: %v", operation, err)
	}

	// Send message
	if err := h.transport.Publish(ctx, h.topic, wrapper, qos); err != nil {
		return "", fmt.Errorf("failed to publish UEP %s: %w", operation, err)
	}

	// Record metrics
	if h.telemetry != nil {
		latencyMs := float64(time.Since(startTime).Nanoseconds()) / 1e6
		h.telemetry.RecordOperationLatency(operation, latencyMs, map[string]string{
			"success":    "true",
			"message_id": messageID,
		})
	}

	h.logger.Info("Executed UEP %s operation with ID %s", operation, messageID)
	return messageID, nil
}

func (h *UEPHandler) storeLocally(operation, messageID string, data map[string]interface{}) error {
	switch operation {
	case UEPOperationMemoryPut:
		tensorData, _ := data["tensor_zstd"].([]byte)
		metadata := map[string]interface{}{
			"frame_id":     data["frame_id"],
			"shape":        data["shape"],
			"dtype":        data["dtype"],
			"timestamp_ns": data["timestamp_ns"],
		}
		return h.storage.Store("memory", messageID, tensorData, metadata)

	case UEPOperationPerception:
		frameID, _ := data["frame_id"].(string)
		return h.storage.Store("perception", frameID, data, nil)

	case UEPOperationAction:
		metadata := map[string]interface{}{
			"action_type": data["action_type"],
		}
		return h.storage.Store("action", messageID, data, metadata)

	case UEPOperationCoordinate:
		return h.storage.Store("coordination", messageID, data, nil)

	case UEPOperationTrust:
		identity, _ := data["identity"].(string)
		return h.storage.Store("trust", identity, data, nil)

	case UEPOperationTelemetry:
		metadata := map[string]interface{}{
			"metric_type": data["metric_type"],
		}
		return h.storage.Store("telemetry", messageID, data, metadata)
	}

	return nil
}

// ========== UNIFIED LISTENING ==========

// UEPHandlers contains handlers for different UEP operations.
type UEPHandlers struct {
	PromptHandlers       []func(context.Context, *pb.MCP, map[string]interface{}) error
	MemoryPutHandlers    []func(context.Context, *pb.MCP, map[string]interface{}) error
	MemoryQueryHandlers  []func(context.Context, *pb.MCP, map[string]interface{}) error
	MemoryDeleteHandlers []func(context.Context, *pb.MCP, map[string]interface{}) error
	ActionHandlers       []func(context.Context, *pb.MCP, map[string]interface{}) error
	PerceptionHandlers   []func(context.Context, *pb.MCP, map[string]interface{}) error
	CoordinateHandlers   []func(context.Context, *pb.MCP, map[string]interface{}) error
	TrustHandlers        []func(context.Context, *pb.MCP, map[string]interface{}) error
	TelemetryHandlers    []func(context.Context, *pb.MCP, map[string]interface{}) error
}

// Listen starts listening for UEP messages and routes them based on operation type.
func (h *UEPHandler) Listen(
	ctx context.Context,
	handlers *UEPHandlers,
	qos map[string]interface{},
) error {
	if handlers == nil {
		return errors.New("handlers cannot be nil")
	}

	// Define unified message handler
	uepHandler := func(ctx context.Context, wrapperMessage *pb.MCP) error {
		// Create telemetry span
		var spanCtx context.Context
		var span trace.Span
		if h.telemetry != nil {
			operation := "unknown"
			if wrapperMessage.Meta != nil {
				operation = wrapperMessage.Meta["uep_operation"]
			}
			spanCtx, span = h.telemetry.CreateSpan(ctx, fmt.Sprintf("uep.receive.%s", operation), trace.SpanKindConsumer, map[string]interface{}{
				"topic":      h.topic,
				"message_id": wrapperMessage.Id,
				"operation":  operation,
			})
			defer span.End()
			ctx = spanCtx
		}

		// Extract operation type
		operation := UEPOperationPrompt // Default
		if wrapperMessage.Meta != nil {
			if op, ok := wrapperMessage.Meta["uep_operation"]; ok {
				operation = op
			}
		}

		// Deserialize operation data
		var operationData map[string]interface{}
		if len(wrapperMessage.ToolJson) > 0 {
			if err := h.serializer.Deserialize(wrapperMessage.ToolJson, &operationData); err != nil {
				h.logger.Error("Failed to deserialize operation data: %v", err)
				if span != nil {
					span.RecordError(err)
				}
				return err
			}
		}

		// Route to appropriate handlers
		var handlerList []func(context.Context, *pb.MCP, map[string]interface{}) error
		switch operation {
		case UEPOperationPrompt:
			handlerList = handlers.PromptHandlers
		case UEPOperationMemoryPut:
			handlerList = handlers.MemoryPutHandlers
		case UEPOperationMemoryQuery:
			handlerList = handlers.MemoryQueryHandlers
		case UEPOperationMemoryDelete:
			handlerList = handlers.MemoryDeleteHandlers
		case UEPOperationAction:
			handlerList = handlers.ActionHandlers
		case UEPOperationPerception:
			handlerList = handlers.PerceptionHandlers
		case UEPOperationCoordinate:
			handlerList = handlers.CoordinateHandlers
		case UEPOperationTrust:
			handlerList = handlers.TrustHandlers
		case UEPOperationTelemetry:
			handlerList = handlers.TelemetryHandlers
		default:
			h.logger.Warn("Unknown UEP operation: %s", operation)
			return nil
		}

		// Call all handlers for this operation
		for _, handler := range handlerList {
			if err := handler(ctx, wrapperMessage, operationData); err != nil {
				h.logger.Error("Error in UEP handler for %s: %v", operation, err)
				if span != nil {
					span.RecordError(err)
				}
			}
		}

		return nil
	}

	// Subscribe to unified topic
	if err := h.transport.Subscribe(ctx, h.topic, &pb.MCP{}, uepHandler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to UEP topic: %w", err)
	}

	h.logger.Info("Listening for UEP messages on topic %s", h.topic)
	return nil
}

// ========== UTILITY METHODS ==========

// ValidateMessage validates a UEP message.
func (h *UEPHandler) ValidateMessage(wrapperMessage *pb.MCP) error {
	if wrapperMessage == nil {
		return errors.New("UEP message cannot be nil")
	}

	if wrapperMessage.Spec != "uep/1.0" {
		return fmt.Errorf("invalid UEP spec: %s", wrapperMessage.Spec)
	}

	if wrapperMessage.Id == "" {
		return errors.New("UEP message ID cannot be empty")
	}

	if wrapperMessage.Meta == nil {
		return errors.New("UEP message must have metadata")
	}

	operation, ok := wrapperMessage.Meta["uep_operation"]
	if !ok {
		return errors.New("UEP message must specify operation type")
	}

	validOperations := []string{
		UEPOperationPrompt, UEPOperationMemoryPut, UEPOperationMemoryQuery,
		UEPOperationMemoryDelete, UEPOperationAction, UEPOperationPerception,
		UEPOperationCoordinate, UEPOperationTrust, UEPOperationTelemetry,
	}

	for _, validOp := range validOperations {
		if operation == validOp {
			return nil
		}
	}

	return fmt.Errorf("invalid UEP operation: %s", operation)
}

// QueryUnified queries any type of stored data.
func (h *UEPHandler) QueryUnified(dataType string, queryParams map[string]interface{}) ([]interface{}, error) {
	return h.storage.Query(dataType, queryParams)
}

// GetStats returns unified statistics.
func (h *UEPHandler) GetStats() map[string]interface{} {
	h.storage.mu.RLock()
	defer h.storage.mu.RUnlock()

	return map[string]interface{}{
		"memory_embeddings":  len(h.storage.memoryEmbeddings),
		"perception_data":    len(h.storage.perceptionData),
		"action_history":     len(h.storage.actionHistory),
		"coordination_state": len(h.storage.coordinationState),
		"trust_credentials":  len(h.storage.trustCredentials),
		"telemetry_data":     len(h.storage.telemetryData),
	}
}

// Close closes the UEP handler and releases resources.
func (h *UEPHandler) Close() error {
	h.storage.mu.Lock()
	defer h.storage.mu.Unlock()

	// Clear all storage
	h.storage.memoryEmbeddings = h.storage.memoryEmbeddings[:0]
	h.storage.perceptionData = make(map[string]PerceptionEntry)
	h.storage.actionHistory = h.storage.actionHistory[:0]
	h.storage.coordinationState = make(map[string]CoordinationEntry)
	h.storage.trustCredentials = make(map[string]TrustEntry)
	h.storage.telemetryData = h.storage.telemetryData[:0]

	h.logger.Info("UEP handler closed")
	return nil
}

// Backward compatibility aliases
type UCPHandler = UEPHandler // For transition period