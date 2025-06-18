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
	"github.com/ecps/ecps-go/pkg/perception"
	pb "github.com/ecps/ecps-go/proto"
)

// MEP operation types
const (
	MEPOperationCreate = "create"
	MEPOperationUpdate = "update"
	MEPOperationDelete = "delete"
	MEPOperationQuery  = "query"
)

// MEPHandler handles Memory Event Protocol (MEP) messages.
type MEPHandler struct {
	transport  core.Transport
	serializer core.Serializer
	telemetry  core.Telemetry
	logger     core.Logger
	topic      string
	// Optional in-memory storage for small deployments
	memoryStore map[string][]byte
	metadataStore map[string]*MemoryEventMetadata
}

// NewMEPHandler creates a new MEPHandler.
func NewMEPHandler(
	transport core.Transport,
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	options ...MEPOption,
) (*MEPHandler, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}

	// Default configuration
	handler := &MEPHandler{
		transport:     transport,
		serializer:    serializer,
		telemetry:     telemetry,
		logger:        logger,
		topic:         "mep", // Default topic
		memoryStore:   make(map[string][]byte),
		metadataStore: make(map[string]*MemoryEventMetadata),
	}

	// Apply options
	for _, opt := range options {
		opt(handler)
	}

	return handler, nil
}

// MEPOption is a function that configures an MEPHandler.
type MEPOption func(*MEPHandler)

// WithMEPTopic sets the topic for MEP messages.
func WithMEPTopic(topic string) MEPOption {
	return func(h *MEPHandler) {
		h.topic = topic
	}
}

// WithInMemoryStorage enables or disables in-memory storage.
func WithInMemoryStorage(enabled bool) MEPOption {
	return func(h *MEPHandler) {
		if !enabled {
			h.memoryStore = nil
			h.metadataStore = nil
		} else if h.memoryStore == nil {
			h.memoryStore = make(map[string][]byte)
			h.metadataStore = make(map[string]*MemoryEventMetadata)
		}
	}
}

// MemoryEventMetadata contains metadata for a memory event.
type MemoryEventMetadata struct {
	ContentType     string            `json:"content_type,omitempty"`
	ContentEncoding string            `json:"content_encoding,omitempty"`
	Labels          map[string]string `json:"labels,omitempty"`
	Vector          []float32         `json:"vector,omitempty"`
	Timestamp       time.Time         `json:"timestamp,omitempty"`
	TTL             int64             `json:"ttl,omitempty"` // Time-to-live in seconds
}

// CreateMemoryEvent creates a new MEP memory event.
func (h *MEPHandler) CreateMemoryEvent(
	operation string,
	memoryID string,
	content []byte,
	metadata *MemoryEventMetadata,
	correlationID string,
) (*pb.MEP, error) {
	// Validate operation
	if operation != MEPOperationCreate && 
	   operation != MEPOperationUpdate && 
	   operation != MEPOperationDelete && 
	   operation != MEPOperationQuery {
		return nil, fmt.Errorf("invalid MEP operation: %s", operation)
	}

	// Generate memory ID if not provided
	if memoryID == "" {
		uuid, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		memoryID = uuid.String()
	}

	// Generate correlation ID if not provided
	if correlationID == "" {
		uuid, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		correlationID = uuid.String()
	}

	// Set timestamp if not provided
	if metadata != nil && metadata.Timestamp.IsZero() {
		metadata.Timestamp = time.Now()
	}

	// Serialize metadata
	var metadataBytes []byte
	var err error
	if metadata != nil {
		metadataBytes, err = json.Marshal(metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
	}

	// Create MEP message
	mep := &pb.MEP{
		Spec:          "mep/1.0",
		Id:            memoryID,
		Operation:     operation,
		Content:       content,
		Metadata:      metadataBytes,
		CorrelationId: correlationID,
	}

	// Record metrics if telemetry is available
	if h.telemetry != nil {
		attrs := map[string]string{
			"id":             memoryID,
			"operation":      operation,
			"correlation_id": correlationID,
		}
		h.telemetry.RecordMEPEventSize(len(content), attrs)
	}

	return mep, nil
}

// SendMemoryEvent sends a memory event.
func (h *MEPHandler) SendMemoryEvent(
	ctx context.Context,
	operation string,
	memoryID string,
	content []byte,
	metadata *MemoryEventMetadata,
	correlationID string,
	qos map[string]interface{},
) (string, error) {
	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "mep.send", trace.SpanKindProducer, map[string]interface{}{
			"topic":          h.topic,
			"memory_id":      memoryID,
			"operation":      operation,
			"correlation_id": correlationID,
			"content_size":   len(content),
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create MEP message
	mep, err := h.CreateMemoryEvent(operation, memoryID, content, metadata, correlationID)
	if err != nil {
		return "", fmt.Errorf("failed to create MEP message: %w", err)
	}

	// Build operation-specific topic
	operationTopic := fmt.Sprintf("%s/%s", h.topic, operation)

	// Publish message
	if err := h.transport.Publish(ctx, operationTopic, mep, qos); err != nil {
		return "", fmt.Errorf("failed to publish MEP message: %w", err)
	}

	h.logger.Info("Sent MEP %s event with ID %s", operation, memoryID)
	return memoryID, nil
}

// CreateMemory creates a new memory entry.
func (h *MEPHandler) CreateMemory(
	ctx context.Context, 
	content []byte, 
	metadata *MemoryEventMetadata,
	qos map[string]interface{},
) (string, error) {
	memoryID, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID: %w", err)
	}

	// If using in-memory store, store the memory directly
	if h.memoryStore != nil {
		h.memoryStore[memoryID.String()] = content
		if metadata != nil {
			h.metadataStore[memoryID.String()] = metadata
		}
	}

	return h.SendMemoryEvent(
		ctx,
		MEPOperationCreate,
		memoryID.String(),
		content,
		metadata,
		"",
		qos,
	)
}

// UpdateMemory updates an existing memory entry.
func (h *MEPHandler) UpdateMemory(
	ctx context.Context,
	memoryID string,
	content []byte,
	metadata *MemoryEventMetadata,
	qos map[string]interface{},
) error {
	// If using in-memory store, update the memory directly
	if h.memoryStore != nil {
		if _, exists := h.memoryStore[memoryID]; !exists {
			return fmt.Errorf("memory ID %s not found", memoryID)
		}
		h.memoryStore[memoryID] = content
		if metadata != nil {
			h.metadataStore[memoryID] = metadata
		}
	}

	_, err := h.SendMemoryEvent(
		ctx,
		MEPOperationUpdate,
		memoryID,
		content,
		metadata,
		"",
		qos,
	)
	return err
}

// DeleteMemory deletes a memory entry.
func (h *MEPHandler) DeleteMemory(
	ctx context.Context,
	memoryID string,
	qos map[string]interface{},
) error {
	// If using in-memory store, delete the memory directly
	if h.memoryStore != nil {
		if _, exists := h.memoryStore[memoryID]; !exists {
			return fmt.Errorf("memory ID %s not found", memoryID)
		}
		delete(h.memoryStore, memoryID)
		delete(h.metadataStore, memoryID)
	}

	_, err := h.SendMemoryEvent(
		ctx,
		MEPOperationDelete,
		memoryID,
		nil,
		nil,
		"",
		qos,
	)
	return err
}

// QueryParams defines parameters for memory queries.
type QueryParams struct {
	Limit       int                `json:"limit,omitempty"`
	Offset      int                `json:"offset,omitempty"`
	TimeRange   [2]time.Time       `json:"time_range,omitempty"`
	Labels      map[string]string  `json:"labels,omitempty"`
	ContentType string             `json:"content_type,omitempty"`
	SimilarTo   []float32          `json:"similar_to,omitempty"`
	Threshold   float32            `json:"threshold,omitempty"`
}

// QueryMemory sends a memory query.
func (h *MEPHandler) QueryMemory(
	ctx context.Context,
	params QueryParams,
	qos map[string]interface{},
) (string, error) {
	// Convert query params to JSON
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("failed to marshal query parameters: %w", err)
	}

	// Create metadata
	metadata := &MemoryEventMetadata{
		ContentType: "application/json",
		Timestamp:   time.Now(),
	}

	// Generate correlation ID for tracking query results
	correlationID, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate correlation ID: %w", err)
	}

	// If using in-memory store, perform query directly
	if h.memoryStore != nil {
		go func() {
			// Process query in background
			h.processInMemoryQuery(ctx, params, correlationID.String(), qos)
		}()
	}

	return h.SendMemoryEvent(
		ctx,
		MEPOperationQuery,
		"",
		paramsBytes,
		metadata,
		correlationID.String(),
		qos,
	)
}

// processInMemoryQuery processes a query against the in-memory store.
func (h *MEPHandler) processInMemoryQuery(
	ctx context.Context,
	params QueryParams,
	correlationID string,
	qos map[string]interface{},
) {
	if h.memoryStore == nil {
		return
	}

	results := 0
	for memoryID, content := range h.memoryStore {
		metadata, exists := h.metadataStore[memoryID]
		
		// Apply filters
		if params.ContentType != "" && (!exists || metadata.ContentType != params.ContentType) {
			continue
		}

		if len(params.Labels) > 0 && exists {
			match := true
			for k, v := range params.Labels {
				if metadata.Labels[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		if !params.TimeRange[0].IsZero() && !params.TimeRange[1].IsZero() && exists {
			if metadata.Timestamp.Before(params.TimeRange[0]) || metadata.Timestamp.After(params.TimeRange[1]) {
				continue
			}
		}

		// Vector similarity check if needed
		if len(params.SimilarTo) > 0 && exists && metadata.Vector != nil {
			similarity := cosineSimilarity(params.SimilarTo, metadata.Vector)
			if similarity < params.Threshold {
				continue
			}
		}

		// Send result
		if err := h.SendQueryResult(ctx, correlationID, memoryID, content, metadata, qos); err != nil {
			h.logger.Error("Error sending query result: %v", err)
			continue
		}

		results++
		if params.Limit > 0 && results >= params.Limit {
			break
		}
	}

	h.logger.Debug("In-memory query returned %d results for correlation ID %s", results, correlationID)
}

// cosineSimilarity calculates the cosine similarity between two vectors.
func cosineSimilarity(a, b []float32) float32 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}

	var dotProduct float32
	var normA float32
	var normB float32

	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}

	if normA == 0 || normB == 0 {
		return 0
	}

	return dotProduct / (float32(sqrt(float64(normA))) * float32(sqrt(float64(normB))))
}

// sqrt is a helper function for square root calculation.
func sqrt(x float64) float64 {
	return float64(int(x*1000000)) / 1000000
}

// ListenForOperation starts listening for specific MEP operations.
func (h *MEPHandler) ListenForOperation(
	ctx context.Context,
	operation string,
	handler func(context.Context, *pb.MEP) error,
	qos map[string]interface{},
) error {
	// Validate operation
	if operation != MEPOperationCreate && 
	   operation != MEPOperationUpdate && 
	   operation != MEPOperationDelete && 
	   operation != MEPOperationQuery {
		return fmt.Errorf("invalid MEP operation: %s", operation)
	}

	// Build operation-specific topic
	operationTopic := fmt.Sprintf("%s/%s", h.topic, operation)

	// Define message handler
	mepHandler := func(ctx context.Context, mepMessage *pb.MEP) error {
		// Create a span if telemetry is available
		var spanCtx context.Context
		var span trace.Span
		if h.telemetry != nil {
			spanCtx, span = h.telemetry.CreateSpan(ctx, "mep.receive", trace.SpanKindConsumer, map[string]interface{}{
				"topic":          operationTopic,
				"memory_id":      mepMessage.Id,
				"operation":      mepMessage.Operation,
				"correlation_id": mepMessage.CorrelationId,
				"content_size":   len(mepMessage.Content),
			})
			defer span.End()
			ctx = spanCtx
		}

		// Process in-memory operations if enabled
		if h.memoryStore != nil && operation != MEPOperationQuery {
			metadata, _ := h.ParseMetadata(mepMessage)
			
			switch operation {
			case MEPOperationCreate:
				h.memoryStore[mepMessage.Id] = mepMessage.Content
				if metadata != nil {
					h.metadataStore[mepMessage.Id] = metadata
				}
			case MEPOperationUpdate:
				h.memoryStore[mepMessage.Id] = mepMessage.Content
				if metadata != nil {
					h.metadataStore[mepMessage.Id] = metadata
				}
			case MEPOperationDelete:
				delete(h.memoryStore, mepMessage.Id)
				delete(h.metadataStore, mepMessage.Id)
			}
		}

		// Call the handler
		if err := handler(ctx, mepMessage); err != nil {
			h.logger.Error("Error in MEP handler: %v", err)
			if span != nil {
				span.RecordError(err)
			}
			return err
		}

		return nil
	}

	// Subscribe to topic
	if err := h.transport.Subscribe(ctx, operationTopic, &pb.MEP{}, mepHandler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to MEP topic %s: %w", operationTopic, err)
	}

	h.logger.Info("Listening for MEP %s operations on topic %s", operation, operationTopic)
	return nil
}

// ListenForQueryResults starts listening for query results.
func (h *MEPHandler) ListenForQueryResults(
	ctx context.Context,
	correlationID string,
	handler func(context.Context, *pb.MEP) error,
	qos map[string]interface{},
) error {
	// Build results topic
	resultsTopic := fmt.Sprintf("%s/results/%s", h.topic, correlationID)

	// Subscribe to results topic
	if err := h.transport.Subscribe(ctx, resultsTopic, &pb.MEP{}, handler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to MEP results topic: %w", err)
	}

	h.logger.Info("Listening for MEP query results on topic %s", resultsTopic)
	return nil
}

// SendQueryResult sends a query result.
func (h *MEPHandler) SendQueryResult(
	ctx context.Context,
	correlationID string,
	memoryID string,
	content []byte,
	metadata *MemoryEventMetadata,
	qos map[string]interface{},
) error {
	// Build results topic
	resultsTopic := fmt.Sprintf("%s/results/%s", h.topic, correlationID)

	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "mep.send_result", trace.SpanKindProducer, map[string]interface{}{
			"topic":          resultsTopic,
			"memory_id":      memoryID,
			"correlation_id": correlationID,
			"content_size":   len(content),
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create MEP message for result
	mep, err := h.CreateMemoryEvent(MEPOperationQuery, memoryID, content, metadata, correlationID)
	if err != nil {
		return fmt.Errorf("failed to create MEP result message: %w", err)
	}

	// Publish result
	if err := h.transport.Publish(ctx, resultsTopic, mep, qos); err != nil {
		return fmt.Errorf("failed to publish MEP result message: %w", err)
	}

	h.logger.Info("Sent MEP query result for memory ID %s, correlation ID %s", memoryID, correlationID)
	return nil
}

// ParseMetadata parses the metadata from an MEP message.
func (h *MEPHandler) ParseMetadata(mep *pb.MEP) (*MemoryEventMetadata, error) {
	if mep == nil {
		return nil, errors.New("MEP message cannot be nil")
	}

	if len(mep.Metadata) == 0 {
		return nil, nil
	}

	var metadata MemoryEventMetadata
	if err := json.Unmarshal(mep.Metadata, &metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return &metadata, nil
}

// ValidateMEPMessage validates an MEP message.
func (h *MEPHandler) ValidateMEPMessage(mep *pb.MEP) error {
	if mep == nil {
		return errors.New("MEP message cannot be nil")
	}

	if mep.Spec != "mep/1.0" {
		return fmt.Errorf("invalid MEP spec: %s", mep.Spec)
	}

	if mep.Operation != MEPOperationCreate && 
	   mep.Operation != MEPOperationUpdate && 
	   mep.Operation != MEPOperationDelete && 
	   mep.Operation != MEPOperationQuery {
		return fmt.Errorf("invalid MEP operation: %s", mep.Operation)
	}

	// For create and update operations, content should not be empty
	if (mep.Operation == MEPOperationCreate || mep.Operation == MEPOperationUpdate) && len(mep.Content) == 0 {
		return errors.New("content cannot be empty for create or update operations")
	}

	// For delete operation, ID should not be empty
	if mep.Operation == MEPOperationDelete && mep.Id == "" {
		return errors.New("memory ID cannot be empty for delete operation")
	}

	// For query operation, correlation ID should not be empty
	if mep.Operation == MEPOperationQuery && mep.CorrelationId == "" {
		return errors.New("correlation ID cannot be empty for query operation")
	}

	return nil
}
// Consistency Model
// Define the consistency model for the Memory Exchange Protocol (MEP).
const (
    ConsistencyModelStrong  = "strong"
    ConsistencyModelEventual = "eventual"
)

// Update the CreateMemoryEvent method to include consistency
func (h *MEPHandler) CreateMemoryEvent(
    operation string,
    memoryID string,
    content []byte,
    metadata *MemoryEventMetadata,
    correlationID string,
    consistency string, // New parameter for consistency
) (*pb.MEP, error) {
    // Existing validation logic...

    // Implement logic for strong consistency if required
    if consistency == ConsistencyModelStrong {
        // Placeholder for strong consistency logic
    }

    // Existing message creation logic...
}

// Update the SendMemoryEvent method to include consistency
func (h *MEPHandler) SendMemoryEvent(
    ctx context.Context,
    operation string,
    memoryID string,
    content []byte,
    metadata *MemoryEventMetadata,
    correlationID string,
    qos map[string]interface{},
    consistency string, // New parameter for consistency
) (string, error) {
    // Existing logic...

    // Create MEP message with consistency
    mep, err := h.CreateMemoryEvent(operation, memoryID, content, metadata, correlationID, consistency)
    if err != nil {
        return "", fmt.Errorf("failed to create MEP message: %w", err)
    }

    // Existing publish logic...
}

// Update the QueryMemory method to include consistency
func (h *MEPHandler) QueryMemory(
    ctx context.Context,
    params QueryParams,
    qos map[string]interface{},
    consistency string, // New parameter for consistency
) (string, error) {
    // Existing logic...

    // Implement logic for strong consistency if required
    if consistency == ConsistencyModelStrong {
        // Placeholder for strong consistency logic
    }

    // Existing message creation logic...
}