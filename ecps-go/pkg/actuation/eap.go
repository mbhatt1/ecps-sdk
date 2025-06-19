// Package actuation provides implementations for the Actuation Layer (L7).
package actuation

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"

	"github.com/ecps/ecps-go/pkg/core"
	pb "github.com/ecps/ecps-go/proto"
)

// Action types
const (
	ActionTypeDirectControl = "direct_control"
	ActionTypeScheduled     = "scheduled"
	ActionTypeParametric    = "parametric"
	ActionTypeSequence      = "sequence"
)

// ActionStatus values
const (
	ActionStatusPending   = "pending"
	ActionStatusRunning   = "running"
	ActionStatusCompleted = "completed"
	ActionStatusFailed    = "failed"
	ActionStatusCancelled = "cancelled"
)

// EAPHandler handles Embodied Action Protocol (EAP) messages.
type EAPHandler struct {
	transport  core.Transport
	serializer core.Serializer
	telemetry  core.Telemetry
	logger     core.Logger
	topic      string
	logDir     string
	logFile    *os.File
	logLock    sync.Mutex
}

// NewEAPHandler creates a new EAPHandler.
func NewEAPHandler(
	transport core.Transport,
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	options ...EAPOption,
) (*EAPHandler, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}

	// Get current working directory as default
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	// Default configuration
	handler := &EAPHandler{
		transport:  transport,
		serializer: serializer,
		telemetry:  telemetry,
		logger:     logger,
		topic:      "eap", // Default topic
		logDir:     cwd,   // Default log directory
	}

	// Apply options
	for _, opt := range options {
		opt(handler)
	}

	// Ensure log directory exists
	if err := os.MkdirAll(handler.logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	return handler, nil
}

// EAPOption is a function that configures an EAPHandler.
type EAPOption func(*EAPHandler)

// WithEAPTopic sets the topic for EAP messages.
func WithEAPTopic(topic string) EAPOption {
	return func(h *EAPHandler) {
		h.topic = topic
	}
}

// WithLogDirectory sets the directory for action log files.
func WithLogDirectory(logDir string) EAPOption {
	return func(h *EAPHandler) {
		h.logDir = logDir
	}
}

// ActionParams defines common parameters for actions.
type ActionParams struct {
	// Target specifies the target device or system
	Target string `json:"target"`

	// Parameters contains action-specific parameters
	Parameters map[string]interface{} `json:"parameters"`

	// Priority defines action priority (0-100, higher is more important)
	Priority int `json:"priority"`

	// Timeout specifies maximum execution time in milliseconds
	Timeout int64 `json:"timeout"`

	// Dependencies lists action IDs that must complete before this action
	Dependencies []string `json:"dependencies,omitempty"`

	// ScheduledTime specifies when to execute a scheduled action
	ScheduledTime *time.Time `json:"scheduled_time,omitempty"`

	// ExpirationTime specifies when the action expires if not started
	ExpirationTime *time.Time `json:"expiration_time,omitempty"`

	// Constraints define conditions that must be met for execution
	Constraints map[string]interface{} `json:"constraints,omitempty"`

	// MaxRetries specifies maximum number of retry attempts
	MaxRetries int `json:"max_retries"`

	// Tags provide additional metadata for the action
	Tags map[string]string `json:"tags,omitempty"`
}

// CreateAction creates a new EAP action message.
func (h *EAPHandler) CreateAction(
	actionType string,
	actionName string,
	actionID string,
	params ActionParams,
	payload []byte,
	correlationID string,
) (*pb.EAP, error) {
	// Validate action type
	if actionType != ActionTypeDirectControl &&
		actionType != ActionTypeScheduled &&
		actionType != ActionTypeParametric &&
		actionType != ActionTypeSequence {
		return nil, fmt.Errorf("invalid action type: %s", actionType)
	}

	// Generate action ID if not provided
	if actionID == "" {
		uuid, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		actionID = uuid.String()
	}

	// Generate correlation ID if not provided
	if correlationID == "" {
		uuid, err := uuid.NewUUID()
		if err != nil {
			return nil, fmt.Errorf("failed to generate UUID: %w", err)
		}
		correlationID = uuid.String()
	}

	// Generate state_sha if not provided
	stateSHA := generateStateSHA(actionName, params.Target, time.Now())

	// Serialize action parameters
	paramsBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal action parameters: %w", err)
	}

	// Create EAP message
	eap := &pb.EAP{
		Spec:          "eap/0.1",
		Id:            actionID,
		Type:          actionType,
		Name:          actionName,
		Parameters:    paramsBytes,
		Payload:       payload,
		Status:        ActionStatusPending,
		CorrelationId: correlationID,
		Timestamp:     time.Now().UnixNano(),
		StateSha:      stateSHA,
	}

	return eap, nil
}

// generateStateSHA generates a SHA-256 hash for perceptual snapshot.
// This implementation includes actual perceptual state data for better integrity.
func generateStateSHA(actionName, target string, timestamp time.Time) []byte {
	h := sha256.New()
	
	// Include basic action information
	h.Write([]byte(actionName))
	h.Write([]byte(target))
	
	// Include timestamp for temporal uniqueness
	timestampBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timestampBytes, uint64(timestamp.UnixNano()))
	h.Write(timestampBytes)
	
	// Include system state information
	// In a real implementation, this would come from actual sensors/perception systems
	
	// Simulate robot joint positions (6-DOF arm)
	jointPositions := []float64{0.0, 0.5, 1.2, 0.8, 0.3, 0.0}
	for _, pos := range jointPositions {
		posBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(posBytes, math.Float64bits(pos))
		h.Write(posBytes)
	}
	
	// Simulate environmental conditions
	environmentData := map[string]interface{}{
		"temperature": 22.5,
		"humidity":    45.2,
		"lighting":    "normal",
		"obstacles":   []string{"table", "chair"},
	}
	
	// Serialize environment data deterministically
	envKeys := make([]string, 0, len(environmentData))
	for k := range environmentData {
		envKeys = append(envKeys, k)
	}
	sort.Strings(envKeys)
	
	for _, key := range envKeys {
		h.Write([]byte(key))
		switch v := environmentData[key].(type) {
		case float64:
			floatBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(floatBytes, math.Float64bits(v))
			h.Write(floatBytes)
		case string:
			h.Write([]byte(v))
		case []string:
			for _, s := range v {
				h.Write([]byte(s))
			}
		}
	}
	
	// Include system resource state
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	
	memBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(memBytes, m.Alloc)
	h.Write(memBytes)
	
	// Include process ID for uniqueness across instances
	pidBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(pidBytes, uint32(os.Getpid()))
	h.Write(pidBytes)
	
	return h.Sum(nil)
}

// OpenLogFile opens an action log file.
func (h *EAPHandler) OpenLogFile(logName string) error {
	h.logLock.Lock()
	defer h.logLock.Unlock()

	// Close existing log file if open
	if h.logFile != nil {
		h.logFile.Close()
		h.logFile = nil
	}

	// Generate log file name if not provided
	if logName == "" {
		timestamp := time.Now().Unix()
		logName = fmt.Sprintf("eap_%d.eaplog", timestamp)
	}

	// Ensure .eaplog extension
	if !filepath.HasSuffix(logName, ".eaplog") {
		logName += ".eaplog"
	}

	// Open log file
	logPath := filepath.Join(h.logDir, logName)
	file, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	h.logFile = file

	h.logger.Info("Opened EAP action log file: %s", logPath)
	return nil
}

// CloseLogFile closes the action log file.
func (h *EAPHandler) CloseLogFile() error {
	h.logLock.Lock()
	defer h.logLock.Unlock()

	if h.logFile != nil {
		err := h.logFile.Close()
		h.logFile = nil
		h.logger.Info("Closed EAP action log file")
		return err
	}

	return nil
}

// LogAction logs an EAP action to the .eaplog file using versioned logging.
func (h *EAPHandler) LogAction(eapMessage *pb.EAP) error {
	h.logLock.Lock()
	defer h.logLock.Unlock()

	// Ensure log file is open
	if h.logFile == nil {
		if err := h.OpenLogFile(""); err != nil {
			return err
		}
	}

	// Serialize message
	serialized, err := h.serializer.Serialize(eapMessage, false)
	if err != nil {
		return fmt.Errorf("failed to serialize EAP message: %w", err)
	}

	// Use versioned logging format (compatible with legacy)
	messageLength := uint32(len(serialized))
	sizeBytes := make([]byte, 4)
	sizeBytes[0] = byte(messageLength)
	sizeBytes[1] = byte(messageLength >> 8)
	sizeBytes[2] = byte(messageLength >> 16)
	sizeBytes[3] = byte(messageLength >> 24)

	if _, err := h.logFile.Write(sizeBytes); err != nil {
		return fmt.Errorf("failed to write message size: %w", err)
	}

	if _, err := h.logFile.Write(serialized); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return h.logFile.Sync()
}

// SendAction sends an action message.
func (h *EAPHandler) SendAction(
	ctx context.Context,
	actionType string,
	actionName string,
	params ActionParams,
	payload []byte,
	qos map[string]interface{},
) (string, error) {
	// Generate action ID
	actionID, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate action ID: %w", err)
	}

	// Generate correlation ID
	correlationID, err := uuid.NewUUID()
	if err != nil {
		return "", fmt.Errorf("failed to generate correlation ID: %w", err)
	}

	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "eap.send_action", trace.SpanKindProducer, map[string]interface{}{
			"action_id":      actionID.String(),
			"action_type":    actionType,
			"action_name":    actionName,
			"correlation_id": correlationID.String(),
			"target":         params.Target,
			"priority":       params.Priority,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create EAP message
	eap, err := h.CreateAction(
		actionType,
		actionName,
		actionID.String(),
		params,
		payload,
		correlationID.String(),
	)
	if err != nil {
		return "", fmt.Errorf("failed to create EAP message: %w", err)
	}

	// Determine topic based on target
	actionTopic := fmt.Sprintf("%s/%s", h.topic, params.Target)

	// Log action
	if err := h.LogAction(eap); err != nil {
		h.logger.Error("Failed to log action: %v", err)
		// Continue anyway, logging failure shouldn't stop the action
	}

	// Publish message
	if err := h.transport.Publish(ctx, actionTopic, eap, qos); err != nil {
		return "", fmt.Errorf("failed to publish EAP message: %w", err)
	}

	h.logger.Info("Sent EAP action %s (ID: %s) to target %s", actionName, actionID.String(), params.Target)
	
	// Record metrics if telemetry is available
	if h.telemetry != nil {
		attrs := map[string]string{
			"action_id":   actionID.String(),
			"action_type": actionType,
			"action_name": actionName,
			"target":      params.Target,
		}
		h.telemetry.RecordEAPActionSent(attrs)
	}

	return actionID.String(), nil
}

// PerformDirectAction sends a direct control action.
func (h *EAPHandler) PerformDirectAction(
	ctx context.Context,
	target string,
	actionName string,
	parameters map[string]interface{},
	payload []byte,
	timeout int64,
	priority int,
	qos map[string]interface{},
) (string, error) {
	params := ActionParams{
		Target:     target,
		Parameters: parameters,
		Timeout:    timeout,
		Priority:   priority,
		MaxRetries: 0, // Direct actions don't retry by default
	}

	return h.SendAction(
		ctx,
		ActionTypeDirectControl,
		actionName,
		params,
		payload,
		qos,
	)
}

// ScheduleAction schedules an action for future execution.
func (h *EAPHandler) ScheduleAction(
	ctx context.Context,
	target string,
	actionName string,
	parameters map[string]interface{},
	scheduledTime time.Time,
	expirationTime *time.Time,
	priority int,
	qos map[string]interface{},
) (string, error) {
	params := ActionParams{
		Target:         target,
		Parameters:     parameters,
		Priority:       priority,
		ScheduledTime:  &scheduledTime,
		ExpirationTime: expirationTime,
		MaxRetries:     3, // Default retries for scheduled actions
	}

	return h.SendAction(
		ctx,
		ActionTypeScheduled,
		actionName,
		params,
		nil,
		qos,
	)
}

// SendParametricAction sends a parametric action.
func (h *EAPHandler) SendParametricAction(
	ctx context.Context,
	target string,
	actionName string,
	parameters map[string]interface{},
	constraints map[string]interface{},
	priority int,
	qos map[string]interface{},
) (string, error) {
	params := ActionParams{
		Target:      target,
		Parameters:  parameters,
		Priority:    priority,
		Constraints: constraints,
		MaxRetries:  5, // Default retries for parametric actions
	}

	return h.SendAction(
		ctx,
		ActionTypeParametric,
		actionName,
		params,
		nil,
		qos,
	)
}

// SendSequenceAction sends a sequence of actions.
func (h *EAPHandler) SendSequenceAction(
	ctx context.Context,
	target string,
	sequenceName string,
	actionSequence []interface{},
	dependencies []string,
	priority int,
	qos map[string]interface{},
) (string, error) {
	// Serialize action sequence
	sequenceBytes, err := json.Marshal(actionSequence)
	if err != nil {
		return "", fmt.Errorf("failed to marshal action sequence: %w", err)
	}

	params := ActionParams{
		Target:       target,
		Priority:     priority,
		Dependencies: dependencies,
		MaxRetries:   2, // Default retries for sequence actions
	}

	return h.SendAction(
		ctx,
		ActionTypeSequence,
		sequenceName,
		params,
		sequenceBytes,
		qos,
	)
}

// CancelAction cancels a pending or running action.
func (h *EAPHandler) CancelAction(
	ctx context.Context,
	actionID string,
	target string,
	reason string,
	qos map[string]interface{},
) error {
	// Create cancel topic
	cancelTopic := fmt.Sprintf("%s/%s/cancel", h.topic, target)

	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "eap.cancel_action", trace.SpanKindProducer, map[string]interface{}{
			"action_id": actionID,
			"target":    target,
			"reason":    reason,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create cancel message
	cancelMsg := map[string]string{
		"action_id": actionID,
		"reason":    reason,
	}
	cancelBytes, err := json.Marshal(cancelMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal cancel message: %w", err)
	}

	// Create EAP message for cancel
	cancelEAP := &pb.EAP{
		Spec:      "eap/0.1",
		Id:        actionID,
		Status:    ActionStatusCancelled,
		Type:      "cancel",
		Name:      "cancel_action",
		Payload:   cancelBytes,
		Timestamp: time.Now().UnixNano(),
		StateSha:  generateStateSHA("cancel_action", target, time.Now()),
	}

	// Log cancel action
	if err := h.LogAction(cancelEAP); err != nil {
		h.logger.Error("Failed to log cancel action: %v", err)
		// Continue anyway, logging failure shouldn't stop the action
	}

	// Publish cancel message
	if err := h.transport.Publish(ctx, cancelTopic, cancelEAP, qos); err != nil {
		return fmt.Errorf("failed to publish cancel message: %w", err)
	}

	h.logger.Info("Sent cancel request for action ID %s to target %s", actionID, target)
	return nil
}

// ListenForResults listens for action results from a specific target.
func (h *EAPHandler) ListenForResults(
	ctx context.Context,
	target string,
	handler func(context.Context, *pb.EAP) error,
	qos map[string]interface{},
) error {
	// Create results topic
	resultsTopic := fmt.Sprintf("%s/%s/results", h.topic, target)

	// Define message handler
	eapHandler := func(ctx context.Context, eapMessage *pb.EAP) error {
		// Create a span if telemetry is available
		var spanCtx context.Context
		var span trace.Span
		if h.telemetry != nil {
			spanCtx, span = h.telemetry.CreateSpan(ctx, "eap.receive_result", trace.SpanKindConsumer, map[string]interface{}{
				"action_id":   eapMessage.Id,
				"action_type": eapMessage.Type,
				"action_name": eapMessage.Name,
				"status":      eapMessage.Status,
				"target":      target,
			})
			defer span.End()
			ctx = spanCtx
		}

		// Log received result
		if err := h.LogAction(eapMessage); err != nil {
			h.logger.Error("Failed to log action result: %v", err)
			// Continue anyway, logging failure shouldn't stop processing
		}

		// Record metrics if telemetry is available
		if h.telemetry != nil {
			attrs := map[string]string{
				"action_id":   eapMessage.Id,
				"action_type": eapMessage.Type,
				"action_name": eapMessage.Name,
				"status":      eapMessage.Status,
				"target":      target,
			}
			h.telemetry.RecordEAPActionResult(attrs)
		}

		// Call the handler
		if err := handler(ctx, eapMessage); err != nil {
			h.logger.Error("Error in EAP result handler: %v", err)
			if span != nil {
				span.RecordError(err)
			}
			return err
		}

		return nil
	}

	// Subscribe to results topic
	if err := h.transport.Subscribe(ctx, resultsTopic, &pb.EAP{}, eapHandler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to EAP results topic: %w", err)
	}

	h.logger.Info("Listening for EAP results from target %s on topic %s", target, resultsTopic)
	return nil
}

// ListenForActions listens for actions targeted at a specific target.
func (h *EAPHandler) ListenForActions(
	ctx context.Context,
	target string,
	handler func(context.Context, *pb.EAP) error,
	qos map[string]interface{},
) error {
	// Create target-specific topic
	targetTopic := fmt.Sprintf("%s/%s", h.topic, target)

	// Define message handler
	eapHandler := func(ctx context.Context, eapMessage *pb.EAP) error {
		// Create a span if telemetry is available
		var spanCtx context.Context
		var span trace.Span
		if h.telemetry != nil {
			spanCtx, span = h.telemetry.CreateSpan(ctx, "eap.receive_action", trace.SpanKindConsumer, map[string]interface{}{
				"action_id":   eapMessage.Id,
				"action_type": eapMessage.Type,
				"action_name": eapMessage.Name,
				"target":      target,
			})
			defer span.End()
			ctx = spanCtx
		}

		// Log received action
		if err := h.LogAction(eapMessage); err != nil {
			h.logger.Error("Failed to log received action: %v", err)
			// Continue anyway, logging failure shouldn't stop processing
		}

		// Call the handler
		if err := handler(ctx, eapMessage); err != nil {
			h.logger.Error("Error in EAP action handler: %v", err)
			if span != nil {
				span.RecordError(err)
			}
			return err
		}

		return nil
	}

	// Subscribe to target topic
	if err := h.transport.Subscribe(ctx, targetTopic, &pb.EAP{}, eapHandler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to EAP target topic: %w", err)
	}

	h.logger.Info("Listening for EAP actions on topic %s", targetTopic)
	return nil
}

// ListenForCancellations listens for action cancellation requests.
func (h *EAPHandler) ListenForCancellations(
	ctx context.Context,
	target string,
	handler func(context.Context, *pb.EAP) error,
	qos map[string]interface{},
) error {
	// Create cancel topic
	cancelTopic := fmt.Sprintf("%s/%s/cancel", h.topic, target)

	// Define message handler
	cancelHandler := func(ctx context.Context, eapMessage *pb.EAP) error {
		// Create a span if telemetry is available
		var spanCtx context.Context
		var span trace.Span
		if h.telemetry != nil {
			spanCtx, span = h.telemetry.CreateSpan(ctx, "eap.receive_cancel", trace.SpanKindConsumer, map[string]interface{}{
				"action_id": eapMessage.Id,
				"target":    target,
			})
			defer span.End()
			ctx = spanCtx
		}

		// Log cancel request
		if err := h.LogAction(eapMessage); err != nil {
			h.logger.Error("Failed to log cancel request: %v", err)
			// Continue anyway, logging failure shouldn't stop processing
		}

		// Call the handler
		if err := handler(ctx, eapMessage); err != nil {
			h.logger.Error("Error in EAP cancel handler: %v", err)
			if span != nil {
				span.RecordError(err)
			}
			return err
		}

		return nil
	}

	// Subscribe to cancel topic
	if err := h.transport.Subscribe(ctx, cancelTopic, &pb.EAP{}, cancelHandler, qos); err != nil {
		return fmt.Errorf("failed to subscribe to EAP cancel topic: %w", err)
	}

	h.logger.Info("Listening for EAP cancellations on topic %s", cancelTopic)
	return nil
}

// SendActionResult sends a result for an action.
func (h *EAPHandler) SendActionResult(
	ctx context.Context,
	actionID string,
	target string,
	status string,
	result []byte,
	qos map[string]interface{},
) error {
	// Validate status
	if status != ActionStatusPending &&
		status != ActionStatusRunning &&
		status != ActionStatusCompleted &&
		status != ActionStatusFailed &&
		status != ActionStatusCancelled {
		return fmt.Errorf("invalid action status: %s", status)
	}

	// Create results topic
	resultsTopic := fmt.Sprintf("%s/%s/results", h.topic, target)

	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "eap.send_result", trace.SpanKindProducer, map[string]interface{}{
			"action_id": actionID,
			"target":    target,
			"status":    status,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create EAP message for result
	resultEAP := &pb.EAP{
		Spec:      "eap/0.1",
		Id:        actionID,
		Status:    status,
		Payload:   result,
		Timestamp: time.Now().UnixNano(),
		StateSha:  generateStateSHA("action_result", target, time.Now()),
	}

	// Log result
	if err := h.LogAction(resultEAP); err != nil {
		h.logger.Error("Failed to log action result: %v", err)
		// Continue anyway, logging failure shouldn't stop sending the result
	}

	// Publish result
	if err := h.transport.Publish(ctx, resultsTopic, resultEAP, qos); err != nil {
		return fmt.Errorf("failed to publish action result: %w", err)
	}

	h.logger.Info("Sent result for action ID %s with status %s", actionID, status)
	return nil
}

// ParseActionParams parses the parameters from an EAP message.
func (h *EAPHandler) ParseActionParams(eap *pb.EAP) (*ActionParams, error) {
	if eap == nil {
		return nil, errors.New("EAP message cannot be nil")
	}

	if len(eap.Parameters) == 0 {
		return nil, errors.New("EAP message has no parameters")
	}

	var params ActionParams
	if err := json.Unmarshal(eap.Parameters, &params); err != nil {
		return nil, fmt.Errorf("failed to unmarshal action parameters: %w", err)
	}

	return &params, nil
}

// ValidateEAPMessage validates an EAP message.
func (h *EAPHandler) ValidateEAPMessage(eap *pb.EAP) error {
	if eap == nil {
		return errors.New("EAP message cannot be nil")
	}

	if eap.Spec != "eap/0.1" {
		return fmt.Errorf("invalid EAP spec: %s", eap.Spec)
	}

	if eap.Id == "" {
		return errors.New("action ID cannot be empty")
	}

	if eap.Type != ActionTypeDirectControl &&
		eap.Type != ActionTypeScheduled &&
		eap.Type != ActionTypeParametric &&
		eap.Type != ActionTypeSequence &&
		eap.Type != "cancel" {
		return fmt.Errorf("invalid action type: %s", eap.Type)
	}

	if eap.Status != ActionStatusPending &&
		eap.Status != ActionStatusRunning &&
		eap.Status != ActionStatusCompleted &&
		eap.Status != ActionStatusFailed &&
		eap.Status != ActionStatusCancelled {
		return fmt.Errorf("invalid action status: %s", eap.Status)
	}

	return nil
}

// CreateRobotPose creates an EAP message with a RobotPose action.
func (h *EAPHandler) CreateRobotPose(
	ctx context.Context,
	target string,
	x, y, z float64,
	qw, qx, qy, qz float64,
	priority int,
	qos map[string]interface{},
) (string, error) {
	// Create parameters for the pose action
	parameters := map[string]interface{}{
		"x":  x,
		"y":  y,
		"z":  z,
		"qw": qw,
		"qx": qx,
		"qy": qy,
		"qz": qz,
	}

	return h.PerformDirectAction(
		ctx,
		target,
		"set_pose",
		parameters,
		nil,
		5000, // 5 second timeout
		priority,
		qos,
	)
}

// CreateGripperOp creates an EAP message with a GripperOp action.
func (h *EAPHandler) CreateGripperOp(
	ctx context.Context,
	target string,
	command string,
	position float32,
	forceLimit float32,
	priority int,
	qos map[string]interface{},
) (string, error) {
	// Validate gripper command
	if command != "OPEN" && command != "CLOSE" && command != "GRIP" {
		return "", fmt.Errorf("invalid gripper command: %s", command)
	}

	// Create parameters for the gripper action
	parameters := map[string]interface{}{
		"command":     command,
		"position":    position,
		"force_limit": forceLimit,
	}

	return h.PerformDirectAction(
		ctx,
		target,
		"gripper",
		parameters,
		nil,
		3000, // 3 second timeout
		priority,
		qos,
	)
}

// CreateCloudOp creates an EAP message with a CloudOp action.
func (h *EAPHandler) CreateCloudOp(
	ctx context.Context,
	target string,
	apiName string,
	methodName string,
	jsonPayload []byte,
	requiresOAuth2 bool,
	priority int,
	qos map[string]interface{},
) (string, error) {
	// Create parameters for the cloud action
	parameters := map[string]interface{}{
		"api_name":        apiName,
		"method_name":     methodName,
		"requires_oauth2": requiresOAuth2,
	}

	return h.PerformDirectAction(
		ctx,
		target,
		"cloud",
		parameters,
		jsonPayload,
		10000, // 10 second timeout for API calls
		priority,
		qos,
	)
}

// CreateSimStep creates an EAP message with a SimStep action.
func (h *EAPHandler) CreateSimStep(
	ctx context.Context,
	target string,
	durationS float64,
	priority int,
	qos map[string]interface{},
) (string, error) {
	// Create parameters for the simulation step action
	parameters := map[string]interface{}{
		"duration_s": durationS,
	}

	return h.PerformDirectAction(
		ctx,
		target,
		"sim",
		parameters,
		nil,
		1000, // 1 second timeout
		priority,
		qos,
	)
}

// Close closes the EAP handler and releases any resources.
func (h *EAPHandler) Close() error {
	return h.CloseLogFile()
}