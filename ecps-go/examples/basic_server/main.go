// Example of a basic ECPS server that handles all protocol layers
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/ecps/ecps-go/pkg/actuation"
	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/core"
	"github.com/ecps/ecps-go/pkg/perception"
	"github.com/ecps/ecps-go/pkg/transport"
	pb "github.com/ecps/ecps-go/proto"
)

// Server configuration
const (
	serverName    = "ecps-example-server"
	serverVersion = "1.0.0"
	deviceID      = "example_device" // Device ID for actuation
)

// ActionInfo tracks active actions for cancellation
type ActionInfo struct {
	id     string
	cancel context.CancelFunc
	startTime time.Time
}

// Global action tracking
var (
	activeActions = make(map[string]*ActionInfo)
	actionsMutex  sync.RWMutex
)

func main() {
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

	// Create and configure server
	server, err := createServer(ctx)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	// Initialize protocol handlers
	ltpHandler, mcpHandler, mepHandler, eapHandler, err := createProtocolHandlers(server)
	if err != nil {
		log.Fatalf("Failed to create protocol handlers: %v", err)
	}

	// Start the server and register handlers
	if err := startServer(ctx, server, ltpHandler, mcpHandler, mepHandler, eapHandler); err != nil {
		log.Fatalf("Server failed: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Server shutting down")
}

func createServer(ctx context.Context) (*core.Server, error) {
	// Create configuration
	config := core.DefaultConfig()
	config.AppID = serverName
	config.LogLevel = core.LogLevelInfo

	// Create transport
	transportImpl, err := transport.NewDDSTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create DDS transport: %w", err)
	}

	// Create server
	server, err := core.NewServer(config, transportImpl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create server: %w", err)
	}

	log.Printf("ECPS server '%s' v%s created successfully", serverName, serverVersion)
	return server, nil
}

func createProtocolHandlers(server *core.Server) (
	*perception.LTPHandler,
	*cognition.MCPHandler,
	*cognition.MEPHandler,
	*actuation.EAPHandler,
	error,
) {
	// Create LTP handler
	ltpHandler, err := perception.NewLTPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create LTP handler: %w", err)
	}

	// Create MCP handler
	mcpHandler, err := cognition.NewMCPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create MCP handler: %w", err)
	}

	// Create MEP handler
	mepHandler, err := cognition.NewMEPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create MEP handler: %w", err)
	}

	// Create EAP handler
	eapHandler, err := actuation.NewEAPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create EAP handler: %w", err)
	}

	return ltpHandler, mcpHandler, mepHandler, eapHandler, nil
}

func startServer(
	ctx context.Context,
	server *core.Server,
	ltpHandler *perception.LTPHandler,
	mcpHandler *cognition.MCPHandler,
	mepHandler *cognition.MEPHandler,
	eapHandler *actuation.EAPHandler,
) error {
	// Start the server
	if err := server.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	// Register LTP handler
	if err := registerLTPHandler(ctx, ltpHandler); err != nil {
		return fmt.Errorf("failed to register LTP handler: %w", err)
	}

	// Register MCP handler
	if err := registerMCPHandler(ctx, mcpHandler); err != nil {
		return fmt.Errorf("failed to register MCP handler: %w", err)
	}

	// Register MEP handlers
	if err := registerMEPHandlers(ctx, mepHandler); err != nil {
		return fmt.Errorf("failed to register MEP handlers: %w", err)
	}

	// Register EAP handler
	if err := registerEAPHandler(ctx, eapHandler); err != nil {
		return fmt.Errorf("failed to register EAP handler: %w", err)
	}

	log.Println("Server started and handlers registered successfully")
	return nil
}

// LTP (Perception Layer) Handler Registration
func registerLTPHandler(ctx context.Context, ltpHandler *perception.LTPHandler) error {
	// Define tensor handler function
	tensorHandler := func(ctx context.Context, ltp *pb.LTP) error {
		// Parse metadata
		metadata, err := ltpHandler.ParseMetadata(ltp)
		if err != nil {
			log.Printf("Error parsing tensor metadata: %v", err)
			return err
		}

		// Extract tensor data
		tensorData, err := ltpHandler.ExtractTensorData(ltp)
		if err != nil {
			log.Printf("Error extracting tensor data: %v", err)
			return err
		}

		// Log received tensor information
		log.Printf("Received tensor with ID: %s", ltp.Id)
		log.Printf("  - Space: %s, Frame: %s", metadata.SpaceName, metadata.FrameID)
		log.Printf("  - Shape: %v, Type: %s", metadata.Shape, metadata.DType)
		log.Printf("  - Labels: %v", metadata.Labels)
		log.Printf("  - Data size: %d elements", len(tensorData))

		// Process tensor (example: calculate mean for float32 tensors)
		if metadata.DType == "float32" && len(tensorData) > 0 {
			floatData, ok := tensorData.([]float32)
			if ok {
				sum := float32(0)
				for _, v := range floatData {
					sum += v
				}
				mean := sum / float32(len(floatData))
				log.Printf("  - Calculated mean: %f", mean)
			}
		}

		return nil
	}

	// Listen for tensors
	if err := ltpHandler.Listen(ctx, []func(context.Context, *pb.LTP) error{tensorHandler}, nil); err != nil {
		return fmt.Errorf("failed to start listening for tensors: %w", err)
	}

	log.Println("LTP handler registered successfully")
	return nil
}

// MCP (Model Context Protocol) Handler Registration
func registerMCPHandler(ctx context.Context, mcpHandler *cognition.MCPHandler) error {
	// Define prompt handler function
	promptHandler := func(ctx context.Context, mcp *pb.MCP) error {
		// Validate message
		if err := mcpHandler.ValidateMCPMessage(mcp); err != nil {
			log.Printf("Invalid MCP message received: %v", err)
			return err
		}

		// Log received prompt information
		log.Printf("Received prompt with ID: %s", mcp.Id)
		log.Printf("  - Prompt: %s", truncateString(mcp.Prompt, 100))
		log.Printf("  - Metadata: %v", mcp.Meta)

		// Extract tool data if present
		if len(mcp.ToolJson) > 0 {
			toolData, err := mcpHandler.ExtractToolJSON(mcp)
			if err != nil {
				log.Printf("Error extracting tool data: %v", err)
			} else {
				log.Printf("  - Tool data: %v", toolData)
			}
		}

		// Generate a simple response
		response := fmt.Sprintf("Received your prompt about: %s", 
			truncateString(mcp.Prompt, 20))
		
		// Add some mock tool result if tool was provided
		var toolResult []byte
		if len(mcp.ToolJson) > 0 {
			mockResult := map[string]interface{}{
				"result": "This is a mock tool result",
				"timestamp": time.Now().Format(time.RFC3339),
			}
			toolResult, _ = json.Marshal(mockResult)
		}
		
		// Send response back
		if err := mcpHandler.SendResponse(
			ctx,
			mcp.Id,
			response,
			toolResult,
			map[string]string{"processed_by": serverName},
			nil, // Default QoS
		); err != nil {
			log.Printf("Error sending MCP response: %v", err)
			return err
		}
		
		log.Printf("Sent response for prompt ID: %s", mcp.Id)
		return nil
	}

	// Listen for prompts
	if err := mcpHandler.Listen(ctx, []func(context.Context, *pb.MCP) error{promptHandler}, nil); err != nil {
		return fmt.Errorf("failed to start listening for prompts: %w", err)
	}

	log.Println("MCP handler registered successfully")
	return nil
}

// MEP (Memory Event Protocol) Handler Registration
func registerMEPHandlers(ctx context.Context, mepHandler *cognition.MEPHandler) error {
	// In-memory store for this example
	memoryStore := make(map[string][]byte)
	memoryMetadata := make(map[string]*cognition.MemoryEventMetadata)

	// Create handler
	createHandler := func(ctx context.Context, mep *pb.MEP) error {
		// Validate message
		if err := mepHandler.ValidateMEPMessage(mep); err != nil {
			log.Printf("Invalid MEP create message: %v", err)
			return err
		}

		// Parse metadata
		metadata, err := mepHandler.ParseMetadata(mep)
		if err != nil {
			log.Printf("Error parsing memory metadata: %v", err)
			return err
		}

		// Store memory
		memoryStore[mep.Id] = mep.Content
		if metadata != nil {
			memoryMetadata[mep.Id] = metadata
		}

		log.Printf("Created memory with ID: %s", mep.Id)
		log.Printf("  - Content type: %s", getContentType(metadata))
		log.Printf("  - Content size: %d bytes", len(mep.Content))
		log.Printf("  - Labels: %v", getLabels(metadata))

		return nil
	}

	// Update handler
	updateHandler := func(ctx context.Context, mep *pb.MEP) error {
		// Validate message
		if err := mepHandler.ValidateMEPMessage(mep); err != nil {
			log.Printf("Invalid MEP update message: %v", err)
			return err
		}

		// Check if memory exists
		if _, exists := memoryStore[mep.Id]; !exists {
			err := fmt.Errorf("memory with ID %s not found for update", mep.Id)
			log.Print(err)
			return err
		}

		// Parse metadata
		metadata, err := mepHandler.ParseMetadata(mep)
		if err != nil {
			log.Printf("Error parsing memory metadata: %v", err)
			return err
		}

		// Update memory
		memoryStore[mep.Id] = mep.Content
		if metadata != nil {
			memoryMetadata[mep.Id] = metadata
		}

		log.Printf("Updated memory with ID: %s", mep.Id)
		log.Printf("  - New content size: %d bytes", len(mep.Content))

		return nil
	}

	// Delete handler
	deleteHandler := func(ctx context.Context, mep *pb.MEP) error {
		// Validate message
		if err := mepHandler.ValidateMEPMessage(mep); err != nil {
			log.Printf("Invalid MEP delete message: %v", err)
			return err
		}

		// Check if memory exists
		if _, exists := memoryStore[mep.Id]; !exists {
			err := fmt.Errorf("memory with ID %s not found for deletion", mep.Id)
			log.Print(err)
			return err
		}

		// Delete memory
		delete(memoryStore, mep.Id)
		delete(memoryMetadata, mep.Id)

		log.Printf("Deleted memory with ID: %s", mep.Id)
		return nil
	}

	// Query handler
	queryHandler := func(ctx context.Context, mep *pb.MEP) error {
		// Validate message
		if err := mepHandler.ValidateMEPMessage(mep); err != nil {
			log.Printf("Invalid MEP query message: %v", err)
			return err
		}

		log.Printf("Received memory query with correlation ID: %s", mep.CorrelationId)

		// Parse query parameters
		var queryParams cognition.QueryParams
		if err := json.Unmarshal(mep.Content, &queryParams); err != nil {
			log.Printf("Error parsing query parameters: %v", err)
			return err
		}

		log.Printf("Query parameters: limit=%d, content_type=%s", 
			queryParams.Limit, queryParams.ContentType)
		if len(queryParams.Labels) > 0 {
			log.Printf("Query labels: %v", queryParams.Labels)
		}

		// Process query and send results
		resultCount := 0
		for id, content := range memoryStore {
			metadata := memoryMetadata[id]
			
			// Filter by content type if specified
			if queryParams.ContentType != "" && 
			   (metadata == nil || metadata.ContentType != queryParams.ContentType) {
				continue
			}
			
			// Filter by labels if specified
			if len(queryParams.Labels) > 0 && metadata != nil {
				match := true
				for k, v := range queryParams.Labels {
					if metadata.Labels[k] != v {
						match = false
						break
					}
				}
				if !match {
					continue
				}
			}
			
			// Send matching result
			if err := mepHandler.SendQueryResult(
				ctx,
				mep.CorrelationId,
				id,
				content,
				metadata,
				nil, // Default QoS
			); err != nil {
				log.Printf("Error sending query result for memory ID %s: %v", id, err)
				continue
			}
			
			resultCount++
			log.Printf("Sent query result for memory ID: %s", id)
			
			// Respect limit if specified
			if queryParams.Limit > 0 && resultCount >= queryParams.Limit {
				break
			}
		}
		
		log.Printf("Sent %d results for query with correlation ID: %s", resultCount, mep.CorrelationId)
		return nil
	}

	// Register handlers for each operation
	if err := mepHandler.ListenForOperation(ctx, cognition.MEPOperationCreate, createHandler, nil); err != nil {
		return fmt.Errorf("failed to register MEP create handler: %w", err)
	}

	if err := mepHandler.ListenForOperation(ctx, cognition.MEPOperationUpdate, updateHandler, nil); err != nil {
		return fmt.Errorf("failed to register MEP update handler: %w", err)
	}

	if err := mepHandler.ListenForOperation(ctx, cognition.MEPOperationDelete, deleteHandler, nil); err != nil {
		return fmt.Errorf("failed to register MEP delete handler: %w", err)
	}

	if err := mepHandler.ListenForOperation(ctx, cognition.MEPOperationQuery, queryHandler, nil); err != nil {
		return fmt.Errorf("failed to register MEP query handler: %w", err)
	}

	log.Println("MEP handlers registered successfully")
	return nil
}

// EAP (Embodied Action Protocol) Handler Registration
func registerEAPHandler(ctx context.Context, eapHandler *actuation.EAPHandler) error {
	// Action handler for the example device
	actionHandler := func(ctx context.Context, eap *pb.EAP) error {
		// Validate message
		if err := eapHandler.ValidateEAPMessage(eap); err != nil {
			log.Printf("Invalid EAP message: %v", err)
			return err
		}

		// Parse action parameters
		params, err := eapHandler.ParseActionParams(eap)
		if err != nil {
			log.Printf("Error parsing action parameters: %v", err)
			return err
		}

		log.Printf("Received action request with ID: %s", eap.Id)
		log.Printf("  - Action: %s (%s)", eap.Name, eap.Type)
		log.Printf("  - Target: %s", params.Target)
		log.Printf("  - Priority: %d", params.Priority)
		if params.Timeout > 0 {
			log.Printf("  - Timeout: %d ms", params.Timeout)
		}
		if len(params.Parameters) > 0 {
			log.Printf("  - Parameters: %v", params.Parameters)
		}

		// For scheduled actions, check the scheduled time
		if eap.Type == actuation.ActionTypeScheduled && params.ScheduledTime != nil {
			scheduledTime := *params.ScheduledTime
			log.Printf("  - Scheduled for: %s", scheduledTime.Format(time.RFC3339))
			
			// If in the future, acknowledge receipt but don't execute yet
			if scheduledTime.After(time.Now()) {
				// Send "accepted" status
				if err := eapHandler.SendActionResult(
					ctx,
					eap.Id,
					params.Target,
					actuation.ActionStatusPending,
					[]byte(`{"status":"scheduled"}`),
					nil, // Default QoS
				); err != nil {
					log.Printf("Error sending action status: %v", err)
					return err
				}
				
				log.Printf("Scheduled action %s acknowledged for future execution", eap.Id)
				return nil
			}
		}

		// Create cancellable context for this action
		actionCtx, actionCancel := context.WithCancel(ctx)
		
		// Track the action for cancellation
		actionsMutex.Lock()
		activeActions[eap.Id] = &ActionInfo{
			id:        eap.Id,
			cancel:    actionCancel,
			startTime: time.Now(),
		}
		actionsMutex.Unlock()
		
		// Ensure cleanup when action completes
		defer func() {
			actionsMutex.Lock()
			delete(activeActions, eap.Id)
			actionsMutex.Unlock()
		}()

		// Update status to running
		if err := eapHandler.SendActionResult(
			ctx,
			eap.Id,
			params.Target,
			actuation.ActionStatusRunning,
			[]byte(`{"status":"processing"}`),
			nil, // Default QoS
		); err != nil {
			log.Printf("Error sending action status: %v", err)
			return err
		}

		// Simulate processing time based on priority
		processingTime := 500 * time.Millisecond
		if params.Priority > 70 {
			processingTime = 100 * time.Millisecond // High priority = faster
		} else if params.Priority < 30 {
			processingTime = 1000 * time.Millisecond // Low priority = slower
		}
		
		log.Printf("Processing action %s (simulating work for %v)...", eap.Id, processingTime)
		
		// Use select to allow cancellation during processing
		select {
		case <-actionCtx.Done():
			log.Printf("Action %s was cancelled during processing", eap.Id)
			return actionCtx.Err()
		case <-time.After(processingTime):
			// Processing completed normally
		}

		// Generate result based on action name
		var result []byte
		var resultErr error
		
		switch eap.Name {
		case "move_arm":
			// Simulate arm movement success
			result = []byte(`{
				"status": "success",
				"position_reached": true,
				"execution_time_ms": 450,
				"final_joint_angles": [0.52, 1.21, 0.79, 1.02, 0.68]
			}`)
			
		case "take_picture":
			// Simulate taking a picture
			imageID := uuid.NewString()
			result = []byte(fmt.Sprintf(`{
				"status": "success",
				"image_id": "%s",
				"resolution": "1920x1080",
				"format": "jpeg",
				"size_bytes": 2457600,
				"save_path": "/data/images/%s.jpg"
			}`, imageID, imageID))
			
		default:
			// Generic success for unknown actions
			result = []byte(fmt.Sprintf(`{
				"status": "success",
				"action": "%s",
				"timestamp": "%s"
			}`, eap.Name, time.Now().Format(time.RFC3339)))
		}

		// Randomly simulate some failures (10% chance)
		if randBetween(1, 10) == 1 {
			result = []byte(fmt.Sprintf(`{
				"status": "error",
				"error_code": "EXECUTION_FAILED",
				"error_message": "Failed to execute action %s due to simulated random failure",
				"timestamp": "%s"
			}`, eap.Name, time.Now().Format(time.RFC3339)))
			
			// Send failed status
			resultErr = eapHandler.SendActionResult(
				ctx,
				eap.Id,
				params.Target,
				actuation.ActionStatusFailed,
				result,
				nil, // Default QoS
			)
		} else {
			// Send completed status
			resultErr = eapHandler.SendActionResult(
				ctx,
				eap.Id,
				params.Target,
				actuation.ActionStatusCompleted,
				result,
				nil, // Default QoS
			)
		}
		
		if resultErr != nil {
			log.Printf("Error sending action result: %v", resultErr)
			return resultErr
		}
		
		log.Printf("Processed action %s and sent result", eap.Id)
		return nil
	}

	// Cancel handler
	cancelHandler := func(ctx context.Context, eap *pb.EAP) error {
		log.Printf("Received cancellation request for action ID: %s", eap.Id)
		
		// Look up the action and cancel it
		actionsMutex.Lock()
		action, exists := activeActions[eap.Id]
		if exists {
			// Cancel the action's context to stop execution
			action.cancel()
			delete(activeActions, eap.Id)
			log.Printf("Successfully cancelled action: %s", eap.Id)
		} else {
			log.Printf("Action not found or already completed: %s", eap.Id)
		}
		actionsMutex.Unlock()
		
		// Send cancelled status
		if err := eapHandler.SendActionResult(
			ctx,
			eap.Id,
			deviceID,
			actuation.ActionStatusCancelled,
			[]byte(`{"status":"cancelled","reason":"user_request"}`),
			nil, // Default QoS
		); err != nil {
			log.Printf("Error sending cancellation result: %v", err)
			return err
		}
		
		log.Printf("Action %s cancelled successfully", eap.Id)
		return nil
	}

	// Listen for actions targeted at our device
	if err := eapHandler.ListenForActions(ctx, deviceID, actionHandler, nil); err != nil {
		return fmt.Errorf("failed to start listening for actions: %w", err)
	}

	// Listen for cancellations
	if err := eapHandler.ListenForCancellations(ctx, deviceID, cancelHandler, nil); err != nil {
		return fmt.Errorf("failed to start listening for cancellations: %w", err)
	}

	log.Println("EAP handlers registered successfully")
	return nil
}

// Helper functions

// truncateString truncates a string to max length and adds ellipsis if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// getContentType safely extracts content type from metadata
func getContentType(metadata *cognition.MemoryEventMetadata) string {
	if metadata == nil {
		return "unknown"
	}
	if metadata.ContentType == "" {
		return "application/octet-stream"
	}
	return metadata.ContentType
}

// getLabels safely extracts labels from metadata
func getLabels(metadata *cognition.MemoryEventMetadata) map[string]string {
	if metadata == nil || metadata.Labels == nil {
		return make(map[string]string)
	}
	return metadata.Labels
}

// randBetween returns a random integer between min and max (inclusive)
func randBetween(min, max int) int {
	return min + int(time.Now().UnixNano()%int64(max-min+1))
}