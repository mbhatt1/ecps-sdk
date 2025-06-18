// Example of a basic ECPS client using all protocol layers
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ecps/ecps-go/pkg/actuation"
	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/core"
	"github.com/ecps/ecps-go/pkg/perception"
	"github.com/ecps/ecps-go/pkg/transport"
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

	// Create and configure client
	client, err := createClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Initialize protocol handlers
	ltpHandler, mcpHandler, mepHandler, eapHandler, err := createProtocolHandlers(client)
	if err != nil {
		log.Fatalf("Failed to create protocol handlers: %v", err)
	}

	// Run the client example flows
	if err := runClientExample(ctx, ltpHandler, mcpHandler, mepHandler, eapHandler); err != nil {
		log.Fatalf("Client example failed: %v", err)
	}

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Client shutting down")
}

func createClient(ctx context.Context) (*core.Client, error) {
	// Create configuration
	config := core.DefaultConfig()
	config.AppID = "ecps-example-client"
	config.LogLevel = core.LogLevelInfo

	// Create transport
	transportImpl, err := transport.NewDDSTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create DDS transport: %w", err)
	}

	// Create client
	client, err := core.NewClient(config, transportImpl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	log.Println("ECPS client created successfully")
	return client, nil
}

func createProtocolHandlers(client *core.Client) (
	*perception.LTPHandler,
	*cognition.MCPHandler,
	*cognition.MEPHandler,
	*actuation.EAPHandler,
	error,
) {
	// Create LTP handler
	ltpHandler, err := perception.NewLTPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create LTP handler: %w", err)
	}

	// Create MCP handler
	mcpHandler, err := cognition.NewMCPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create MCP handler: %w", err)
	}

	// Create MEP handler
	mepHandler, err := cognition.NewMEPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create MEP handler: %w", err)
	}

	// Create EAP handler
	eapHandler, err := actuation.NewEAPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create EAP handler: %w", err)
	}

	return ltpHandler, mcpHandler, mepHandler, eapHandler, nil
}

func runClientExample(
	ctx context.Context,
	ltpHandler *perception.LTPHandler,
	mcpHandler *cognition.MCPHandler,
	mepHandler *cognition.MEPHandler,
	eapHandler *actuation.EAPHandler,
) error {
	// Example 1: Send a perception tensor
	log.Println("--- LTP Example: Sending a perception tensor ---")
	if err := sendExampleTensor(ctx, ltpHandler); err != nil {
		return fmt.Errorf("LTP example failed: %w", err)
	}

	// Example 2: Send a model prompt
	log.Println("--- MCP Example: Sending a model prompt ---")
	if err := sendExamplePrompt(ctx, mcpHandler); err != nil {
		return fmt.Errorf("MCP example failed: %w", err)
	}

	// Example 3: Create and query memory
	log.Println("--- MEP Example: Creating and querying memory ---")
	if err := createAndQueryMemory(ctx, mepHandler); err != nil {
		return fmt.Errorf("MEP example failed: %w", err)
	}

	// Example 4: Send an action
	log.Println("--- EAP Example: Sending an action ---")
	if err := sendExampleAction(ctx, eapHandler); err != nil {
		return fmt.Errorf("EAP example failed: %w", err)
	}

	log.Println("All examples completed successfully")
	return nil
}

func sendExampleTensor(ctx context.Context, ltpHandler *perception.LTPHandler) error {
	// Create sample tensor data (3x3 matrix)
	tensorData := []float32{
		1.0, 2.0, 3.0,
		4.0, 5.0, 6.0,
		7.0, 8.0, 9.0,
	}

	// Define tensor metadata
	metadata := &perception.TensorMetadata{
		Shape:         []int{3, 3},
		DType:         "float32",
		ContentType:   "tensor/float",
		SpaceName:     "sample_space",
		FrameID:       "sample_frame",
		Timestamp:     time.Now(),
		Labels:        map[string]string{"source": "example", "type": "matrix"},
		BatchSize:     1,
		IsCompressed:  false,
		CompressionFormat: "",
	}

	// Send tensor
	tensorID, err := ltpHandler.SendTensor(
		ctx,
		tensorData,
		metadata,
		nil, // Default QoS
	)
	if err != nil {
		return fmt.Errorf("failed to send tensor: %w", err)
	}

	log.Printf("Sent tensor with ID: %s", tensorID)
	return nil
}

func sendExamplePrompt(ctx context.Context, mcpHandler *cognition.MCPHandler) error {
	// Create a sample prompt
	prompt := "What is the capital of France?"

	// Create tool JSON
	toolParams := map[string]interface{}{
		"allowed_tools": []string{"search", "calculator"},
		"search_config": map[string]interface{}{
			"engine": "bing",
			"limit":  5,
		},
	}
	toolJSON, err := json.Marshal(toolParams)
	if err != nil {
		return fmt.Errorf("failed to marshal tool JSON: %w", err)
	}

	// Send prompt
	messageID, err := mcpHandler.Send(
		ctx,
		prompt,
		"", // Generate message ID
		toolJSON,
		map[string]string{"lang": "en", "mode": "chat"},
		nil, // Default QoS
	)
	if err != nil {
		return fmt.Errorf("failed to send prompt: %w", err)
	}

	log.Printf("Sent prompt with ID: %s", messageID)
	return nil
}

func createAndQueryMemory(ctx context.Context, mepHandler *cognition.MEPHandler) error {
	// Create sample memory content
	content := []byte(`{
		"type": "fact",
		"content": "The Earth orbits around the Sun at an average distance of 93 million miles."
	}`)

	// Create memory metadata
	metadata := &cognition.MemoryEventMetadata{
		ContentType: "application/json",
		Labels: map[string]string{
			"category": "astronomy",
			"source":   "example",
		},
		Timestamp: time.Now(),
		TTL:       3600, // 1 hour
	}

	// Create memory
	memoryID, err := mepHandler.CreateMemory(
		ctx,
		content,
		metadata,
		nil, // Default QoS
	)
	if err != nil {
		return fmt.Errorf("failed to create memory: %w", err)
	}

	log.Printf("Created memory with ID: %s", memoryID)

	// Create query
	queryParams := cognition.QueryParams{
		Limit: 10,
		Labels: map[string]string{
			"category": "astronomy",
		},
		ContentType: "application/json",
	}

	// Send query
	correlationID, err := mepHandler.QueryMemory(
		ctx,
		queryParams,
		nil, // Default QoS
	)
	if err != nil {
		return fmt.Errorf("failed to query memory: %w", err)
	}

	log.Printf("Sent memory query with correlation ID: %s", correlationID)
	return nil
}

func sendExampleAction(ctx context.Context, eapHandler *actuation.EAPHandler) error {
	// Define action parameters
	target := "example_device"
	actionName := "move_arm"
	parameters := map[string]interface{}{
		"joint_angles": []float64{0.5, 1.2, 0.8, 1.0, 0.7},
		"speed":        0.8,
		"acceleration": 0.5,
	}

	// Send direct action
	actionID, err := eapHandler.PerformDirectAction(
		ctx,
		target,
		actionName,
		parameters,
		nil, // No payload
		5000, // 5 second timeout
		50,   // Medium priority
		nil,  // Default QoS
	)
	if err != nil {
		return fmt.Errorf("failed to send action: %w", err)
	}

	log.Printf("Sent action '%s' to target '%s' with ID: %s", actionName, target, actionID)

	// Schedule an action for future execution
	futureTime := time.Now().Add(5 * time.Minute)
	scheduledActionName := "take_picture"
	scheduledParams := map[string]interface{}{
		"resolution": "high",
		"format":     "jpeg",
		"save_path":  "/data/images/",
	}

	scheduledID, err := eapHandler.ScheduleAction(
		ctx,
		target,
		scheduledActionName,
		scheduledParams,
		futureTime,
		nil, // No expiration
		30,  // Lower priority
		nil, // Default QoS
	)
	if err != nil {
		return fmt.Errorf("failed to schedule action: %w", err)
	}

	log.Printf("Scheduled action '%s' on target '%s' with ID: %s for %s",
		scheduledActionName, target, scheduledID, futureTime.Format(time.RFC3339))

	return nil
}