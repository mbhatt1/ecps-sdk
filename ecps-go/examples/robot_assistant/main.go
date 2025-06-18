// Example of a robot assistant using all ECPS protocol layers
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ecps/ecps-go/pkg/actuation"
	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/core"
	"github.com/ecps/ecps-go/pkg/perception"
	"github.com/ecps/ecps-go/pkg/transport"
	pb "github.com/ecps/ecps-go/proto"
)

// Simulation parameters
const (
	SimulatedRobotID = "sim_robot_001"
	SimulatedCamera  = "depth_camera"
)

var (
	// Command line flags
	domainID    = flag.Int("domain", 0, "DDS domain ID")
	role        = flag.String("role", "client", "Role: client or server")
	serverAddr  = flag.String("server", "localhost", "Server address for gRPC transport")
	useTransport = flag.String("transport", "dds", "Transport type: dds, grpc, or mqtt")
)

func main() {
	// Parse command line flags
	flag.Parse()

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

	// Create transport based on command line flags
	transportImpl, err := createTransport(ctx, *useTransport, *domainID, *serverAddr)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	// Create and run based on role
	if strings.ToLower(*role) == "server" {
		runServer(ctx, transportImpl)
	} else {
		runClient(ctx, transportImpl)
	}
}

// createTransport creates the appropriate transport based on user selection
func createTransport(ctx context.Context, transportType string, domainID int, serverAddr string) (core.Transport, error) {
	var transportImpl core.Transport
	var err error

	switch strings.ToLower(transportType) {
	case "dds":
		transportImpl, err = transport.NewDDSTransport(ctx, transport.WithDomainID(domainID))
	case "grpc":
		transportImpl, err = transport.NewGRPCTransport(ctx, fmt.Sprintf("%s:50051", serverAddr))
	case "mqtt":
		transportImpl, err = transport.NewMQTTTransport(ctx, fmt.Sprintf("tcp://%s:1883", serverAddr))
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", transportType)
	}

	return transportImpl, err
}

// runServer runs the server role (simulated robot and LLM)
func runServer(ctx context.Context, transportImpl core.Transport) {
	log.Println("Starting server...")

	// Create server configuration
	config := core.DefaultConfig()
	config.AppID = "robot-assistant-server"

	// Create server
	server, err := core.NewServer(config, transportImpl, nil)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer server.Close()

	// Start the server
	if err := server.Start(ctx); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	log.Println("Server started")

	// Create protocol handlers
	ltpHandler, mcpHandler, mepHandler, eapHandler, err := createProtocolHandlers(server)
	if err != nil {
		log.Fatalf("Failed to create protocol handlers: %v", err)
	}

	// Register handlers
	registerServerHandlers(ctx, ltpHandler, mcpHandler, mepHandler, eapHandler)

	// Simulate sensor data periodically
	go simulateSensorData(ctx, ltpHandler)

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Server shutting down")
}

// runClient runs the client role (assistant application)
func runClient(ctx context.Context, transportImpl core.Transport) {
	log.Println("Starting client...")

	// Create client configuration
	config := core.DefaultConfig()
	config.AppID = "robot-assistant-client"

	// Create client
	client, err := core.NewClient(config, transportImpl, nil)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	// Start the client
	if err := client.Start(ctx); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}
	log.Println("Client started")

	// Create protocol handlers
	ltpHandler, mcpHandler, mepHandler, eapHandler, err := createProtocolHandlers(client)
	if err != nil {
		log.Fatalf("Failed to create protocol handlers: %v", err)
	}

	// Register handlers
	registerClientHandlers(ctx, ltpHandler, mcpHandler, mepHandler, eapHandler)

	// Run the interactive assistant
	runInteractiveAssistant(ctx, ltpHandler, mcpHandler, mepHandler, eapHandler)

	// Wait for context cancellation
	<-ctx.Done()
	log.Println("Client shutting down")
}

// createProtocolHandlers creates handlers for all protocols
func createProtocolHandlers(node interface{}) (
	*perception.LTPHandler,
	*cognition.MCPHandler,
	*cognition.MEPHandler,
	*actuation.EAPHandler,
	error,
) {
	var transport core.Transport
	var serializer core.Serializer
	var telemetry core.Telemetry
	var logger core.Logger

	// Extract components based on node type
	switch n := node.(type) {
	case *core.Client:
		transport = n.Transport()
		serializer = n.Serializer()
		telemetry = n.Telemetry()
		logger = n.Logger()
	case *core.Server:
		transport = n.Transport()
		serializer = n.Serializer()
		telemetry = n.Telemetry()
		logger = n.Logger()
	default:
		return nil, nil, nil, nil, fmt.Errorf("unknown node type: %T", node)
	}

	// Create LTP handler
	ltpHandler, err := perception.NewLTPHandler(
		transport,
		serializer,
		telemetry,
		logger,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create LTP handler: %w", err)
	}

	// Create MCP handler
	mcpHandler, err := cognition.NewMCPHandler(
		transport,
		serializer,
		telemetry,
		logger,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create MCP handler: %w", err)
	}

	// Create MEP handler with in-memory storage
	mepHandler, err := cognition.NewMEPHandler(
		transport,
		serializer,
		telemetry,
		logger,
		cognition.WithInMemoryStorage(true),
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create MEP handler: %w", err)
	}

	// Create EAP handler
	eapHandler, err := actuation.NewEAPHandler(
		transport,
		serializer,
		telemetry,
		logger,
	)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("failed to create EAP handler: %w", err)
	}

	return ltpHandler, mcpHandler, mepHandler, eapHandler, nil
}

// registerServerHandlers registers handlers for the server role
func registerServerHandlers(
	ctx context.Context,
	ltpHandler *perception.LTPHandler,
	mcpHandler *cognition.MCPHandler,
	mepHandler *cognition.MEPHandler,
	eapHandler *actuation.EAPHandler,
) {
	// Register MCP handler (simulated LLM)
	err := mcpHandler.Listen(ctx, []func(context.Context, *pb.MCP) error{
		func(ctx context.Context, mcp *pb.MCP) error {
			// Skip if this is a response
			if mcpHandler.IsResponse(mcp) {
				return nil
			}

			log.Printf("Received prompt: %s", mcp.Prompt)

			// Extract tool JSON if available
			var toolData map[string]interface{}
			if len(mcp.ToolJson) > 0 {
				json.Unmarshal(mcp.ToolJson, &toolData)
				log.Printf("With tool data: %v", toolData)
			}

			// Generate a simulated response
			response := fmt.Sprintf("I received your prompt: '%s'. How can I assist you with the robot?", mcp.Prompt)

			// Add memory information if the prompt mentions memory
			if strings.Contains(strings.ToLower(mcp.Prompt), "memory") {
				response += " I can store and retrieve information from my memory system."
			}

			// Add movement information if the prompt mentions movement
			if strings.Contains(strings.ToLower(mcp.Prompt), "move") || 
			   strings.Contains(strings.ToLower(mcp.Prompt), "go to") {
				response += " I can control the robot's movement using the Embodied Action Protocol."
			}

			// Send the response
			err := mcpHandler.SendResponse(
				ctx,
				mcp.Id,
				response,
				nil,
				map[string]string{"source": "simulated-llm"},
				nil,
			)
			if err != nil {
				log.Printf("Error sending response: %v", err)
				return err
			}

			log.Printf("Sent response for prompt ID: %s", mcp.Id)
			return nil
		},
	}, nil)
	if err != nil {
		log.Printf("Failed to register MCP handler: %v", err)
	}

	// Register MEP handlers
	err = mepHandler.ListenForOperation(ctx, cognition.MEPOperationCreate, func(ctx context.Context, mep *pb.MEP) error {
		log.Printf("Memory created with ID: %s", mep.Id)
		return nil
	}, nil)
	if err != nil {
		log.Printf("Failed to register MEP create handler: %v", err)
	}

	err = mepHandler.ListenForOperation(ctx, cognition.MEPOperationQuery, func(ctx context.Context, mep *pb.MEP) error {
		log.Printf("Memory query received with correlation ID: %s", mep.CorrelationId)

		// Parse query parameters
		var params cognition.QueryParams
		json.Unmarshal(mep.Content, &params)

		// Generate a simulated result
		resultContent := []byte(`{"result": "Simulated memory content"}`)
		resultMetadata := &cognition.MemoryEventMetadata{
			ContentType: "application/json",
			Labels:      map[string]string{"source": "simulation"},
			Timestamp:   time.Now(),
		}

		// Send the result
		err := mepHandler.SendQueryResult(
			ctx,
			mep.CorrelationId,
			"sim-memory-1",
			resultContent,
			resultMetadata,
			nil,
		)
		if err != nil {
			log.Printf("Error sending query result: %v", err)
			return err
		}

		log.Printf("Sent memory query result for correlation ID: %s", mep.CorrelationId)
		return nil
	}, nil)
	if err != nil {
		log.Printf("Failed to register MEP query handler: %v", err)
	}

	// Register EAP handlers (simulated robot)
	err = eapHandler.ListenForActions(ctx, SimulatedRobotID, func(ctx context.Context, eap *pb.EAP) error {
		log.Printf("Received action: %s (ID: %s)", eap.Name, eap.Id)

		// Parse action parameters
		params, err := eapHandler.ParseActionParams(eap)
		if err != nil {
			log.Printf("Error parsing action parameters: %v", err)
			return err
		}

		log.Printf("Action parameters: %+v", params.Parameters)

		// Simulate action execution
		time.Sleep(500 * time.Millisecond)

		// Send a simulated result
		resultData := map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Executed action %s successfully", eap.Name),
			"time":    time.Now().Format(time.RFC3339),
		}
		resultJSON, _ := json.Marshal(resultData)

		err = eapHandler.SendActionResult(
			ctx,
			eap.Id,
			SimulatedRobotID,
			actuation.ActionStatusCompleted,
			resultJSON,
			nil,
		)
		if err != nil {
			log.Printf("Error sending action result: %v", err)
			return err
		}

		log.Printf("Sent result for action ID: %s", eap.Id)
		return nil
	}, nil)
	if err != nil {
		log.Printf("Failed to register EAP action handler: %v", err)
	}
}

// registerClientHandlers registers handlers for the client role
func registerClientHandlers(
	ctx context.Context,
	ltpHandler *perception.LTPHandler,
	mcpHandler *cognition.MCPHandler,
	mepHandler *cognition.MEPHandler,
	eapHandler *actuation.EAPHandler,
) {
	// Register LTP handler (sensor data)
	err := ltpHandler.Receive(ctx, SimulatedCamera, func(ctx context.Context, tensor *perception.Tensor, metadata map[string]string) error {
		log.Printf("Received tensor from %s: shape=%v, type=%s", 
			metadata["frame_id"], tensor.Shape, tensor.DType)
		
		// In a real application, you would process the tensor data here
		// For example, run object detection on camera frames
		
		return nil
	}, nil)
	if err != nil {
		log.Printf("Failed to register LTP handler: %v", err)
	}

	// Register MCP response handler
	err = mcpHandler.Listen(ctx, []func(context.Context, *pb.MCP) error{
		func(ctx context.Context, mcp *pb.MCP) error {
			// Only handle responses
			if !mcpHandler.IsResponse(mcp) {
				return nil
			}

			log.Printf("Received response: %s", mcp.Prompt)
			return nil
		},
	}, nil)
	if err != nil {
		log.Printf("Failed to register MCP response handler: %v", err)
	}

	// Register MEP query result handler
	err = mepHandler.ListenForOperation(ctx, cognition.MEPOperationQuery, func(ctx context.Context, mep *pb.MEP) error {
		// Setup result handler for this query
		return mepHandler.ListenForQueryResults(ctx, mep.CorrelationId, func(ctx context.Context, result *pb.MEP) error {
			log.Printf("Received query result: %s", result.Id)
			
			// Parse content
			var resultData map[string]interface{}
			json.Unmarshal(result.Content, &resultData)
			log.Printf("Result data: %v", resultData)
			
			return nil
		}, nil)
	}, nil)
	if err != nil {
		log.Printf("Failed to register MEP query handler: %v", err)
	}

	// Register EAP result handler
	err = eapHandler.ListenForResults(ctx, SimulatedRobotID, func(ctx context.Context, eap *pb.EAP) error {
		log.Printf("Received action result: %s (status: %s)", eap.Id, eap.Status)
		
		// Parse result payload
		var resultData map[string]interface{}
		json.Unmarshal(eap.Payload, &resultData)
		log.Printf("Result data: %v", resultData)
		
		return nil
	}, nil)
	if err != nil {
		log.Printf("Failed to register EAP result handler: %v", err)
	}
}

// simulateSensorData simulates periodic sensor data from a depth camera
func simulateSensorData(ctx context.Context, ltpHandler *perception.LTPHandler) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Create simulated depth data (30x40 depth map)
			width := 30
			height := 40
			depthData := make([]byte, width*height*4) // 4 bytes per float32
			for i := 0; i < width*height; i++ {
				// Simulate a flat surface with some bumps
				depth := float32(1.0 + 0.1*float32(i%10)/10.0)
				
				// Convert float32 to bytes (simplified, not handling endianness properly)
				depthData[i*4] = byte(depth)
				depthData[i*4+1] = byte(depth * 256)
				depthData[i*4+2] = 0
				depthData[i*4+3] = 0
			}

			// Create tensor
			tensor := &perception.Tensor{
				Data:        depthData,
				Shape:       []uint32{uint32(height), uint32(width)},
				DType:       perception.DTypeFloat32,
				FrameID:     SimulatedCamera,
				TimestampNS: uint64(time.Now().UnixNano()),
			}

			// Send tensor
			_, err := ltpHandler.Send(ctx, SimulatedCamera, tensor, nil)
			if err != nil {
				log.Printf("Error sending simulated depth data: %v", err)
			} else {
				log.Printf("Sent simulated depth data: %dx%d", width, height)
			}
		}
	}
}

// runInteractiveAssistant runs an interactive assistant that accepts user commands
func runInteractiveAssistant(
	ctx context.Context,
	ltpHandler *perception.LTPHandler,
	mcpHandler *cognition.MCPHandler,
	mepHandler *cognition.MEPHandler,
	eapHandler *actuation.EAPHandler,
) {
	log.Println("=== Robot Assistant ===")
	log.Println("Enter commands or 'exit' to quit")
	log.Println("Available commands:")
	log.Println("- ask <prompt>: Send a prompt to the LLM")
	log.Println("- move <x> <y> <z>: Move robot to position")
	log.Println("- store <key> <value>: Store information in memory")
	log.Println("- recall <key>: Retrieve information from memory")
	log.Println("- status: Check robot status")
	log.Println("- help: Show this help")
	log.Println("=======================")

	// Create a goroutine to read from stdin
	go func() {
		for {
			var input string
			fmt.Print("> ")
			fmt.Scanln(&input)
			
			if strings.ToLower(input) == "exit" {
				log.Println("Exiting...")
				return
			}
			
			parts := strings.SplitN(input, " ", 2)
			command := strings.ToLower(parts[0])
			
			switch command {
			case "ask":
				if len(parts) < 2 {
					log.Println("Usage: ask <prompt>")
					continue
				}
				prompt := parts[1]
				
				// Send prompt to LLM
				_, err := mcpHandler.Send(ctx, prompt, "", nil, nil, nil)
				if err != nil {
					log.Printf("Error sending prompt: %v", err)
				}
				
			case "move":
				// Parse coordinates
				var x, y, z float64
				fmt.Sscanf(parts[1], "%f %f %f", &x, &y, &z)
				
				// Send movement action
				actionID, err := eapHandler.CreateRobotPose(
					ctx,
					SimulatedRobotID,
					x, y, z,
					1.0, 0.0, 0.0, 0.0, // Default orientation (no rotation)
					50,                  // Medium priority
					nil,
				)
				if err != nil {
					log.Printf("Error sending movement action: %v", err)
				} else {
					log.Printf("Sent movement action (ID: %s)", actionID)
				}
				
			case "store":
				if len(parts) < 2 {
					log.Println("Usage: store <key> <value>")
					continue
				}
				
				// Parse key and value
				keyValue := strings.SplitN(parts[1], " ", 2)
				if len(keyValue) < 2 {
					log.Println("Usage: store <key> <value>")
					continue
				}
				
				key := keyValue[0]
				value := keyValue[1]
				
				// Create memory content
				content := map[string]string{
					"key":   key,
					"value": value,
				}
				contentBytes, _ := json.Marshal(content)
				
				// Create metadata
				metadata := &cognition.MemoryEventMetadata{
					ContentType: "application/json",
					Labels: map[string]string{
						"key": key,
						"type": "user_data",
					},
					Timestamp: time.Now(),
				}
				
				// Store in memory
				memoryID, err := mepHandler.CreateMemory(ctx, contentBytes, metadata, nil)
				if err != nil {
					log.Printf("Error storing memory: %v", err)
				} else {
					log.Printf("Stored memory with ID: %s", memoryID)
				}
				
			case "recall":
				if len(parts) < 2 {
					log.Println("Usage: recall <key>")
					continue
				}
				
				key := parts[1]
				
				// Create query parameters
				queryParams := cognition.QueryParams{
					Limit: 1,
					Labels: map[string]string{
						"key": key,
					},
				}
				
				// Send query
				correlationID, err := mepHandler.QueryMemory(ctx, queryParams, nil)
				if err != nil {
					log.Printf("Error querying memory: %v", err)
				} else {
					log.Printf("Sent memory query with correlation ID: %s", correlationID)
				}
				
			case "status":
				// Send a status check action
				actionID, err := eapHandler.PerformDirectAction(
					ctx,
					SimulatedRobotID,
					"get_status",
					map[string]interface{}{
						"detailed": true,
					},
					nil,
					2000, // 2 second timeout
					10,   // Low priority
					nil,
				)
				if err != nil {
					log.Printf("Error sending status action: %v", err)
				} else {
					log.Printf("Sent status action (ID: %s)", actionID)
				}
				
			case "help":
				log.Println("Available commands:")
				log.Println("- ask <prompt>: Send a prompt to the LLM")
				log.Println("- move <x> <y> <z>: Move robot to position")
				log.Println("- store <key> <value>: Store information in memory")
				log.Println("- recall <key>: Retrieve information from memory")
				log.Println("- status: Check robot status")
				log.Println("- help: Show this help")
				
			default:
				log.Printf("Unknown command: %s", command)
				log.Println("Type 'help' for available commands")
			}
		}
	}()
}