// Package main demonstrates the Unified ECPS Protocol (UEP) in Go.
//
// This example shows how ALL ECPS protocols are consolidated into a single API:
// - MCP (Model Context Protocol) for AI prompts
// - MEP (Memory Exchange Protocol) for memory storage/retrieval
// - EAP (Event Action Protocol) for actuation/actions
// - LTP (Latent Tensor Protocol) for perception data
// - A2A coordination for agent-to-agent communication
// - Trust and security operations
// - Telemetry and observability
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/core"
	pb "github.com/ecps/ecps-go/proto"
)

// MockTransport implements core.Transport for demonstration
type MockTransport struct{}

func (t *MockTransport) Publish(ctx context.Context, topic string, message interface{}, qos map[string]interface{}) error {
	fmt.Printf("📤 Published to topic '%s': %T\n", topic, message)
	return nil
}

func (t *MockTransport) Subscribe(ctx context.Context, topic string, messageType interface{}, handler func(context.Context, interface{}) error, qos map[string]interface{}) error {
	fmt.Printf("📥 Subscribed to topic '%s' for type %T\n", topic, messageType)
	return nil
}

func (t *MockTransport) Close() error {
	return nil
}

// MockSerializer implements core.Serializer for demonstration
type MockSerializer struct{}

func (s *MockSerializer) Serialize(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

func (s *MockSerializer) Deserialize(data []byte, target interface{}) error {
	return json.Unmarshal(data, target)
}

// MockTelemetry implements core.Telemetry for demonstration
type MockTelemetry struct{}

func (t *MockTelemetry) CreateSpan(ctx context.Context, name string, kind interface{}, attrs map[string]interface{}) (context.Context, interface{}) {
	fmt.Printf("📊 Created telemetry span: %s\n", name)
	return ctx, &MockSpan{name: name}
}

func (t *MockTelemetry) RecordMCPPromptSize(size int, attrs map[string]string) {
	fmt.Printf("📏 Recorded MCP prompt size: %d bytes\n", size)
}

func (t *MockTelemetry) RecordMEPQueryLatency(latency float64, attrs map[string]string) {
	fmt.Printf("⏱️ Recorded MEP query latency: %.2f ms\n", latency)
}

func (t *MockTelemetry) RecordOperationLatency(operation string, latency float64, attrs map[string]string) {
	fmt.Printf("⏱️ Recorded %s operation latency: %.2f ms\n", operation, latency)
}

type MockSpan struct {
	name string
}

func (s *MockSpan) End() {
	fmt.Printf("🏁 Ended span: %s\n", s.name)
}

func (s *MockSpan) RecordError(err error) {
	fmt.Printf("❌ Recorded error in span %s: %v\n", s.name, err)
}

// MockLogger implements core.Logger for demonstration
type MockLogger struct{}

func (l *MockLogger) Info(format string, args ...interface{}) {
	fmt.Printf("ℹ️ "+format+"\n", args...)
}

func (l *MockLogger) Warn(format string, args ...interface{}) {
	fmt.Printf("⚠️ "+format+"\n", args...)
}

func (l *MockLogger) Error(format string, args ...interface{}) {
	fmt.Printf("❌ "+format+"\n", args...)
}

func (l *MockLogger) Debug(format string, args ...interface{}) {
	fmt.Printf("🐛 "+format+"\n", args...)
}

func main() {
	fmt.Println("🚀 Starting Unified ECPS Protocol (UEP) Demo in Go")
	fmt.Println(strings.Repeat("=", 60))

	ctx := context.Background()

	// Initialize components
	transport := &MockTransport{}
	serializer := &MockSerializer{}
	telemetry := &MockTelemetry{}
	logger := &MockLogger{}

	// Create unified handler
	uepHandler, err := cognition.NewUEPHandler(
		transport,
		serializer,
		telemetry,
		logger,
		cognition.WithUEPTopic("unified_demo"),
		cognition.WithUEPServiceName("DemoService"),
	)
	if err != nil {
		log.Fatalf("Failed to create UEP handler: %v", err)
	}
	defer uepHandler.Close()

	// ========== 1. PROMPT OPERATIONS (MCP) ==========
	fmt.Println("\n📝 1. Sending AI Prompt (MCP)")

	toolData := map[string]interface{}{
		"type": "navigation_analysis",
		"parameters": map[string]interface{}{
			"environment": "indoor_office",
			"obstacles":   []string{"desk", "chair", "person"},
			"target":      "conference_room_b",
		},
	}
	toolJSON, _ := json.Marshal(toolData)

	promptID, err := uepHandler.SendPrompt(
		ctx,
		"Analyze the robot's current environment and suggest optimal navigation path",
		"", // Auto-generate message ID
		toolJSON,
		map[string]string{
			"priority":  "high",
			"agent_id":  "robot_001",
		},
		nil, // QoS
	)
	if err != nil {
		log.Printf("Error sending prompt: %v", err)
	} else {
		fmt.Printf("✅ Prompt sent with ID: %s\n", promptID)
	}

	// ========== 2. MEMORY OPERATIONS (MEP) ==========
	fmt.Println("\n🧠 2. Memory Storage and Retrieval (MEP)")

	// Create sample embedding
	embedding := make([]byte, 512*4) // 512 float32 values
	rand.Read(embedding)

	// Store memory
	success, messageID, err := uepHandler.StoreMemory(
		ctx,
		embedding,
		[]int32{512},
		"f32",
		"office_map_001",
		time.Now().UnixNano(),
		nil,
	)
	if err != nil {
		log.Printf("Error storing memory: %v", err)
	} else {
		fmt.Printf("✅ Memory stored: success=%t, ID=%s\n", success, messageID)
	}

	// Query similar memories
	queryEmbedding := map[string]interface{}{
		"tensor_zstd":  embedding,
		"shape":        []int32{512},
		"dtype":        "f32",
		"frame_id":     "office_map_query",
		"timestamp_ns": time.Now().UnixNano(),
	}

	memories, err := uepHandler.QueryMemory(ctx, queryEmbedding, 5, 0.8, nil)
	if err != nil {
		log.Printf("Error querying memory: %v", err)
	} else {
		fmt.Printf("✅ Found %d similar memories\n", len(memories))
	}

	// ========== 3. ACTION OPERATIONS (EAP) ==========
	fmt.Println("\n🤖 3. Robot Action Commands (EAP)")

	actionData := map[string]interface{}{
		"position": map[string]float64{
			"x": 2.5,
			"y": 1.8,
			"z": 0.0,
		},
		"orientation": map[string]float64{
			"roll":  0.0,
			"pitch": 0.0,
			"yaw":   1.57,
		},
		"frame_id": "map",
	}

	actionID, err := uepHandler.SendAction(
		ctx,
		"set_pose",
		actionData,
		[]byte("sha256_hash_of_current_perception"),
		map[string]string{
			"urgency":            "normal",
			"estimated_duration": "5.2s",
		},
		nil,
	)
	if err != nil {
		log.Printf("Error sending action: %v", err)
	} else {
		fmt.Printf("✅ Action command sent with ID: %s\n", actionID)
	}

	// ========== 4. PERCEPTION OPERATIONS (LTP) ==========
	fmt.Println("\n👁️ 4. Perception Data (LTP)")

	// Create sample perception tensor (e.g., camera image features)
	perceptionTensor := make([]byte, 224*224*3) // RGB image
	rand.Read(perceptionTensor)

	perceptionID, err := uepHandler.SendPerception(
		ctx,
		perceptionTensor,
		[]int32{224, 224, 3},
		"uint8",
		"camera_front",
		time.Now().UnixNano(),
		nil,
	)
	if err != nil {
		log.Printf("Error sending perception: %v", err)
	} else {
		fmt.Printf("✅ Perception data sent with ID: %s\n", perceptionID)
	}

	// ========== 5. COORDINATION OPERATIONS (A2A) ==========
	fmt.Println("\n🤝 5. Agent Coordination (A2A)")

	coordinationData := map[string]interface{}{
		"task":     "warehouse_inventory",
		"zones":    []string{"A1-A5", "B1-B5", "C1-C5"},
		"deadline": "2024-01-15T18:00:00Z",
	}

	coordinationID, err := uepHandler.CoordinateAgents(
		ctx,
		"task_allocation",
		[]string{"robot_001", "robot_002", "robot_003"},
		coordinationData,
		map[string]string{
			"coordinator":        "robot_001",
			"consensus_required": "true",
		},
		nil,
	)
	if err != nil {
		log.Printf("Error coordinating agents: %v", err)
	} else {
		fmt.Printf("✅ Coordination message sent with ID: %s\n", coordinationID)
	}

	// ========== 6. TRUST OPERATIONS ==========
	fmt.Println("\n🔐 6. Trust and Security Operations")

	trustData := map[string]interface{}{
		"certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
		"signature":   "base64_encoded_signature",
		"challenge":   "random_challenge_string",
	}

	trustID, err := uepHandler.ManageTrust(
		ctx,
		"verify_identity",
		"robot_002",
		trustData,
		map[string]string{
			"verification_level": "high",
			"expires":            "2024-01-15T12:00:00Z",
		},
		nil,
	)
	if err != nil {
		log.Printf("Error managing trust: %v", err)
	} else {
		fmt.Printf("✅ Trust operation sent with ID: %s\n", trustID)
	}

	// ========== 7. TELEMETRY OPERATIONS ==========
	fmt.Println("\n📊 7. Telemetry and Monitoring")

	telemetryData := map[string]interface{}{
		"cpu_usage":       45.2,
		"memory_usage":    67.8,
		"disk_usage":      23.1,
		"network_latency": 12.5,
		"battery_level":   87.3,
		"temperature":     42.1,
	}

	telemetryID, err := uepHandler.SendTelemetry(
		ctx,
		"system_health",
		telemetryData,
		time.Now().UnixNano(),
		map[string]string{
			"node_id":  "robot_001",
			"location": "warehouse_zone_a",
		},
		nil,
	)
	if err != nil {
		log.Printf("Error sending telemetry: %v", err)
	} else {
		fmt.Printf("✅ Telemetry data sent with ID: %s\n", telemetryID)
	}

	// ========== 8. UNIFIED QUERYING ==========
	fmt.Println("\n🔍 8. Unified Data Querying")

	// Query different types of stored data
	memoryData, err := uepHandler.QueryUnified("memory", map[string]interface{}{
		"k":       3,
		"min_sim": 0.5,
	})
	if err != nil {
		log.Printf("Error querying memory: %v", err)
	} else {
		fmt.Printf("✅ Found %d memory entries\n", len(memoryData))
	}

	actionData, err := uepHandler.QueryUnified("action", map[string]interface{}{
		"action_type": "set_pose",
		"limit":       5,
	})
	if err != nil {
		log.Printf("Error querying actions: %v", err)
	} else {
		fmt.Printf("✅ Found %d action entries\n", len(actionData))
	}

	telemetryQueryData, err := uepHandler.QueryUnified("telemetry", map[string]interface{}{
		"metric_type": "system_health",
		"limit":       10,
	})
	if err != nil {
		log.Printf("Error querying telemetry: %v", err)
	} else {
		fmt.Printf("✅ Found %d telemetry entries\n", len(telemetryQueryData))
	}

	// ========== 9. UNIFIED STATISTICS ==========
	fmt.Println("\n📈 9. Unified Statistics")

	stats := uepHandler.GetStats()
	fmt.Println("📊 Unified Storage Statistics:")
	for dataType, count := range stats {
		fmt.Printf("   %s: %v entries\n", dataType, count)
	}

	// ========== 10. UNIFIED LISTENING ==========
	fmt.Println("\n👂 10. Setting up Unified Message Listening")

	// Define handlers for different operation types
	handlers := &cognition.UEPHandlers{
		PromptHandlers: []func(context.Context, *pb.MCP, map[string]interface{}) error{
			func(ctx context.Context, msg *pb.MCP, data map[string]interface{}) error {
				prompt := ""
				if data != nil {
					if p, ok := data["prompt"].(string); ok && len(p) > 50 {
						prompt = p[:50] + "..."
					} else if ok {
						prompt = p
					}
				}
				fmt.Printf("🎯 Received prompt: %s\n", prompt)
				return nil
			},
		},
		MemoryPutHandlers: []func(context.Context, *pb.MCP, map[string]interface{}) error{
			func(ctx context.Context, msg *pb.MCP, data map[string]interface{}) error {
				frameID := ""
				if data != nil {
					if f, ok := data["frame_id"].(string); ok {
						frameID = f
					}
				}
				fmt.Printf("🧠 Received memory storage: frame_id=%s\n", frameID)
				return nil
			},
		},
		ActionHandlers: []func(context.Context, *pb.MCP, map[string]interface{}) error{
			func(ctx context.Context, msg *pb.MCP, data map[string]interface{}) error {
				actionType := ""
				if data != nil {
					if a, ok := data["action_type"].(string); ok {
						actionType = a
					}
				}
				fmt.Printf("🤖 Received action: %s\n", actionType)
				return nil
			},
		},
		CoordinateHandlers: []func(context.Context, *pb.MCP, map[string]interface{}) error{
			func(ctx context.Context, msg *pb.MCP, data map[string]interface{}) error {
				coordType := ""
				if data != nil {
					if c, ok := data["coordination_type"].(string); ok {
						coordType = c
					}
				}
				fmt.Printf("🤝 Received coordination: %s\n", coordType)
				return nil
			},
		},
		TrustHandlers: []func(context.Context, *pb.MCP, map[string]interface{}) error{
			func(ctx context.Context, msg *pb.MCP, data map[string]interface{}) error {
				trustOp := ""
				if data != nil {
					if t, ok := data["trust_operation"].(string); ok {
						trustOp = t
					}
				}
				fmt.Printf("🔐 Received trust operation: %s\n", trustOp)
				return nil
			},
		},
		TelemetryHandlers: []func(context.Context, *pb.MCP, map[string]interface{}) error{
			func(ctx context.Context, msg *pb.MCP, data map[string]interface{}) error {
				metricType := ""
				if data != nil {
					if m, ok := data["metric_type"].(string); ok {
						metricType = m
					}
				}
				fmt.Printf("📊 Received telemetry: %s\n", metricType)
				return nil
			},
		},
	}

	// Set up unified listening (in a real application, this would run continuously)
	fmt.Println("✅ Unified message handlers configured")
	fmt.Println("   (In production, call uepHandler.Listen(ctx, handlers, nil) to start listening)")

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🎉 Unified ECPS Protocol Demo Complete!")
	fmt.Println("🔥 ALL protocols consolidated into a SINGLE API!")
	fmt.Println(strings.Repeat("=", 60))

	demonstrateComparison()
}

func demonstrateComparison() {
	fmt.Println("\n🔄 API COMPARISON")
	fmt.Println(strings.Repeat("=", 40))

	fmt.Println("❌ OLD WAY (Separate APIs):")
	fmt.Println(`
// Separate handlers for each protocol
mcpHandler, _ := cognition.NewMCPHandler(transport, serializer, telemetry, logger)
mepHandler, _ := cognition.NewMEPHandler(transport, serializer, telemetry, logger)
// ... more handlers for EAP, LTP, A2A, Trust, etc.

// Different methods for each operation
mcpHandler.Send(ctx, prompt, messageID, toolJSON, meta, qos)
mepHandler.CreateMemory(ctx, content, metadata, qos)
// ... different APIs for each protocol`)

	fmt.Println("\n✅ NEW WAY (Unified API):")
	fmt.Println(`
// Single unified handler
uepHandler, _ := cognition.NewUEPHandler(transport, serializer, telemetry, logger)

// Single set of methods for ALL operations
uepHandler.SendPrompt(ctx, prompt, messageID, toolJSON, meta, qos)
uepHandler.StoreMemory(ctx, tensorZstd, shape, dtype, frameID, timestampNs, qos)
uepHandler.SendAction(ctx, actionType, actionData, stateSHA, meta, qos)
uepHandler.SendPerception(ctx, tensorZstd, shape, dtype, frameID, timestampNs, qos)
uepHandler.CoordinateAgents(ctx, coordinationType, agentIDs, coordinationData, meta, qos)
uepHandler.ManageTrust(ctx, trustOperation, identity, trustData, meta, qos)
uepHandler.SendTelemetry(ctx, metricType, metricData, timestampNs, meta, qos)

// Single listening interface
uepHandler.Listen(ctx, handlers, qos)

// Single querying interface
uepHandler.QueryUnified(dataType, queryParams)`)

	fmt.Println("\n🎯 BENEFITS:")
	fmt.Println("   ✅ Single API for ALL protocols")
	fmt.Println("   ✅ Consistent interface across all operations")
	fmt.Println("   ✅ Unified storage and querying")
	fmt.Println("   ✅ Simplified error handling")
	fmt.Println("   ✅ Better observability and telemetry")
	fmt.Println("   ✅ Easier testing and debugging")
	fmt.Println("   ✅ Reduced cognitive load for developers")
}