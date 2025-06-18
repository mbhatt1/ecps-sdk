package tests

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ecps/ecps-go/pkg/actuation"
	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/core"
	"github.com/ecps/ecps-go/pkg/perception"
	"github.com/ecps/ecps-go/pkg/transport"
	pb "github.com/ecps/ecps-go/proto"
)

const (
	testTimeout = 5 * time.Second
	deviceID    = "test_device"
)

// TestFullECPSIntegration tests a complete workflow with all ECPS protocol layers.
func TestFullECPSIntegration(t *testing.T) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()

	// Create client and server
	client, server := setupClientServer(t, ctx)
	defer func() {
		client.Close()
		server.Close()
	}()

	// Create protocol handlers
	clientHandlers, serverHandlers := createProtocolHandlers(t, client, server)

	// Setup server-side handlers
	setupServerHandlers(t, ctx, serverHandlers)

	// Run the full integration test
	runIntegrationTest(t, ctx, clientHandlers)
}

// setupClientServer creates and starts a client and server for testing.
func setupClientServer(t *testing.T, ctx context.Context) (*core.Client, *core.Server) {
	// Create transport
	transportImpl, err := transport.NewDDSTransport(ctx, transport.WithDDSInMemory(true))
	require.NoError(t, err, "Failed to create DDS transport")

	// Create client configuration
	clientConfig := core.DefaultConfig()
	clientConfig.AppID = "ecps-test-client"
	clientConfig.LogLevel = core.LogLevelInfo

	// Create client
	client, err := core.NewClient(clientConfig, transportImpl, nil)
	require.NoError(t, err, "Failed to create client")

	// Create server configuration
	serverConfig := core.DefaultConfig()
	serverConfig.AppID = "ecps-test-server"
	serverConfig.LogLevel = core.LogLevelInfo

	// Create server
	server, err := core.NewServer(serverConfig, transportImpl, nil)
	require.NoError(t, err, "Failed to create server")

	// Start client and server
	err = client.Start(ctx)
	require.NoError(t, err, "Failed to start client")

	err = server.Start(ctx)
	require.NoError(t, err, "Failed to start server")

	return client, server
}

// ProtocolHandlers contains all the protocol handlers for a node.
type ProtocolHandlers struct {
	LTP *perception.LTPHandler
	MCP *cognition.MCPHandler
	MEP *cognition.MEPHandler
	EAP *actuation.EAPHandler
}

// createProtocolHandlers creates all the protocol handlers for client and server.
func createProtocolHandlers(t *testing.T, client *core.Client, server *core.Server) (ProtocolHandlers, ProtocolHandlers) {
	// Create client handlers
	clientLTP, err := perception.NewLTPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	require.NoError(t, err, "Failed to create client LTP handler")

	clientMCP, err := cognition.NewMCPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	require.NoError(t, err, "Failed to create client MCP handler")

	clientMEP, err := cognition.NewMEPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
		cognition.WithInMemoryStorage(true),
	)
	require.NoError(t, err, "Failed to create client MEP handler")

	clientEAP, err := actuation.NewEAPHandler(
		client.Transport(),
		client.Serializer(),
		client.Telemetry(),
		client.Logger(),
	)
	require.NoError(t, err, "Failed to create client EAP handler")

	// Create server handlers
	serverLTP, err := perception.NewLTPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	require.NoError(t, err, "Failed to create server LTP handler")

	serverMCP, err := cognition.NewMCPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	require.NoError(t, err, "Failed to create server MCP handler")

	serverMEP, err := cognition.NewMEPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
		cognition.WithInMemoryStorage(true),
	)
	require.NoError(t, err, "Failed to create server MEP handler")

	serverEAP, err := actuation.NewEAPHandler(
		server.Transport(),
		server.Serializer(),
		server.Telemetry(),
		server.Logger(),
	)
	require.NoError(t, err, "Failed to create server EAP handler")

	// Return client and server handlers
	return ProtocolHandlers{
			LTP: clientLTP,
			MCP: clientMCP,
			MEP: clientMEP,
			EAP: clientEAP,
		}, ProtocolHandlers{
			LTP: serverLTP,
			MCP: serverMCP,
			MEP: serverMEP,
			EAP: serverEAP,
		}
}

// setupServerHandlers sets up the server-side handlers for all protocols.
func setupServerHandlers(t *testing.T, ctx context.Context, h ProtocolHandlers) {
	// Setup LTP handler
	err := h.LTP.Receive(ctx, "ltp", func(ctx context.Context, tensor *perception.Tensor, metadata map[string]string) error {
		t.Logf("Server received tensor: %v with metadata: %v", tensor.Shape, metadata)
		return nil
	}, nil)
	require.NoError(t, err, "Failed to setup server LTP handler")

	// Setup MCP handler
	err = h.MCP.Listen(ctx, []func(context.Context, *pb.MCP) error{
		func(ctx context.Context, mcp *pb.MCP) error {
			t.Logf("Server received MCP prompt: %s", mcp.Prompt)

			// Extract tool JSON if available
			var toolData map[string]interface{}
			if len(mcp.ToolJson) > 0 {
				json.Unmarshal(mcp.ToolJson, &toolData)
				t.Logf("With tool data: %v", toolData)
			}

			// Send a response
			responseText := "This is a response to: " + mcp.Prompt
			responseToolJSON, _ := json.Marshal(map[string]interface{}{
				"result": "Success",
				"data":   "Some result data",
			})

			return h.MCP.SendResponse(
				ctx,
				mcp.Id,
				responseText,
				responseToolJSON,
				map[string]string{"source": "test-server"},
				nil,
			)
		},
	}, nil)
	require.NoError(t, err, "Failed to setup server MCP handler")

	// Setup MEP handlers
	err = h.MEP.ListenForOperation(ctx, cognition.MEPOperationCreate, func(ctx context.Context, mep *pb.MEP) error {
		t.Logf("Server received MEP create: %s", mep.Id)
		metadata, _ := h.MEP.ParseMetadata(mep)
		t.Logf("With metadata: %+v", metadata)
		return nil
	}, nil)
	require.NoError(t, err, "Failed to setup server MEP create handler")

	err = h.MEP.ListenForOperation(ctx, cognition.MEPOperationQuery, func(ctx context.Context, mep *pb.MEP) error {
		t.Logf("Server received MEP query with correlation ID: %s", mep.CorrelationId)

		// Parse query parameters
		var params cognition.QueryParams
		if err := json.Unmarshal(mep.Content, &params); err != nil {
			t.Logf("Error parsing query params: %v", err)
			return err
		}

		// Create and send a mock result
		resultContent := []byte(`{"result": "test-result"}`)
		resultMetadata := &cognition.MemoryEventMetadata{
			ContentType: "application/json",
			Labels:      map[string]string{"source": "test"},
			Timestamp:   time.Now(),
		}

		return h.MEP.SendQueryResult(
			ctx,
			mep.CorrelationId,
			"result-1",
			resultContent,
			resultMetadata,
			nil,
		)
	}, nil)
	require.NoError(t, err, "Failed to setup server MEP query handler")

	// Setup EAP handlers
	err = h.EAP.ListenForActions(ctx, deviceID, func(ctx context.Context, eap *pb.EAP) error {
		t.Logf("Server received EAP action: %s (%s)", eap.Name, eap.Id)

		// Parse action parameters
		params, _ := h.EAP.ParseActionParams(eap)
		if params != nil {
			t.Logf("With parameters: %+v", params.Parameters)
		}

		// Send a result
		resultJSON, _ := json.Marshal(map[string]interface{}{
			"success": true,
			"data":    "Action executed successfully",
		})

		return h.EAP.SendActionResult(
			ctx,
			eap.Id,
			deviceID,
			actuation.ActionStatusCompleted,
			resultJSON,
			nil,
		)
	}, nil)
	require.NoError(t, err, "Failed to setup server EAP action handler")
}

// runIntegrationTest runs the actual integration test workflow.
func runIntegrationTest(t *testing.T, ctx context.Context, h ProtocolHandlers) {
	var wg sync.WaitGroup

	// Test 1: Send LTP tensor
	t.Run("SendTensor", func(t *testing.T) {
		// Create tensor data
		tensor := &perception.Tensor{
			Data:        []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			Shape:       []uint32{3, 4},
			DType:       perception.DTypeFloat32,
			FrameID:     "camera_frame",
			TimestampNS: uint64(time.Now().UnixNano()),
		}

		// Send tensor
		messageID, err := h.LTP.Send(ctx, "ltp", tensor, nil)
		require.NoError(t, err, "Failed to send tensor")
		t.Logf("Sent tensor with ID: %s", messageID)

		// Allow time for processing
		time.Sleep(100 * time.Millisecond)
	})

	// Test 2: Send MCP prompt and receive response
	t.Run("SendPromptReceiveResponse", func(t *testing.T) {
		wg.Add(1)

		// Setup response handler
		promptID := ""
		err := h.MCP.Listen(ctx, []func(context.Context, *pb.MCP) error{
			func(ctx context.Context, mcp *pb.MCP) error {
				// Skip if not a response
				if !h.MCP.IsResponse(mcp) {
					return nil
				}

				t.Logf("Client received MCP response: %s", mcp.Prompt)
				if len(mcp.ToolJson) > 0 {
					var toolResult map[string]interface{}
					json.Unmarshal(mcp.ToolJson, &toolResult)
					t.Logf("With tool result: %v", toolResult)
				}
				wg.Done()
				return nil
			},
		}, nil)
		require.NoError(t, err, "Failed to setup MCP response handler")

		// Create tool JSON
		toolJSON, _ := json.Marshal(map[string]interface{}{
			"name": "calculator",
			"params": map[string]interface{}{
				"operation": "add",
				"operands":  []int{5, 7},
			},
		})

		// Send prompt
		promptID, err = h.MCP.Send(ctx, "What is 5 + 7?", "", toolJSON, map[string]string{"test": "true"}, nil)
		require.NoError(t, err, "Failed to send prompt")
		t.Logf("Sent prompt with ID: %s", promptID)

		// Wait for response with timeout
		waitWithTimeout(t, &wg, 2*time.Second)
	})

	// Test 3: Create and query memory
	t.Run("CreateAndQueryMemory", func(t *testing.T) {
		wg.Add(1)

		// Setup query result handler
		var correlationID string
		err := h.MEP.ListenForOperation(ctx, cognition.MEPOperationQuery, func(ctx context.Context, mep *pb.MEP) error {
			if mep.CorrelationId == correlationID {
				// Handle query results
				h.MEP.ListenForQueryResults(ctx, correlationID, func(ctx context.Context, result *pb.MEP) error {
					t.Logf("Received query result: %s", result.Id)
					metadata, _ := h.MEP.ParseMetadata(result)
					t.Logf("With metadata: %+v", metadata)
					wg.Done()
					return nil
				}, nil)
			}
			return nil
		}, nil)
		require.NoError(t, err, "Failed to setup MEP query handler")

		// Create memory
		content := []byte(`{"fact": "The capital of France is Paris"}`)
		metadata := &cognition.MemoryEventMetadata{
			ContentType: "application/json",
			Labels: map[string]string{
				"category": "geography",
				"source":   "test",
			},
			Timestamp: time.Now(),
		}

		memoryID, err := h.MEP.CreateMemory(ctx, content, metadata, nil)
		require.NoError(t, err, "Failed to create memory")
		t.Logf("Created memory with ID: %s", memoryID)

		// Query memory
		queryParams := cognition.QueryParams{
			Limit:       10,
			ContentType: "application/json",
			Labels: map[string]string{
				"category": "geography",
			},
		}

		correlationID, err = h.MEP.QueryMemory(ctx, queryParams, nil)
		require.NoError(t, err, "Failed to query memory")
		t.Logf("Sent memory query with correlation ID: %s", correlationID)

		// Wait for query results with timeout
		waitWithTimeout(t, &wg, 2*time.Second)
	})

	// Test 4: Send EAP action and receive result
	t.Run("SendActionReceiveResult", func(t *testing.T) {
		wg.Add(1)

		// Setup result handler
		err := h.EAP.ListenForResults(ctx, deviceID, func(ctx context.Context, eap *pb.EAP) error {
			t.Logf("Received action result for ID %s with status: %s", eap.Id, eap.Status)
			if eap.Status == actuation.ActionStatusCompleted {
				var resultData map[string]interface{}
				json.Unmarshal(eap.Payload, &resultData)
				t.Logf("Result data: %v", resultData)
				wg.Done()
			}
			return nil
		}, nil)
		require.NoError(t, err, "Failed to setup EAP result handler")

		// Send direct action
		actionID, err := h.EAP.PerformDirectAction(
			ctx,
			deviceID,
			"move_arm",
			map[string]interface{}{
				"joint_angles": []float64{1.0, 0.5, 0.7},
				"speed":        0.8,
			},
			nil,
			5000,
			50,
			nil,
		)
		require.NoError(t, err, "Failed to send action")
		t.Logf("Sent action with ID: %s", actionID)

		// Wait for result with timeout
		waitWithTimeout(t, &wg, 2*time.Second)
	})

	// Test 5: Schedule action
	t.Run("ScheduleAction", func(t *testing.T) {
		// Schedule an action for future execution
		scheduledTime := time.Now().Add(1 * time.Hour)
		actionID, err := h.EAP.ScheduleAction(
			ctx,
			deviceID,
			"take_picture",
			map[string]interface{}{
				"resolution": "high",
				"format":     "jpeg",
			},
			scheduledTime,
			nil,
			30,
			nil,
		)
		require.NoError(t, err, "Failed to schedule action")
		t.Logf("Scheduled action with ID: %s for %s", actionID, scheduledTime.Format(time.RFC3339))
	})
}

// Helper function to wait for waitgroup with timeout
func waitWithTimeout(t *testing.T, wg *sync.WaitGroup, timeout time.Duration) {
	c := make(chan struct{})
	go func() {
		defer close(c)
		wg.Wait()
	}()

	select {
	case <-c:
		// Success!
	case <-time.After(timeout):
		t.Fatalf("Timed out waiting for operation to complete (timeout: %v)", timeout)
	}
}