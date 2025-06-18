package core

import (
	"context"
	"io"

	"github.com/ecps/ecps-go/proto"
	"go.opentelemetry.io/otel/trace"
)

// Transport is the interface for the transport layer (L2).
type Transport interface {
	// Start starts the transport server.
	Start(ctx context.Context) error

	// Close closes the transport and releases resources.
	Close() error

	// Publish publishes a message to a topic.
	Publish(ctx context.Context, topic string, message interface{}, qos map[string]interface{}) error

	// Subscribe subscribes to a topic and registers a handler.
	Subscribe(ctx context.Context, topic string, messageType interface{}, handler interface{}, qos map[string]interface{}) error

	// Request sends a request to a service and awaits a response.
	Request(ctx context.Context, service string, request interface{}, timeout int64, qos map[string]interface{}) (interface{}, error)

	// RegisterService registers a service handler.
	RegisterService(ctx context.Context, service string, handler interface{}, requestType interface{}, responseType interface{}, qos map[string]interface{}) error

	// StreamRequest sends a request to a service and handles streamed responses.
	StreamRequest(ctx context.Context, service string, request interface{}, handler interface{}, timeout int64, qos map[string]interface{}) error

	// RegisterStreamService registers a streaming service handler.
	RegisterStreamService(ctx context.Context, service string, handler interface{}, requestType interface{}, responseType interface{}, qos map[string]interface{}) error
}

// Serializer is the interface for the serialization layer (L3).
type Serializer interface {
	// Serialize serializes a message to bytes.
	Serialize(message interface{}, useJSON bool) ([]byte, error)

	// Deserialize deserializes bytes to a message.
	Deserialize(data []byte, messageType interface{}, useJSON bool) (interface{}, error)

	// GetMessageTypeName returns the type name of a message.
	GetMessageTypeName(message interface{}) string

	// IsValidMessage checks if an object is a valid message.
	IsValidMessage(message interface{}) bool

	// WrapCloudEvents wraps a message in a CloudEvents envelope.
	WrapCloudEvents(message interface{}, source string, useJSON bool) (map[string]string, []byte, error)

	// UnwrapCloudEvents extracts a message from a CloudEvents envelope.
	UnwrapCloudEvents(headers map[string]string, body []byte, messageType interface{}) (interface{}, map[string]string, error)

	// ExtractTraceID extracts the trace ID from CloudEvents headers.
	ExtractTraceID(headers map[string]string) string
}

// Telemetry is the interface for the observability layer (L4).
type Telemetry interface {
	// Tracer returns an OpenTelemetry tracer.
	Tracer() trace.Tracer

	// CreateSpan creates a new span for tracing.
	CreateSpan(ctx context.Context, name string, kind trace.SpanKind, attributes map[string]interface{}) (context.Context, trace.Span)

	// RecordEAPLatency records EAP action execution latency.
	RecordEAPLatency(latencyMs float64, attributes map[string]string)

	// RecordLTPFrameSize records LTP frame size.
	RecordLTPFrameSize(sizeBytes int, attributes map[string]string)

	// RecordMCPPromptSize records MCP prompt size.
	RecordMCPPromptSize(chars int, attributes map[string]string)

	// RecordMEPQueryLatency records MEP query latency.
	RecordMEPQueryLatency(latencyMs float64, attributes map[string]string)

	// RecordBytesSent records bytes sent over transport.
	RecordBytesSent(bytesCount int, transportType string, attributes map[string]string)

	// RecordBytesReceived records bytes received over transport.
	RecordBytesReceived(bytesCount int, transportType string, attributes map[string]string)

	// InjectContext injects trace context into headers.
	InjectContext(ctx context.Context, headers map[string]string) map[string]string

	// ExtractContext extracts trace context from headers.
	ExtractContext(ctx context.Context, headers map[string]string) context.Context

	// Shutdown shuts down telemetry providers and exporters.
	Shutdown(ctx context.Context) error
}

// MessageHandler is the interface for handling ECPS messages.
type MessageHandler interface {
	// SendMCP sends an MCP message.
	SendMCP(ctx context.Context, prompt string, toolJSON []byte, meta map[string]string) (string, error)

	// ListenMCP starts listening for MCP messages.
	ListenMCP(ctx context.Context, handler func(context.Context, *proto.MCP) error) error

	// SendEAP sends an EAP message.
	SendEAP(ctx context.Context, actionType string, actionData interface{}, stateSHA []byte, meta map[string]string) (string, error)

	// ListenEAP starts listening for EAP messages.
	ListenEAP(ctx context.Context, handler func(context.Context, *proto.EAP) error) error

	// StoreLTP stores an LTP message (tensor).
	StoreLTP(ctx context.Context, tensorZstd []byte, shape []uint32, dtype string, frameID string, timestampNS uint64) (bool, string, error)

	// QueryLTP queries for similar LTP messages (tensors).
	QueryLTP(ctx context.Context, queryEmbedding *proto.LTP, k uint32, minSim float32) ([]*proto.LTP, error)
}

// MEPService is the interface for the Memory Exchange Protocol service.
type MEPService interface {
	// Start starts the MEP service.
	Start(ctx context.Context) error

	// Stop stops the MEP service.
	Stop(ctx context.Context) error

	// Put stores an embedding.
	Put(ctx context.Context, ltp *proto.LTP) (*proto.Ack, error)

	// Query queries for similar embeddings.
	Query(ctx context.Context, req *proto.QueryReq, resultChan chan<- *proto.LTP) error
}

// VectorStore is the interface for the vector storage backend.
type VectorStore interface {
	// Put stores a vector.
	Put(ctx context.Context, vector []float32, metadata map[string]interface{}) error

	// Query queries for similar vectors.
	Query(ctx context.Context, vector []float32, k int, minSim float32) ([]struct {
		Vector   []float32
		Metadata map[string]interface{}
		Score    float32
	}, error)

	// Close closes the vector store.
	Close() error
}

// ActionLogger is the interface for logging EAP actions.
type ActionLogger interface {
	// OpenLog opens a log file.
	OpenLog(logName string) error

	// LogAction logs an EAP action.
	LogAction(eap *proto.EAP) error

	// Close closes the log file.
	Close() error
}

// File is an interface for file operations.
type File interface {
	io.Writer
	io.Reader
	io.Closer
}

// FileSystem is an interface for file system operations.
type FileSystem interface {
	// Open opens a file for reading.
	Open(name string) (File, error)

	// Create creates or truncates a file for writing.
	Create(name string) (File, error)

	// Append opens a file for appending.
	Append(name string) (File, error)

	// MkdirAll creates a directory and all parent directories if they don't exist.
	MkdirAll(path string, perm uint32) error

	// Exists checks if a file or directory exists.
	Exists(path string) (bool, error)
}