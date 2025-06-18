package serialization

import (
	"context"
	"fmt"
	"strings"

	cloudevents "github.com/cloudevents/sdk-go/v2"
	"github.com/cloudevents/sdk-go/v2/binding"
	"github.com/cloudevents/sdk-go/v2/binding/format"
	"github.com/cloudevents/sdk-go/v2/protocol/http"
	"github.com/cloudevents/sdk-go/v2/types"
	"google.golang.org/protobuf/proto"

	"github.com/ecps/ecps-go/pkg/core"
)

// CloudEventsWrapper implements functionality to wrap ECPS messages in CloudEvents.
type CloudEventsWrapper struct {
	serializer   core.Serializer
	defaultSource string
	specVersion  string
}

// NewCloudEventsWrapper creates a new CloudEventsWrapper.
func NewCloudEventsWrapper(serializer core.Serializer) *CloudEventsWrapper {
	return &CloudEventsWrapper{
		serializer:    serializer,
		defaultSource: "urn:ecps:client",
		specVersion:   "1.0",
	}
}

// getMessageType returns the CloudEvents type for an ECPS message.
func (w *CloudEventsWrapper) getMessageType(message proto.Message) string {
	// Get message type name
	messageType := w.serializer.GetMessageTypeName(message)
	
	// Extract the short type name without package
	parts := strings.Split(messageType, ".")
	shortTypeName := parts[len(parts)-1]
	
	// Map to CloudEvents type
	switch shortTypeName {
	case "MCP":
		return "ecps.mcp.prompt"
	case "LTP":
		return "ecps.ltp.tensor"
	case "EAP":
		return "ecps.eap.action"
	case "Ack":
		return "ecps.mep.ack"
	case "QueryReq":
		return "ecps.mep.query"
	default:
		return fmt.Sprintf("ecps.unknown.%s", strings.ToLower(shortTypeName))
	}
}

// getContentType returns the content type for serialized data.
func (w *CloudEventsWrapper) getContentType(useJSON bool) string {
	if useJSON {
		return "application/cloudevents+json"
	}
	return "application/cloudevents+protobuf"
}

// getMessageID gets or creates a message ID.
func (w *CloudEventsWrapper) getMessageID(message proto.Message) string {
	// Try to get ID field from message using reflection
	id, err := w.serializer.GetField(message, "id")
	if err == nil && id != nil && id.(string) != "" {
		return id.(string)
	}
	
	// Generate a new UUID
	return cloudevents.NewUUID().String()
}

// WrapCloudEvents wraps a message in a CloudEvents envelope.
func (w *CloudEventsWrapper) WrapCloudEvents(message proto.Message, source string, useJSON bool) (map[string]string, []byte, error) {
	// Get message ID
	messageID := w.getMessageID(message)
	
	// Set ID in message if it has an id field
	err := w.serializer.SetField(message, "id", messageID)
	if err != nil {
		// Not all messages might have an ID field, so we'll ignore this error
	}
	
	// Get CloudEvents type
	ceType := w.getMessageType(message)
	
	// Get source
	if source == "" {
		source = w.defaultSource
	}
	
	// Get content type
	contentType := w.getContentType(useJSON)
	
	// Serialize message
	data, err := w.serializer.Serialize(message, useJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize message: %w", err)
	}
	
	// Create CloudEvent
	event := cloudevents.NewEvent()
	event.SetID(messageID)
	event.SetSource(source)
	event.SetType(ceType)
	event.SetSpecVersion(w.specVersion)
	
	// Set data content type and data
	event.SetDataContentType(contentType)
	event.SetData(contentType, data)
	
	// Convert to structured HTTP format using binding API
	httpMessage := http.NewMessageFromEvent(context.Background(), event)
	
	// Get headers and body
	structured := http.NewStructuredWriter(context.Background())
	err = httpMessage.ReadStructured(context.Background(), structured)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to structured format: %w", err)
	}
	
	// Extract headers and body
	headers := structured.Header
	body := structured.Body
	
	// Convert headers to string map
	headerMap := make(map[string]string)
	for k, v := range headers {
		if len(v) > 0 {
			headerMap[k] = v[0]
		}
	}
	
	return headerMap, body, nil
}

// UnwrapCloudEvents extracts a message from a CloudEvents envelope.
func (w *CloudEventsWrapper) UnwrapCloudEvents(headers map[string]string, body []byte, messageType proto.Message) (proto.Message, map[string]string, error) {
	// Convert headers to http.Header
	httpHeaders := make(http.Header)
	for k, v := range headers {
		httpHeaders.Add(k, v)
	}
	
	// Create an HTTP message
	message := http.NewMessage(httpHeaders, body)
	
	// Convert to a CloudEvent
	event, err := binding.ToEvent(context.Background(), message)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to CloudEvent: %w", err)
	}
	
	// Extract CloudEvents attributes
	attributes := map[string]string{
		"id":              event.ID(),
		"source":          event.Source(),
		"type":            event.Type(),
		"specversion":     event.SpecVersion(),
		"datacontenttype": event.DataContentType(),
	}
	
	// Get the data payload
	data := event.Data()
	
	// Determine serialization format
	useJSON := event.DataContentType() == "application/cloudevents+json"
	
	// Deserialize message
	msg, err := w.serializer.Deserialize(data, messageType, useJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to deserialize message: %w", err)
	}
	
	// Cast back to proto.Message
	protoMsg, ok := msg.(proto.Message)
	if !ok {
		return nil, nil, fmt.Errorf("deserialized message is not a proto.Message: %T", msg)
	}
	
	// Mirror CloudEvents ID to message if it has an id field
	err = w.serializer.SetField(protoMsg, "id", event.ID())
	if err != nil {
		// Not all messages might have an ID field, so we'll ignore this error
	}
	
	return protoMsg, attributes, nil
}

// ExtractTraceID extracts trace ID from CloudEvents headers.
func (w *CloudEventsWrapper) ExtractTraceID(headers map[string]string) string {
	// In ECPS, the CloudEvents ID is used as the trace ID
	if ceID, ok := headers["ce-id"]; ok {
		return ceID
	}
	return ""
}

// WrapIntoHTTPRequest wraps a CloudEvents message into HTTP request headers and body.
func (w *CloudEventsWrapper) WrapIntoHTTPRequest(event cloudevents.Event) (map[string]string, []byte, error) {
	// Create an HTTP structured writer
	writer := http.NewStructuredWriter(context.Background())
	
	// Create a message from the event
	message := http.NewMessageFromEvent(context.Background(), event)
	
	// Write the message to the structured writer
	err := message.ReadStructured(context.Background(), writer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to structured format: %w", err)
	}
	
	// Extract headers and body
	headers := make(map[string]string)
	for k, v := range writer.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	
	return headers, writer.Body, nil
}

// UnwrapFromHTTPRequest unwraps a CloudEvents message from HTTP request headers and body.
func (w *CloudEventsWrapper) UnwrapFromHTTPRequest(headers map[string]string, body []byte) (*cloudevents.Event, error) {
	// Convert headers to http.Header
	httpHeaders := make(http.Header)
	for k, v := range headers {
		httpHeaders.Add(k, v)
	}
	
	// Create an HTTP message
	message := http.NewMessage(httpHeaders, body)
	
	// Convert to a CloudEvent
	event, err := binding.ToEvent(context.Background(), message)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to CloudEvent: %w", err)
	}
	
	return event, nil
}

// CreateEvent creates a new CloudEvents event.
func (w *CloudEventsWrapper) CreateEvent(messageID string, source string, eventType string, data interface{}, contentType string) (cloudevents.Event, error) {
	event := cloudevents.NewEvent()
	event.SetID(messageID)
	event.SetSource(source)
	event.SetType(eventType)
	event.SetSpecVersion(w.specVersion)
	
	if contentType != "" {
		event.SetDataContentType(contentType)
	}
	
	if data != nil {
		err := event.SetData(contentType, data)
		if err != nil {
			return cloudevents.Event{}, fmt.Errorf("failed to set event data: %w", err)
		}
	}
	
	return event, nil
}

// BinaryModeProtocol implements a simple protocol for binary mode CloudEvents.
type BinaryModeProtocol struct{}

// NewBinaryModeProtocol creates a new BinaryModeProtocol.
func NewBinaryModeProtocol() *BinaryModeProtocol {
	return &BinaryModeProtocol{}
}

// SendEvent sends an event in binary mode.
func (p *BinaryModeProtocol) SendEvent(ctx context.Context, event cloudevents.Event) (map[string]string, []byte, error) {
	// Create a message from the event
	message := binding.ToMessage(&event)
	
	// Create a writer for binary mode
	writer := http.NewBinaryWriter(context.Background())
	
	// Write the message to the binary writer
	err := message.ReadBinary(ctx, writer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to convert to binary format: %w", err)
	}
	
	// Extract headers and body
	headers := make(map[string]string)
	for k, v := range writer.Header {
		if len(v) > 0 {
			headers[k] = v[0]
		}
	}
	
	return headers, writer.Body, nil
}

// ReceiveEvent receives an event in binary mode.
func (p *BinaryModeProtocol) ReceiveEvent(ctx context.Context, headers map[string]string, body []byte) (*cloudevents.Event, error) {
	// Convert headers to http.Header
	httpHeaders := make(http.Header)
	for k, v := range headers {
		httpHeaders.Add(k, v)
	}
	
	// Create an HTTP message
	message := http.NewMessage(httpHeaders, body)
	
	// Convert to a CloudEvent
	event, err := binding.ToEvent(ctx, message)
	if err != nil {
		return nil, fmt.Errorf("failed to convert to CloudEvent: %w", err)
	}
	
	return event, nil
}