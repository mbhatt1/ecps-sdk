package transport

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/eclipse-cyclonedds/cyclonedds-go/dds"
	"github.com/eclipse-cyclonedds/cyclonedds-go/idl"
	"github.com/eclipse-cyclonedds/cyclonedds-go/topic"
	"github.com/google/uuid"

	"github.com/ecps/ecps-go/pkg/core"
	"github.com/ecps/ecps-go/proto"
)

// DDSTransport implements the Transport interface using DDS/RTPS via cyclonedds-go.
type DDSTransport struct {
	*BaseTransport
	domainID      int
	participant   dds.Entity
	publishers    map[string]dds.Publisher
	subscribers   map[string]dds.Subscriber
	readers       map[string]dds.DataReader
	writers       map[string]dds.DataWriter
	topics        map[string]dds.Topic
	pubLock       sync.RWMutex
	subLock       sync.RWMutex
	requestTopics map[string]string // Maps request IDs to reply topics
	requestLock   sync.RWMutex
	responseChan  chan dds.Sample
}

// NewDDSTransport creates a new DDSTransport instance.
func NewDDSTransport(
	config map[string]interface{},
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	isServer bool,
) (*DDSTransport, error) {
	baseTransport := NewBaseTransport(config, serializer, telemetry, logger, isServer)

	// Get DDS-specific configuration
	domainID, ok := config["domain_id"].(int)
	if !ok {
		domainID = 0 // Default domain
	}

	// Set up default QoS for DDS
	baseTransport.defaultQoS = map[string]interface{}{
		"reliability": "reliable",
		"durability":  "transient_local",
		"history": map[string]interface{}{
			"kind":  "keep_last",
			"depth": 4,
		},
	}

	transport := &DDSTransport{
		BaseTransport: baseTransport,
		domainID:      domainID,
		publishers:    make(map[string]dds.Publisher),
		subscribers:   make(map[string]dds.Subscriber),
		readers:       make(map[string]dds.DataReader),
		writers:       make(map[string]dds.DataWriter),
		topics:        make(map[string]dds.Topic),
		requestTopics: make(map[string]string),
		responseChan:  make(chan dds.Sample, 100),
	}

	return transport, nil
}

// createDDSQoSPolicy creates a DDS QoS policy from a map of settings.
func (t *DDSTransport) createDDSQoSPolicy(qosParams map[string]interface{}) dds.QosPolicy {
	qosPolicy := dds.NewQosPolicy()

	// Apply specific QoS parameters
	if reliability, ok := qosParams["reliability"].(string); ok {
		if reliability == "reliable" {
			qosPolicy.SetReliability(dds.ReliabilityReliable, dds.DurationInfinite)
		} else if reliability == "best_effort" {
			qosPolicy.SetReliability(dds.ReliabilityBestEffort, dds.DurationInfinite)
		}
	}

	if durability, ok := qosParams["durability"].(string); ok {
		if durability == "volatile" {
			qosPolicy.SetDurability(dds.DurabilityVolatile)
		} else if durability == "transient_local" {
			qosPolicy.SetDurability(dds.DurabilityTransientLocal)
		} else if durability == "transient" {
			qosPolicy.SetDurability(dds.DurabilityTransient)
		} else if durability == "persistent" {
			qosPolicy.SetDurability(dds.DurabilityPersistent)
		}
	}

	if history, ok := qosParams["history"].(map[string]interface{}); ok {
		if kind, ok := history["kind"].(string); ok {
			if kind == "keep_last" {
				depth := 1
				if depthVal, ok := history["depth"].(int); ok {
					depth = depthVal
				}
				qosPolicy.SetHistory(dds.HistoryKeepLast, depth)
			} else if kind == "keep_all" {
				qosPolicy.SetHistory(dds.HistoryKeepAll, 0)
			}
		}
	}

	return qosPolicy
}

// Start initializes and starts the DDS transport.
func (t *DDSTransport) Start(ctx context.Context) error {
	if t.IsStarted() {
		return nil
	}

	t.logger.Info("Starting DDS transport with domain ID %d", t.domainID)

	// Create DDS participant
	participant, err := dds.CreateParticipant(uint32(t.domainID))
	if err != nil {
		t.logger.Error("Failed to create DDS participant: %v", err)
		return err
	}
	t.participant = participant

	// Create default publisher and subscriber
	publisher, err := dds.CreatePublisher(participant)
	if err != nil {
		t.logger.Error("Failed to create default publisher: %v", err)
		return err
	}
	t.publishers["default"] = publisher

	subscriber, err := dds.CreateSubscriber(participant)
	if err != nil {
		t.logger.Error("Failed to create default subscriber: %v", err)
		return err
	}
	t.subscribers["default"] = subscriber

	t.SetConnected(true)
	t.SetStarted(true)
	t.logger.Info("DDS transport started")
	return nil
}

// Close closes the DDS transport and releases resources.
func (t *DDSTransport) Close() error {
	if !t.IsStarted() {
		return nil
	}

	t.logger.Info("Closing DDS transport")

	// Close all readers
	for _, reader := range t.readers {
		reader.Delete()
	}

	// Close all writers
	for _, writer := range t.writers {
		writer.Delete()
	}

	// Close all topics
	for _, topicObj := range t.topics {
		topicObj.Delete()
	}

	// Close publishers and subscribers
	for _, pub := range t.publishers {
		pub.Delete()
	}
	for _, sub := range t.subscribers {
		sub.Delete()
	}

	// Close participant
	if t.participant != nil {
		t.participant.Delete()
		t.participant = nil
	}

	t.SetConnected(false)
	t.SetStarted(false)
	t.logger.Info("DDS transport closed")
	return nil
}

// Publish publishes a message to a DDS topic.
func (t *DDSTransport) Publish(ctx context.Context, topicName string, message interface{}, qos map[string]interface{}) error {
	if !t.IsStarted() {
		return ErrTransportNotStarted
	}

	// Create a span if telemetry is available
	startTime := time.Now()
	var spanCtx context.Context
	var span trace.Span
	if t.telemetry != nil {
		spanCtx, span = t.telemetry.CreateSpan(ctx, "dds.publish", trace.SpanKindProducer, map[string]interface{}{
			"topic": topicName,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Get or create writer for this topic
	t.pubLock.RLock()
	writer, ok := t.writers[topicName]
	t.pubLock.RUnlock()

	if !ok {
		// Create topic and writer
		t.pubLock.Lock()
		defer t.pubLock.Unlock()

		// Check again in case another goroutine created it
		if writer, ok = t.writers[topicName]; !ok {
			// Get message type
			var err error
			var topicObj dds.Topic

			// Create topic based on message type
			qosPolicy := t.createDDSQoSPolicy(t.ApplyQoS(qos))
			
			// We'll need to create a topic based on the message type
			// For this example, we'll handle a few specific message types
			if mcpMsg, ok := message.(*proto.MCP); ok {
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.MCP{}), qosPolicy)
			} else if ltpMsg, ok := message.(*proto.LTP); ok {
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.LTP{}), qosPolicy)
			} else if eapMsg, ok := message.(*proto.EAP); ok {
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.EAP{}), qosPolicy)
			} else if ackMsg, ok := message.(*proto.Ack); ok {
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.Ack{}), qosPolicy)
			} else if queryMsg, ok := message.(*proto.QueryReq); ok {
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.QueryReq{}), qosPolicy)
			} else {
				return fmt.Errorf("unsupported message type: %T", message)
			}

			if err != nil {
				t.logger.Error("Failed to create topic: %v", err)
				return err
			}
			t.topics[topicName] = topicObj

			// Get the default publisher
			pub := t.publishers["default"]

			// Create writer
			writer, err = dds.CreateDataWriter(pub, topicObj)
			if err != nil {
				t.logger.Error("Failed to create writer: %v", err)
				return err
			}
			t.writers[topicName] = writer
			t.logger.Debug("Created DDS writer for topic %s", topicName)
		}
	}

	// Write the message
	if err := writer.Write(message); err != nil {
		t.logger.Error("Failed to write message: %v", err)
		return err
	}

	t.logger.Debug("Published message to topic %s", topicName)

	// Record metrics
	if t.telemetry != nil {
		elapsedMs := float64(time.Since(startTime).Milliseconds())
		// Record message size if available
		if t.serializer != nil {
			serializedMsg, err := t.serializer.Serialize(message, false)
			if err == nil && len(serializedMsg) > 0 {
				t.RecordBytesSent("dds", len(serializedMsg), map[string]string{
					"topic": topicName,
				})
			}
		}
	}

	return nil
}

// Subscribe subscribes to a DDS topic and registers a handler.
func (t *DDSTransport) Subscribe(ctx context.Context, topicName string, messageType interface{}, handler interface{}, qos map[string]interface{}) error {
	if !t.IsStarted() {
		return ErrTransportNotStarted
	}

	// Validate handler
	if handler == nil {
		return ErrInvalidHandler
	}

	// Validate message type
	if messageType == nil {
		return ErrInvalidMessageType
	}

	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if t.telemetry != nil {
		spanCtx, span = t.telemetry.CreateSpan(ctx, "dds.subscribe", trace.SpanKindConsumer, map[string]interface{}{
			"topic": topicName,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Store the subscription handler
	t.AddTopicHandler(topicName, handler)

	// Get or create reader for this topic
	t.subLock.RLock()
	reader, ok := t.readers[topicName]
	t.subLock.RUnlock()

	if !ok {
		// Create topic and reader
		t.subLock.Lock()
		defer t.subLock.Unlock()

		// Check again in case another goroutine created it
		if reader, ok = t.readers[topicName]; !ok {
			// Create topic based on message type
			var err error
			var topicObj dds.Topic

			// Create QoS policy
			qosPolicy := t.createDDSQoSPolicy(t.ApplyQoS(qos))

			// Create topic based on message type
			switch messageType.(type) {
			case *proto.MCP:
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.MCP{}), qosPolicy)
			case *proto.LTP:
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.LTP{}), qosPolicy)
			case *proto.EAP:
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.EAP{}), qosPolicy)
			case *proto.Ack:
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.Ack{}), qosPolicy)
			case *proto.QueryReq:
				topicObj, err = dds.CreateTopic(t.participant, topicName, idl.GetTopicType(&proto.QueryReq{}), qosPolicy)
			default:
				return fmt.Errorf("unsupported message type: %T", messageType)
			}

			if err != nil {
				t.logger.Error("Failed to create topic: %v", err)
				return err
			}
			t.topics[topicName] = topicObj

			// Get the default subscriber
			sub := t.subscribers["default"]

			// Create reader
			reader, err = dds.CreateDataReader(sub, topicObj)
			if err != nil {
				t.logger.Error("Failed to create reader: %v", err)
				return err
			}
			t.readers[topicName] = reader

			// Create a goroutine to monitor this reader
			go t.readerLoop(ctx, topicName, reader, messageType)

			t.logger.Debug("Created DDS reader for topic %s", topicName)
		}
	}

	return nil
}

// readerLoop is a background goroutine to read messages from a DDS topic.
func (t *DDSTransport) readerLoop(ctx context.Context, topicName string, reader dds.DataReader, messageType interface{}) {
	t.logger.Debug("Started reader loop for topic %s", topicName)

	// Create a DDS ReadCondition for ANY_SAMPLE_STATE | ANY_VIEW_STATE | ANY_INSTANCE_STATE
	condition := dds.NewReadCondition(
		reader,
		dds.AnyState,
		dds.AnyState,
		dds.AnyState,
	)

	// Create a DDS waitset and attach the condition
	waitset := dds.NewWaitSet()
	waitset.Attach(condition)

	for {
		// Check if context is cancelled
		select {
		case <-ctx.Done():
			t.logger.Debug("Reader loop for topic %s stopped: context cancelled", topicName)
			waitset.Detach(condition)
			condition.Delete()
			waitset.Delete()
			return
		default:
			// Continue
		}

		// Wait for data (with timeout)
		waitResult := waitset.Wait(dds.Duration(100 * time.Millisecond))
		if len(waitResult) > 0 {
			// Data is available
			samples := reader.Take(10)
			for _, sample := range samples {
				if sample.Info.ValidData {
					// Process the sample and call the handlers
					t.processMessage(ctx, topicName, sample.Data, messageType)
				}
			}
		}
	}
}

// processMessage processes a received DDS message and calls the appropriate handlers.
func (t *DDSTransport) processMessage(ctx context.Context, topicName string, message interface{}, messageType interface{}) {
	// Create a span if telemetry is available
	startTime := time.Now()
	var spanCtx context.Context
	var span trace.Span
	if t.telemetry != nil {
		spanCtx, span = t.telemetry.CreateSpan(ctx, "dds.receive", trace.SpanKindConsumer, map[string]interface{}{
			"topic": topicName,
		})
		defer span.End()
		ctx = spanCtx
	}

	// Get handlers for this topic
	handlers := t.GetTopicHandlers(topicName)
	if handlers == nil || len(handlers) == 0 {
		t.logger.Debug("No handlers for topic %s", topicName)
		return
	}

	// Call each handler
	for _, h := range handlers {
		// Convert handler to the expected function type based on message type
		switch msg := message.(type) {
		case *proto.MCP:
			if handler, ok := h.(func(context.Context, *proto.MCP) error); ok {
				if err := handler(ctx, msg); err != nil {
					t.logger.Error("Error in MCP handler: %v", err)
				}
			}
		case *proto.LTP:
			if handler, ok := h.(func(context.Context, *proto.LTP) error); ok {
				if err := handler(ctx, msg); err != nil {
					t.logger.Error("Error in LTP handler: %v", err)
				}
			}
		case *proto.EAP:
			if handler, ok := h.(func(context.Context, *proto.EAP) error); ok {
				if err := handler(ctx, msg); err != nil {
					t.logger.Error("Error in EAP handler: %v", err)
				}
			}
		case *proto.Ack:
			if handler, ok := h.(func(context.Context, *proto.Ack) error); ok {
				if err := handler(ctx, msg); err != nil {
					t.logger.Error("Error in Ack handler: %v", err)
				}
			}
		case *proto.QueryReq:
			if handler, ok := h.(func(context.Context, *proto.QueryReq) error); ok {
				if err := handler(ctx, msg); err != nil {
					t.logger.Error("Error in QueryReq handler: %v", err)
				}
			}
		default:
			t.logger.Error("Unsupported message type: %T", message)
		}
	}

	// Record metrics
	if t.telemetry != nil {
		elapsedMs := float64(time.Since(startTime).Milliseconds())
		// Record appropriate metrics
		if t.serializer != nil {
			serializedMsg, err := t.serializer.Serialize(message, false)
			if err == nil && len(serializedMsg) > 0 {
				t.RecordBytesReceived("dds", len(serializedMsg), map[string]string{
					"topic": topicName,
				})
			}
		}
	}
}

// Request sends a request to a service and awaits a response.
func (t *DDSTransport) Request(ctx context.Context, service string, request interface{}, timeout int64, qos map[string]interface{}) (interface{}, error) {
	if !t.IsStarted() {
		return nil, ErrTransportNotStarted
	}

	// Generate a unique correlation ID for this request
	correlationID := uuid.New().String()

	// Create a channel to hold the response
	responseChan := make(chan interface{}, 1)
	errorChan := make(chan error, 1)

	// Subscribe to reply topic with correlation ID
	replyTopic := fmt.Sprintf("%s/reply/%s", service, correlationID)
	t.requestLock.Lock()
	t.requestTopics[correlationID] = replyTopic
	t.requestLock.Unlock()

	// Define reply handler based on the expected response type
	var replyHandler interface{}
	
	// We need to determine the expected response type based on the service
	// For this example, we'll assume specific services and response types
	if service == "MemoryStore.Put" {
		replyHandler = func(ctx context.Context, response *proto.Ack) error {
			select {
			case responseChan <- response:
			default:
				// Channel full, discard
			}
			return nil
		}
	} else {
		// Default handler for unknown service
		return nil, fmt.Errorf("unknown service: %s", service)
	}

	// Subscribe to reply topic
	var responseType interface{}
	if service == "MemoryStore.Put" {
		responseType = &proto.Ack{}
	} else {
		return nil, fmt.Errorf("unknown service: %s", service)
	}

	if err := t.Subscribe(ctx, replyTopic, responseType, replyHandler, qos); err != nil {
		return nil, err
	}

	// Set correlation ID in request if it has an 'id' field
	// Use reflection to try to set the id field
	reqValue := reflect.ValueOf(request).Elem()
	if idField := reqValue.FieldByName("Id"); idField.IsValid() && idField.CanSet() && idField.Kind() == reflect.String {
		idField.SetString(correlationID)
	}

	// Publish request
	requestTopic := fmt.Sprintf("%s/request", service)
	if err := t.Publish(ctx, requestTopic, request, qos); err != nil {
		return nil, err
	}

	// Wait for response with timeout
	var response interface{}
	var err error
	
	select {
	case response = <-responseChan:
		// Got response
	case err = <-errorChan:
		// Got error
	case <-time.After(time.Duration(timeout) * time.Millisecond):
		err = fmt.Errorf("request to service %s timed out after %d ms", service, timeout)
	case <-ctx.Done():
		err = ctx.Err()
	}

	// Clean up
	t.requestLock.Lock()
	delete(t.requestTopics, correlationID)
	t.requestLock.Unlock()

	// Unsubscribe from reply topic
	t.subLock.Lock()
	if reader, ok := t.readers[replyTopic]; ok {
		reader.Delete()
		delete(t.readers, replyTopic)
	}
	t.subLock.Unlock()

	if err != nil {
		return nil, err
	}
	return response, nil
}

// RegisterService registers a service handler.
func (t *DDSTransport) RegisterService(ctx context.Context, service string, handler interface{}, requestType interface{}, responseType interface{}, qos map[string]interface{}) error {
	if !t.IsStarted() {
		return ErrTransportNotStarted
	}

	// Validate handler
	if handler == nil {
		return ErrInvalidHandler
	}

	// Store the service handler
	t.AddServiceHandler(service, handler)

	// Subscribe to request topic
	requestTopic := fmt.Sprintf("%s/request", service)

	// Create wrapper handler that publishes response to reply topic
	wrapperHandler := func(ctx context.Context, request interface{}) error {
		// Call actual handler
		var response interface{}
		var err error

		// Extract correlation ID from request
		reqValue := reflect.ValueOf(request).Elem()
		var correlationID string
		if idField := reqValue.FieldByName("Id"); idField.IsValid() && idField.Kind() == reflect.String {
			correlationID = idField.String()
		} else {
			correlationID = uuid.New().String()
		}

		// Call the handler with the appropriate type
		switch req := request.(type) {
		case *proto.LTP:
			if h, ok := handler.(func(context.Context, *proto.LTP) (*proto.Ack, error)); ok {
				response, err = h(ctx, req)
			} else {
				return fmt.Errorf("invalid handler type for LTP request")
			}
		case *proto.QueryReq:
			// For streaming services, we'll handle differently
			return fmt.Errorf("QueryReq should use RegisterStreamService")
		default:
			return fmt.Errorf("unsupported request type: %T", request)
		}

		if err != nil {
			return err
		}

		// Publish response to reply topic
		replyTopic := fmt.Sprintf("%s/reply/%s", service, correlationID)
		return t.Publish(ctx, replyTopic, response, qos)
	}

	// Subscribe to request topic with wrapper handler
	return t.Subscribe(ctx, requestTopic, requestType, wrapperHandler, qos)
}

// StreamRequest sends a request to a streaming service.
func (t *DDSTransport) StreamRequest(ctx context.Context, service string, request interface{}, handler interface{}, timeout int64, qos map[string]interface{}) error {
	if !t.IsStarted() {
		return ErrTransportNotStarted
	}

	// Generate a unique correlation ID for this request
	correlationID := uuid.New().String()

	// Subscribe to stream topic with correlation ID
	streamTopic := fmt.Sprintf("%s/stream/%s", service, correlationID)

	// Subscribe to stream topic with the provided handler
	var streamType interface{}
	if service == "MemoryStore.Query" {
		streamType = &proto.LTP{}
	} else {
		return fmt.Errorf("unknown streaming service: %s", service)
	}

	if err := t.Subscribe(ctx, streamTopic, streamType, handler, qos); err != nil {
		return err
	}

	// Set correlation ID in request if it has an 'id' field
	reqValue := reflect.ValueOf(request).Elem()
	if idField := reqValue.FieldByName("Id"); idField.IsValid() && idField.CanSet() && idField.Kind() == reflect.String {
		idField.SetString(correlationID)
	}

	// Publish request
	requestTopic := fmt.Sprintf("%s/request", service)
	if err := t.Publish(ctx, requestTopic, request, qos); err != nil {
		return err
	}

	// We don't wait for completion here - the handler will be called for each response

	return nil
}

// RegisterStreamService registers a streaming service handler.
func (t *DDSTransport) RegisterStreamService(ctx context.Context, service string, handler interface{}, requestType interface{}, responseType interface{}, qos map[string]interface{}) error {
	if !t.IsStarted() {
		return ErrTransportNotStarted
	}

	// Validate handler
	if handler == nil {
		return ErrInvalidHandler
	}

	// Store the stream service handler
	t.AddStreamServiceHandler(service, handler)

	// Subscribe to request topic
	requestTopic := fmt.Sprintf("%s/request", service)

	// Create wrapper handler that publishes streamed responses
	wrapperHandler := func(ctx context.Context, request interface{}) error {
		// Extract correlation ID from request
		reqValue := reflect.ValueOf(request).Elem()
		var correlationID string
		if idField := reqValue.FieldByName("Id"); idField.IsValid() && idField.Kind() == reflect.String {
			correlationID = idField.String()
		} else {
			correlationID = uuid.New().String()
		}

		// Stream topic for this request
		streamTopic := fmt.Sprintf("%s/stream/%s", service, correlationID)

		// Define publisher function to pass to handler
		publishResponse := func(response interface{}, isFinal bool) error {
			// Publish response to stream topic
			return t.Publish(ctx, streamTopic, response, qos)
		}

		// Call the handler with the appropriate type
		switch req := request.(type) {
		case *proto.QueryReq:
			if h, ok := handler.(func(context.Context, *proto.QueryReq, func(interface{}, bool) error) error); ok {
				return h(ctx, req, publishResponse)
			}
			return fmt.Errorf("invalid handler type for QueryReq request")
		default:
			return fmt.Errorf("unsupported request type: %T", request)
		}
	}

	// Subscribe to request topic with wrapper handler
	return t.Subscribe(ctx, requestTopic, requestType, wrapperHandler, qos)
}