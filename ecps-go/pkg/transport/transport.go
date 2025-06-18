// Package transport provides implementations of the Transport interface
// for various protocols (DDS, gRPC, MQTT).
package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/ecps/ecps-go/pkg/core"
)

// BaseTransport provides common functionality for all transport implementations.
type BaseTransport struct {
	config          map[string]interface{}
	serializer      core.Serializer
	telemetry       core.Telemetry
	logger          core.Logger
	isServer        bool
	topics          map[string][]interface{} // topic -> list of handlers
	services        map[string]interface{}   // service -> handler
	streamServices  map[string]interface{}   // service -> stream handler
	subscriptions   map[string]interface{}   // topic -> subscription handle/ID
	servicesLock    sync.RWMutex
	topicsLock      sync.RWMutex
	started         bool
	connected       bool
	defaultQoS      map[string]interface{}
}

// NewBaseTransport creates a new BaseTransport.
func NewBaseTransport(
	config map[string]interface{},
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	isServer bool,
) *BaseTransport {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}

	return &BaseTransport{
		config:         config,
		serializer:     serializer,
		telemetry:      telemetry,
		logger:         logger,
		isServer:       isServer,
		topics:         make(map[string][]interface{}),
		services:       make(map[string]interface{}),
		streamServices: make(map[string]interface{}),
		subscriptions:  make(map[string]interface{}),
		started:        false,
		connected:      false,
		defaultQoS:     make(map[string]interface{}),
	}
}

// ErrTransportNotStarted is returned when a transport operation is attempted before the transport is started.
var ErrTransportNotStarted = errors.New("transport not started")

// ErrTransportNotConnected is returned when a transport operation is attempted before the transport is connected.
var ErrTransportNotConnected = errors.New("transport not connected")

// ErrInvalidMessageType is returned when an invalid message type is provided.
var ErrInvalidMessageType = errors.New("invalid message type")

// ErrInvalidHandler is returned when an invalid handler is provided.
var ErrInvalidHandler = errors.New("invalid handler")

// ErrUnsupportedOperation is returned when an operation is not supported by the transport.
var ErrUnsupportedOperation = errors.New("unsupported operation")

// CreateTransport creates a new Transport implementation based on the transport type.
func CreateTransport(
	transportType string,
	config map[string]interface{},
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	isServer bool,
) (core.Transport, error) {
	switch transportType {
	case "dds":
		return NewDDSTransport(config, serializer, telemetry, logger, isServer)
	case "grpc":
		return NewGRPCTransport(config, serializer, telemetry, logger, isServer)
	case "mqtt":
		return NewMQTTTransport(config, serializer, telemetry, logger, isServer)
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", transportType)
	}
}

// AddTopicHandler adds a handler for a topic.
func (t *BaseTransport) AddTopicHandler(topic string, handler interface{}) {
	t.topicsLock.Lock()
	defer t.topicsLock.Unlock()

	if t.topics[topic] == nil {
		t.topics[topic] = make([]interface{}, 0)
	}
	t.topics[topic] = append(t.topics[topic], handler)
}

// GetTopicHandlers gets all handlers for a topic.
func (t *BaseTransport) GetTopicHandlers(topic string) []interface{} {
	t.topicsLock.RLock()
	defer t.topicsLock.RUnlock()

	if handlers, ok := t.topics[topic]; ok {
		return handlers
	}
	return nil
}

// AddServiceHandler adds a handler for a service.
func (t *BaseTransport) AddServiceHandler(service string, handler interface{}) {
	t.servicesLock.Lock()
	defer t.servicesLock.Unlock()

	t.services[service] = handler
}

// GetServiceHandler gets the handler for a service.
func (t *BaseTransport) GetServiceHandler(service string) interface{} {
	t.servicesLock.RLock()
	defer t.servicesLock.RUnlock()

	return t.services[service]
}

// AddStreamServiceHandler adds a handler for a streaming service.
func (t *BaseTransport) AddStreamServiceHandler(service string, handler interface{}) {
	t.servicesLock.Lock()
	defer t.servicesLock.Unlock()

	t.streamServices[service] = handler
}

// GetStreamServiceHandler gets the handler for a streaming service.
func (t *BaseTransport) GetStreamServiceHandler(service string) interface{} {
	t.servicesLock.RLock()
	defer t.servicesLock.RUnlock()

	return t.streamServices[service]
}

// AddSubscription adds a subscription handle/ID for a topic.
func (t *BaseTransport) AddSubscription(topic string, subscription interface{}) {
	t.topicsLock.Lock()
	defer t.topicsLock.Unlock()

	t.subscriptions[topic] = subscription
}

// GetSubscription gets the subscription handle/ID for a topic.
func (t *BaseTransport) GetSubscription(topic string) interface{} {
	t.topicsLock.RLock()
	defer t.topicsLock.RUnlock()

	return t.subscriptions[topic]
}

// RemoveSubscription removes a subscription handle/ID for a topic.
func (t *BaseTransport) RemoveSubscription(topic string) {
	t.topicsLock.Lock()
	defer t.topicsLock.Unlock()

	delete(t.subscriptions, topic)
}

// IsServer returns whether this transport is for a server.
func (t *BaseTransport) IsServer() bool {
	return t.isServer
}

// IsStarted returns whether the transport is started.
func (t *BaseTransport) IsStarted() bool {
	return t.started
}

// IsConnected returns whether the transport is connected.
func (t *BaseTransport) IsConnected() bool {
	return t.connected
}

// SetStarted sets the started state.
func (t *BaseTransport) SetStarted(started bool) {
	t.started = started
}

// SetConnected sets the connected state.
func (t *BaseTransport) SetConnected(connected bool) {
	t.connected = connected
}

// GetConfig gets a configuration value.
func (t *BaseTransport) GetConfig(key string, defaultValue interface{}) interface{} {
	if value, ok := t.config[key]; ok {
		return value
	}
	return defaultValue
}

// RecordBytesSent records bytes sent over transport.
func (t *BaseTransport) RecordBytesSent(transportType string, bytesCount int, attributes map[string]string) {
	if t.telemetry != nil {
		t.telemetry.RecordBytesSent(bytesCount, transportType, attributes)
	}
}

// RecordBytesReceived records bytes received over transport.
func (t *BaseTransport) RecordBytesReceived(transportType string, bytesCount int, attributes map[string]string) {
	if t.telemetry != nil {
		t.telemetry.RecordBytesReceived(bytesCount, transportType, attributes)
	}
}

// ApplyQoS applies QoS settings, merging with defaults.
func (t *BaseTransport) ApplyQoS(qos map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy default QoS settings
	for k, v := range t.defaultQoS {
		result[k] = v
	}

	// Apply specific QoS settings
	if qos != nil {
		for k, v := range qos {
			result[k] = v
		}
	}

	return result
}