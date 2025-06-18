// Package core provides the core components of the ECPS Go SDK.
package core

import (
	"github.com/ecps/ecps-go/pkg/transport"
	"go.opentelemetry.io/otel/trace"
)

// ProfileType represents the ECPS conformance profile.
type ProfileType string

const (
	// EdgeLiteProfile is for MCU-class robotic arms and small embedded systems.
	EdgeLiteProfile ProfileType = "edge-lite"
	
	// StandardProfile is for lab mobile robots and single-robot deployments.
	StandardProfile ProfileType = "standard"
	
	// CloudFleetProfile is for large-scale deployments of robot fleets.
	CloudFleetProfile ProfileType = "cloud-fleet"
)

// TransportType represents the transport layer to use.
type TransportType string

const (
	// DDSTransport uses DDS/RTPS for real-time local control.
	DDSTransport TransportType = "dds"
	
	// GRPCTransport uses gRPC/HTTP-2 for cloud/WAN communication.
	GRPCTransport TransportType = "grpc"
	
	// MQTTTransport uses MQTT 5 for constrained IoT devices.
	MQTTTransport TransportType = "mqtt"
)

// SerializationFormat represents the serialization format to use.
type SerializationFormat string

const (
	// ProtobufFormat uses Protocol Buffers binary encoding.
	ProtobufFormat SerializationFormat = "protobuf"
	
	// JSONFormat uses JSON encoding (for debugging).
	JSONFormat SerializationFormat = "json"
)

// Config represents the configuration for ECPS client and server components.
type Config struct {
	// Profile is the ECPS conformance profile.
	Profile ProfileType
	
	// TransportType is the transport layer to use.
	TransportType TransportType
	
	// SerializationFormat is the serialization format to use.
	SerializationFormat SerializationFormat
	
	// ObservabilityEnabled determines if OpenTelemetry is enabled.
	ObservabilityEnabled bool
	
	// TransportConfig contains transport-specific configuration.
	TransportConfig map[string]interface{}
	
	// OTLPEndpoint is the OpenTelemetry endpoint URL.
	OTLPEndpoint string
	
	// TracerProvider is the OpenTelemetry tracer provider.
	TracerProvider trace.TracerProvider
	
	// Logger is the logger to use.
	Logger Logger
}

// DefaultConfig returns a default configuration with the Standard profile.
func DefaultConfig() *Config {
	return &Config{
		Profile:              StandardProfile,
		TransportType:        DDSTransport,
		SerializationFormat:  ProtobufFormat,
		ObservabilityEnabled: true,
		TransportConfig:      make(map[string]interface{}),
		OTLPEndpoint:         "http://localhost:4317",
		TracerProvider:       nil, // Will be created if nil
		Logger:               NewDefaultLogger(),
	}
}

// EdgeLiteConfig returns a configuration for the Edge-Lite profile.
func EdgeLiteConfig() *Config {
	config := DefaultConfig()
	config.Profile = EdgeLiteProfile
	config.TransportType = DDSTransport
	config.ObservabilityEnabled = false
	return config
}

// StandardConfig returns a configuration for the Standard profile.
func StandardConfig() *Config {
	return DefaultConfig()
}

// CloudFleetConfig returns a configuration for the Cloud-Fleet profile.
func CloudFleetConfig() *Config {
	config := DefaultConfig()
	config.Profile = CloudFleetProfile
	config.TransportType = GRPCTransport
	return config
}

// Validate validates the configuration based on the selected profile.
func (c *Config) Validate() error {
	// Edge-Lite profile restrictions
	if c.Profile == EdgeLiteProfile {
		if c.TransportType != DDSTransport {
			c.Logger.Warn("Edge-Lite profile typically only supports DDS transport")
		}
		if c.ObservabilityEnabled {
			c.Logger.Warn("Edge-Lite profile typically does not include observability layer")
		}
	}
	
	// Standard profile requirements
	if c.Profile == StandardProfile {
		if c.TransportType != DDSTransport && c.TransportType != GRPCTransport {
			c.Logger.Warn("Standard profile typically uses DDS or gRPC transport")
		}
	}
	
	return nil
}