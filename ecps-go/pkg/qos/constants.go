// Package qos provides Quality of Service constants and utilities for ECPS.
package qos

import (
	"fmt"
	"time"
)

// QoSLevel represents different levels of Quality of Service.
type QoSLevel int

const (
	BestEffort QoSLevel = iota
	Reliable
	Critical
	RealTime
)

func (q QoSLevel) String() string {
	switch q {
	case BestEffort:
		return "best_effort"
	case Reliable:
		return "reliable"
	case Critical:
		return "critical"
	case RealTime:
		return "real_time"
	default:
		return "unknown"
	}
}

// TimingBudgets defines timing constraints for different message types and profiles.
type TimingBudgets struct {
	// MCP (Model Context Protocol) timing budgets
	MCPPromptLatency    time.Duration
	MCPResponseLatency  time.Duration
	MCPToolCallLatency  time.Duration
	
	// MEP (Memory Exchange Protocol) timing budgets
	MEPStoreLatency     time.Duration
	MEPQueryLatency     time.Duration
	MEPRetrieveLatency  time.Duration
	
	// EAP (Embodied Action Protocol) timing budgets
	EAPCommandLatency   time.Duration
	EAPFeedbackLatency  time.Duration
	EAPCancelLatency    time.Duration
	
	// LTP (Latent Tensor Protocol) timing budgets
	LTPTransferLatency  time.Duration
	LTPProcessLatency   time.Duration
	
	// A2A (Agent-to-Agent) timing budgets
	A2ACoordLatency     time.Duration
	A2AConsensusLatency time.Duration
	
	// System timing budgets
	HeartbeatInterval   time.Duration
	TimeoutDuration     time.Duration
}

// EdgeLiteTimingBudgets returns timing budgets for Edge-Lite profile.
func EdgeLiteTimingBudgets() *TimingBudgets {
	return &TimingBudgets{
		// MCP - Relaxed for MCU-class systems
		MCPPromptLatency:    2000 * time.Millisecond,
		MCPResponseLatency:  5000 * time.Millisecond,
		MCPToolCallLatency:  3000 * time.Millisecond,
		
		// MEP - Simple memory operations
		MEPStoreLatency:     500 * time.Millisecond,
		MEPQueryLatency:     1000 * time.Millisecond,
		MEPRetrieveLatency:  300 * time.Millisecond,
		
		// EAP - Basic actuation
		EAPCommandLatency:   200 * time.Millisecond,
		EAPFeedbackLatency:  100 * time.Millisecond,
		EAPCancelLatency:    50 * time.Millisecond,
		
		// LTP - Limited perception processing
		LTPTransferLatency:  1000 * time.Millisecond,
		LTPProcessLatency:   2000 * time.Millisecond,
		
		// A2A - Basic coordination
		A2ACoordLatency:     1000 * time.Millisecond,
		A2AConsensusLatency: 5000 * time.Millisecond,
		
		// System
		HeartbeatInterval:   1000 * time.Millisecond,
		TimeoutDuration:     10000 * time.Millisecond,
	}
}

// StandardTimingBudgets returns timing budgets for Standard profile.
func StandardTimingBudgets() *TimingBudgets {
	return &TimingBudgets{
		// MCP - Balanced performance
		MCPPromptLatency:    1000 * time.Millisecond,
		MCPResponseLatency:  2000 * time.Millisecond,
		MCPToolCallLatency:  1500 * time.Millisecond,
		
		// MEP - Moderate memory operations
		MEPStoreLatency:     200 * time.Millisecond,
		MEPQueryLatency:     500 * time.Millisecond,
		MEPRetrieveLatency:  150 * time.Millisecond,
		
		// EAP - Responsive actuation
		EAPCommandLatency:   100 * time.Millisecond,
		EAPFeedbackLatency:  50 * time.Millisecond,
		EAPCancelLatency:    25 * time.Millisecond,
		
		// LTP - Real-time perception
		LTPTransferLatency:  500 * time.Millisecond,
		LTPProcessLatency:   1000 * time.Millisecond,
		
		// A2A - Efficient coordination
		A2ACoordLatency:     500 * time.Millisecond,
		A2AConsensusLatency: 2000 * time.Millisecond,
		
		// System
		HeartbeatInterval:   500 * time.Millisecond,
		TimeoutDuration:     5000 * time.Millisecond,
	}
}

// CloudFleetTimingBudgets returns timing budgets for Cloud-Fleet profile.
func CloudFleetTimingBudgets() *TimingBudgets {
	return &TimingBudgets{
		// MCP - High-performance processing
		MCPPromptLatency:    500 * time.Millisecond,
		MCPResponseLatency:  1000 * time.Millisecond,
		MCPToolCallLatency:  750 * time.Millisecond,
		
		// MEP - Fast memory operations
		MEPStoreLatency:     100 * time.Millisecond,
		MEPQueryLatency:     200 * time.Millisecond,
		MEPRetrieveLatency:  75 * time.Millisecond,
		
		// EAP - Ultra-responsive actuation
		EAPCommandLatency:   50 * time.Millisecond,
		EAPFeedbackLatency:  25 * time.Millisecond,
		EAPCancelLatency:    10 * time.Millisecond,
		
		// LTP - High-throughput perception
		LTPTransferLatency:  200 * time.Millisecond,
		LTPProcessLatency:   500 * time.Millisecond,
		
		// A2A - Fleet-scale coordination
		A2ACoordLatency:     200 * time.Millisecond,
		A2AConsensusLatency: 1000 * time.Millisecond,
		
		// System
		HeartbeatInterval:   250 * time.Millisecond,
		TimeoutDuration:     2000 * time.Millisecond,
	}
}

// QoSParameters defines QoS parameters for different transport protocols.
type QoSParameters struct {
	// Reliability
	Reliability string // "reliable", "best_effort"
	
	// Durability
	Durability string // "volatile", "transient_local", "transient", "persistent"
	
	// History
	HistoryKind  string // "keep_last", "keep_all"
	HistoryDepth int    // Number of samples to keep
	
	// Deadline
	Deadline time.Duration
	
	// Latency budget
	LatencyBudget time.Duration
	
	// Liveliness
	LivelinessKind     string        // "automatic", "manual_by_participant", "manual_by_topic"
	LivelinessDuration time.Duration
	
	// Resource limits
	MaxSamples         int
	MaxInstances       int
	MaxSamplesPerInstance int
	
	// Transport priority
	TransportPriority int
}

// ConformanceProfiles defines QoS profiles for different conformance levels.
type ConformanceProfiles struct {
	EdgeLite   map[string]*QoSParameters
	Standard   map[string]*QoSParameters
	CloudFleet map[string]*QoSParameters
}

// NewConformanceProfiles creates QoS profiles for all conformance levels.
func NewConformanceProfiles() *ConformanceProfiles {
	return &ConformanceProfiles{
		EdgeLite:   createEdgeLiteProfiles(),
		Standard:   createStandardProfiles(),
		CloudFleet: createCloudFleetProfiles(),
	}
}

// createEdgeLiteProfiles creates QoS profiles for Edge-Lite conformance.
func createEdgeLiteProfiles() map[string]*QoSParameters {
	return map[string]*QoSParameters{
		"mcp": {
			Reliability:           "reliable",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          1,
			Deadline:              2000 * time.Millisecond,
			LatencyBudget:         1000 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    5000 * time.Millisecond,
			MaxSamples:            10,
			MaxInstances:          5,
			MaxSamplesPerInstance: 2,
			TransportPriority:     0,
		},
		"mep": {
			Reliability:           "reliable",
			Durability:            "transient_local",
			HistoryKind:           "keep_last",
			HistoryDepth:          5,
			Deadline:              1000 * time.Millisecond,
			LatencyBudget:         500 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    3000 * time.Millisecond,
			MaxSamples:            50,
			MaxInstances:          10,
			MaxSamplesPerInstance: 5,
			TransportPriority:     1,
		},
		"eap": {
			Reliability:           "reliable",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          1,
			Deadline:              200 * time.Millisecond,
			LatencyBudget:         100 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    1000 * time.Millisecond,
			MaxSamples:            20,
			MaxInstances:          5,
			MaxSamplesPerInstance: 4,
			TransportPriority:     2,
		},
		"ltp": {
			Reliability:           "best_effort",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          1,
			Deadline:              1000 * time.Millisecond,
			LatencyBudget:         500 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    2000 * time.Millisecond,
			MaxSamples:            10,
			MaxInstances:          3,
			MaxSamplesPerInstance: 3,
			TransportPriority:     0,
		},
	}
}

// createStandardProfiles creates QoS profiles for Standard conformance.
func createStandardProfiles() map[string]*QoSParameters {
	return map[string]*QoSParameters{
		"mcp": {
			Reliability:           "reliable",
			Durability:            "transient_local",
			HistoryKind:           "keep_last",
			HistoryDepth:          3,
			Deadline:              1000 * time.Millisecond,
			LatencyBudget:         500 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    3000 * time.Millisecond,
			MaxSamples:            50,
			MaxInstances:          20,
			MaxSamplesPerInstance: 5,
			TransportPriority:     1,
		},
		"mep": {
			Reliability:           "reliable",
			Durability:            "transient_local",
			HistoryKind:           "keep_last",
			HistoryDepth:          10,
			Deadline:              500 * time.Millisecond,
			LatencyBudget:         200 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    2000 * time.Millisecond,
			MaxSamples:            200,
			MaxInstances:          50,
			MaxSamplesPerInstance: 10,
			TransportPriority:     2,
		},
		"eap": {
			Reliability:           "reliable",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          3,
			Deadline:              100 * time.Millisecond,
			LatencyBudget:         50 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    500 * time.Millisecond,
			MaxSamples:            100,
			MaxInstances:          20,
			MaxSamplesPerInstance: 5,
			TransportPriority:     3,
		},
		"ltp": {
			Reliability:           "best_effort",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          3,
			Deadline:              500 * time.Millisecond,
			LatencyBudget:         200 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    1000 * time.Millisecond,
			MaxSamples:            50,
			MaxInstances:          10,
			MaxSamplesPerInstance: 5,
			TransportPriority:     1,
		},
	}
}

// createCloudFleetProfiles creates QoS profiles for Cloud-Fleet conformance.
func createCloudFleetProfiles() map[string]*QoSParameters {
	return map[string]*QoSParameters{
		"mcp": {
			Reliability:           "reliable",
			Durability:            "transient",
			HistoryKind:           "keep_last",
			HistoryDepth:          10,
			Deadline:              500 * time.Millisecond,
			LatencyBudget:         200 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    1000 * time.Millisecond,
			MaxSamples:            500,
			MaxInstances:          100,
			MaxSamplesPerInstance: 10,
			TransportPriority:     2,
		},
		"mep": {
			Reliability:           "reliable",
			Durability:            "persistent",
			HistoryKind:           "keep_last",
			HistoryDepth:          50,
			Deadline:              200 * time.Millisecond,
			LatencyBudget:         100 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    1000 * time.Millisecond,
			MaxSamples:            1000,
			MaxInstances:          200,
			MaxSamplesPerInstance: 20,
			TransportPriority:     3,
		},
		"eap": {
			Reliability:           "reliable",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          5,
			Deadline:              50 * time.Millisecond,
			LatencyBudget:         25 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    250 * time.Millisecond,
			MaxSamples:            500,
			MaxInstances:          100,
			MaxSamplesPerInstance: 10,
			TransportPriority:     4,
		},
		"ltp": {
			Reliability:           "best_effort",
			Durability:            "volatile",
			HistoryKind:           "keep_last",
			HistoryDepth:          5,
			Deadline:              200 * time.Millisecond,
			LatencyBudget:         100 * time.Millisecond,
			LivelinessKind:        "automatic",
			LivelinessDuration:    500 * time.Millisecond,
			MaxSamples:            200,
			MaxInstances:          50,
			MaxSamplesPerInstance: 10,
			TransportPriority:     2,
		},
	}
}

// GetQoSForMessageType returns QoS parameters for a specific message type and transport.
func GetQoSForMessageType(messageType, transport string) map[string]interface{} {
	profiles := NewConformanceProfiles()
	
	// Default to standard profile
	params, exists := profiles.Standard[messageType]
	if !exists {
		// Return default QoS
		return map[string]interface{}{
			"reliability": "reliable",
			"durability":  "volatile",
			"history": map[string]interface{}{
				"kind":  "keep_last",
				"depth": 1,
			},
		}
	}
	
	result := map[string]interface{}{
		"reliability": params.Reliability,
		"durability":  params.Durability,
		"history": map[string]interface{}{
			"kind":  params.HistoryKind,
			"depth": params.HistoryDepth,
		},
		"deadline":         params.Deadline.Milliseconds(),
		"latency_budget":   params.LatencyBudget.Milliseconds(),
		"liveliness": map[string]interface{}{
			"kind":     params.LivelinessKind,
			"duration": params.LivelinessDuration.Milliseconds(),
		},
		"resource_limits": map[string]interface{}{
			"max_samples":              params.MaxSamples,
			"max_instances":            params.MaxInstances,
			"max_samples_per_instance": params.MaxSamplesPerInstance,
		},
		"transport_priority": params.TransportPriority,
	}
	
	return result
}

// GetProfileQoS returns QoS parameters for a specific profile, message type, and transport.
func GetProfileQoS(profile, messageType, transport string) map[string]interface{} {
	profiles := NewConformanceProfiles()
	
	var profileMap map[string]*QoSParameters
	switch profile {
	case "edge-lite":
		profileMap = profiles.EdgeLite
	case "standard":
		profileMap = profiles.Standard
	case "cloud-fleet":
		profileMap = profiles.CloudFleet
	default:
		profileMap = profiles.Standard
	}
	
	params, exists := profileMap[messageType]
	if !exists {
		return GetQoSForMessageType(messageType, transport)
	}
	
	result := map[string]interface{}{
		"reliability": params.Reliability,
		"durability":  params.Durability,
		"history": map[string]interface{}{
			"kind":  params.HistoryKind,
			"depth": params.HistoryDepth,
		},
		"deadline":         params.Deadline.Milliseconds(),
		"latency_budget":   params.LatencyBudget.Milliseconds(),
		"liveliness": map[string]interface{}{
			"kind":     params.LivelinessKind,
			"duration": params.LivelinessDuration.Milliseconds(),
		},
		"resource_limits": map[string]interface{}{
			"max_samples":              params.MaxSamples,
			"max_instances":            params.MaxInstances,
			"max_samples_per_instance": params.MaxSamplesPerInstance,
		},
		"transport_priority": params.TransportPriority,
	}
	
	return result
}

// ValidateTimingBudget validates if actual latency meets the timing budget for a message type and profile.
func ValidateTimingBudget(actualLatency time.Duration, messageType, profile string) bool {
	var budgets *TimingBudgets
	
	switch profile {
	case "edge-lite":
		budgets = EdgeLiteTimingBudgets()
	case "standard":
		budgets = StandardTimingBudgets()
	case "cloud-fleet":
		budgets = CloudFleetTimingBudgets()
	default:
		budgets = StandardTimingBudgets()
	}
	
	var expectedLatency time.Duration
	switch messageType {
	case "mcp_prompt":
		expectedLatency = budgets.MCPPromptLatency
	case "mcp_response":
		expectedLatency = budgets.MCPResponseLatency
	case "mcp_tool_call":
		expectedLatency = budgets.MCPToolCallLatency
	case "mep_store":
		expectedLatency = budgets.MEPStoreLatency
	case "mep_query":
		expectedLatency = budgets.MEPQueryLatency
	case "mep_retrieve":
		expectedLatency = budgets.MEPRetrieveLatency
	case "eap_command":
		expectedLatency = budgets.EAPCommandLatency
	case "eap_feedback":
		expectedLatency = budgets.EAPFeedbackLatency
	case "eap_cancel":
		expectedLatency = budgets.EAPCancelLatency
	case "ltp_transfer":
		expectedLatency = budgets.LTPTransferLatency
	case "ltp_process":
		expectedLatency = budgets.LTPProcessLatency
	case "a2a_coord":
		expectedLatency = budgets.A2ACoordLatency
	case "a2a_consensus":
		expectedLatency = budgets.A2AConsensusLatency
	default:
		return true // Unknown message type, assume valid
	}
	
	return actualLatency <= expectedLatency
}

// GetTimingBudgetForProfile returns the timing budgets for a specific profile.
func GetTimingBudgetForProfile(profile string) *TimingBudgets {
	switch profile {
	case "edge-lite":
		return EdgeLiteTimingBudgets()
	case "standard":
		return StandardTimingBudgets()
	case "cloud-fleet":
		return CloudFleetTimingBudgets()
	default:
		return StandardTimingBudgets()
	}
}