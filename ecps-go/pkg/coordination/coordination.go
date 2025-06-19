// Package coordination provides coordination capabilities for ECPS including
// agent-to-agent coordination, consensus algorithms, swarm management, and
// intelligent task distribution.
package coordination

import (
	"context"
	"fmt"

	"github.com/ecps/ecps-go/pkg/core"
)

// CoordinationManager manages all coordination services for an ECPS node.
type CoordinationManager struct {
	nodeID          string
	transport       core.Transport
	logger          core.Logger
	
	// Coordination services
	a2aCoordinator  *A2ACoordinator
	raftNode        *RaftNode
	swarmManager    *SwarmManager
	taskDistributor *TaskDistributor
	
	// Configuration
	enableConsensus     bool
	enableSwarmManagement bool
	enableTaskDistribution bool
}

// CoordinationConfig holds configuration for coordination services.
type CoordinationConfig struct {
	NodeID                 string   `json:"node_id"`
	ClusterID              string   `json:"cluster_id"`
	SwarmID                string   `json:"swarm_id,omitempty"`
	Peers                  []string `json:"peers,omitempty"`
	EnableConsensus        bool     `json:"enable_consensus"`
	EnableSwarmManagement  bool     `json:"enable_swarm_management"`
	EnableTaskDistribution bool     `json:"enable_task_distribution"`
}

// NewCoordinationManager creates a new coordination manager.
func NewCoordinationManager(
	config *CoordinationConfig,
	transport core.Transport,
	logger core.Logger,
) *CoordinationManager {
	cm := &CoordinationManager{
		nodeID:                 config.NodeID,
		transport:              transport,
		logger:                 logger,
		enableConsensus:        config.EnableConsensus,
		enableSwarmManagement:  config.EnableSwarmManagement,
		enableTaskDistribution: config.EnableTaskDistribution,
	}
	
	// Initialize A2A coordinator (always enabled)
	cm.a2aCoordinator = NewA2ACoordinator(
		config.NodeID,
		transport,
		nil, // serializer will be provided by transport
		logger,
	)
	
	// Initialize Raft consensus if enabled
	if config.EnableConsensus && len(config.Peers) > 0 {
		cm.raftNode = NewRaftNode(
			config.NodeID,
			config.ClusterID,
			config.Peers,
			transport,
			logger,
		)
	}
	
	// Initialize swarm manager if enabled
	if config.EnableSwarmManagement && config.SwarmID != "" {
		cm.swarmManager = NewSwarmManager(
			config.SwarmID,
			config.NodeID,
			transport,
			logger,
			cm.a2aCoordinator,
		)
	}
	
	// Initialize task distributor if enabled
	if config.EnableTaskDistribution {
		cm.taskDistributor = NewTaskDistributor(
			config.NodeID,
			transport,
			logger,
			cm.a2aCoordinator,
		)
	}
	
	return cm
}

// Start starts all enabled coordination services.
func (cm *CoordinationManager) Start(ctx context.Context) error {
	// Start A2A coordinator
	if err := cm.a2aCoordinator.Start(ctx); err != nil {
		return fmt.Errorf("failed to start A2A coordinator: %w", err)
	}
	
	// Start Raft consensus if enabled
	if cm.raftNode != nil {
		if err := cm.raftNode.Start(ctx); err != nil {
			return fmt.Errorf("failed to start Raft node: %w", err)
		}
	}
	
	// Start swarm manager if enabled
	if cm.swarmManager != nil {
		if err := cm.swarmManager.Start(ctx); err != nil {
			return fmt.Errorf("failed to start swarm manager: %w", err)
		}
	}
	
	// Start task distributor if enabled
	if cm.taskDistributor != nil {
		if err := cm.taskDistributor.Start(ctx); err != nil {
			return fmt.Errorf("failed to start task distributor: %w", err)
		}
	}
	
	cm.logger.Info("Coordination manager started for node %s", cm.nodeID)
	return nil
}

// Stop stops all coordination services.
func (cm *CoordinationManager) Stop() error {
	var lastErr error
	
	// Stop task distributor
	if cm.taskDistributor != nil {
		if err := cm.taskDistributor.Stop(); err != nil {
			cm.logger.Error("Failed to stop task distributor: %v", err)
			lastErr = err
		}
	}
	
	// Stop swarm manager
	if cm.swarmManager != nil {
		if err := cm.swarmManager.Stop(); err != nil {
			cm.logger.Error("Failed to stop swarm manager: %v", err)
			lastErr = err
		}
	}
	
	// Stop Raft node
	if cm.raftNode != nil {
		if err := cm.raftNode.Stop(); err != nil {
			cm.logger.Error("Failed to stop Raft node: %v", err)
			lastErr = err
		}
	}
	
	// Stop A2A coordinator
	if err := cm.a2aCoordinator.Stop(); err != nil {
		cm.logger.Error("Failed to stop A2A coordinator: %v", err)
		lastErr = err
	}
	
	cm.logger.Info("Coordination manager stopped for node %s", cm.nodeID)
	return lastErr
}

// GetA2ACoordinator returns the A2A coordinator.
func (cm *CoordinationManager) GetA2ACoordinator() *A2ACoordinator {
	return cm.a2aCoordinator
}

// GetRaftNode returns the Raft node (may be nil if consensus is disabled).
func (cm *CoordinationManager) GetRaftNode() *RaftNode {
	return cm.raftNode
}

// GetSwarmManager returns the swarm manager (may be nil if swarm management is disabled).
func (cm *CoordinationManager) GetSwarmManager() *SwarmManager {
	return cm.swarmManager
}

// GetTaskDistributor returns the task distributor (may be nil if task distribution is disabled).
func (cm *CoordinationManager) GetTaskDistributor() *TaskDistributor {
	return cm.taskDistributor
}

// GetCoordinationStatus returns the status of all coordination services.
func (cm *CoordinationManager) GetCoordinationStatus() map[string]interface{} {
	status := map[string]interface{}{
		"node_id": cm.nodeID,
		"services": map[string]interface{}{
			"a2a_coordinator": map[string]interface{}{
				"enabled": true,
				"status":  "running",
			},
		},
	}
	
	services := status["services"].(map[string]interface{})
	
	if cm.raftNode != nil {
		state, term, isLeader := cm.raftNode.GetState()
		services["consensus"] = map[string]interface{}{
			"enabled":   true,
			"status":    "running",
			"state":     state.String(),
			"term":      term,
			"is_leader": isLeader,
		}
	} else {
		services["consensus"] = map[string]interface{}{
			"enabled": false,
			"status":  "disabled",
		}
	}
	
	if cm.swarmManager != nil {
		swarmStatus := cm.swarmManager.GetSwarmStatus()
		services["swarm_management"] = map[string]interface{}{
			"enabled": true,
			"status":  "running",
			"details": swarmStatus,
		}
	} else {
		services["swarm_management"] = map[string]interface{}{
			"enabled": false,
			"status":  "disabled",
		}
	}
	
	if cm.taskDistributor != nil {
		distributionStats := cm.taskDistributor.GetDistributionStats()
		services["task_distribution"] = map[string]interface{}{
			"enabled": true,
			"status":  "running",
			"stats":   distributionStats,
		}
	} else {
		services["task_distribution"] = map[string]interface{}{
			"enabled": false,
			"status":  "disabled",
		}
	}
	
	return status
}