// Package coordination provides swarm management capabilities for ECPS.
package coordination

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ecps/ecps-go/pkg/core"
)

// SwarmRole represents the role of an agent in the swarm.
type SwarmRole string

const (
	SwarmLeader   SwarmRole = "leader"
	SwarmFollower SwarmRole = "follower"
	SwarmWorker   SwarmRole = "worker"
	SwarmScout    SwarmRole = "scout"
)

// SwarmAgent represents an agent in the swarm.
type SwarmAgent struct {
	ID           string                 `json:"id"`
	Role         SwarmRole              `json:"role"`
	Capabilities []string               `json:"capabilities"`
	Status       string                 `json:"status"` // "active", "inactive", "busy", "error"
	LastSeen     time.Time              `json:"last_seen"`
	Position     map[string]float64     `json:"position,omitempty"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// SwarmTask represents a task to be executed by the swarm.
type SwarmTask struct {
	ID           string                 `json:"id"`
	Type         string                 `json:"type"`
	Priority     int                    `json:"priority"`
	Requirements []string               `json:"requirements"`
	Data         map[string]interface{} `json:"data"`
	AssignedTo   []string               `json:"assigned_to"`
	Status       string                 `json:"status"` // "pending", "assigned", "running", "completed", "failed"
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Deadline     time.Time              `json:"deadline,omitempty"`
}

// SwarmFormation represents a formation configuration for the swarm.
type SwarmFormation struct {
	Name        string                            `json:"name"`
	Type        string                            `json:"type"` // "line", "circle", "grid", "custom"
	Positions   map[string]map[string]float64     `json:"positions"`
	Parameters  map[string]interface{}            `json:"parameters"`
	Constraints map[string]interface{}            `json:"constraints"`
}

// SwarmManager manages a swarm of robotic agents.
type SwarmManager struct {
	swarmID     string
	agentID     string
	transport   core.Transport
	logger      core.Logger
	coordinator *A2ACoordinator
	
	// Swarm state
	mu          sync.RWMutex
	agents      map[string]*SwarmAgent
	tasks       map[string]*SwarmTask
	formations  map[string]*SwarmFormation
	currentRole SwarmRole
	
	// Configuration
	heartbeatInterval time.Duration
	agentTimeout      time.Duration
	taskTimeout       time.Duration
	
	// Channels
	taskChan      chan *SwarmTask
	agentChan     chan *SwarmAgent
	formationChan chan *SwarmFormation
	stopChan      chan struct{}
	
	// Handlers
	taskHandlers      []func(context.Context, *SwarmTask) error
	agentHandlers     []func(context.Context, *SwarmAgent) error
	formationHandlers []func(context.Context, *SwarmFormation) error
}

// NewSwarmManager creates a new swarm manager.
func NewSwarmManager(
	swarmID string,
	agentID string,
	transport core.Transport,
	logger core.Logger,
	coordinator *A2ACoordinator,
) *SwarmManager {
	return &SwarmManager{
		swarmID:           swarmID,
		agentID:           agentID,
		transport:         transport,
		logger:            logger,
		coordinator:       coordinator,
		agents:            make(map[string]*SwarmAgent),
		tasks:             make(map[string]*SwarmTask),
		formations:        make(map[string]*SwarmFormation),
		currentRole:       SwarmFollower,
		heartbeatInterval: 5 * time.Second,
		agentTimeout:      30 * time.Second,
		taskTimeout:       5 * time.Minute,
		taskChan:          make(chan *SwarmTask, 100),
		agentChan:         make(chan *SwarmAgent, 100),
		formationChan:     make(chan *SwarmFormation, 100),
		stopChan:          make(chan struct{}),
	}
}

// Start starts the swarm manager.
func (sm *SwarmManager) Start(ctx context.Context) error {
	// Subscribe to swarm messages
	swarmTopic := fmt.Sprintf("swarm/%s/messages", sm.swarmID)
	if err := sm.transport.Subscribe(ctx, swarmTopic, &map[string]interface{}{}, sm.handleSwarmMessage, nil); err != nil {
		return fmt.Errorf("failed to subscribe to swarm messages: %w", err)
	}
	
	// Register self as swarm agent
	self := &SwarmAgent{
		ID:           sm.agentID,
		Role:         sm.currentRole,
		Capabilities: []string{"coordination", "task_execution"},
		Status:       "active",
		LastSeen:     time.Now(),
		Metadata:     make(map[string]interface{}),
	}
	
	sm.mu.Lock()
	sm.agents[sm.agentID] = self
	sm.mu.Unlock()
	
	// Start background goroutines
	go sm.heartbeat(ctx)
	go sm.processMessages(ctx)
	go sm.monitorAgents(ctx)
	go sm.manageTasks(ctx)
	
	sm.logger.Info("Swarm manager started for swarm %s, agent %s", sm.swarmID, sm.agentID)
	return nil
}

// Stop stops the swarm manager.
func (sm *SwarmManager) Stop() error {
	close(sm.stopChan)
	sm.logger.Info("Swarm manager stopped for swarm %s", sm.swarmID)
	return nil
}

// JoinSwarm joins this agent to the swarm.
func (sm *SwarmManager) JoinSwarm(capabilities []string, metadata map[string]interface{}) error {
	agent := &SwarmAgent{
		ID:           sm.agentID,
		Role:         SwarmFollower,
		Capabilities: capabilities,
		Status:       "active",
		LastSeen:     time.Now(),
		Metadata:     metadata,
	}
	
	sm.mu.Lock()
	sm.agents[sm.agentID] = agent
	sm.currentRole = SwarmFollower
	sm.mu.Unlock()
	
	// Broadcast join message
	message := map[string]interface{}{
		"type":   "agent_join",
		"agent":  agent,
		"sender": sm.agentID,
	}
	
	return sm.broadcastSwarmMessage(message)
}

// LeaveSwarm removes this agent from the swarm.
func (sm *SwarmManager) LeaveSwarm() error {
	sm.mu.Lock()
	delete(sm.agents, sm.agentID)
	sm.currentRole = SwarmFollower
	sm.mu.Unlock()
	
	// Broadcast leave message
	message := map[string]interface{}{
		"type":     "agent_leave",
		"agent_id": sm.agentID,
		"sender":   sm.agentID,
	}
	
	return sm.broadcastSwarmMessage(message)
}

// AssignTask assigns a task to specific agents in the swarm.
func (sm *SwarmManager) AssignTask(
	taskType string,
	requirements []string,
	data map[string]interface{},
	priority int,
	deadline time.Time,
) (*SwarmTask, error) {
	task := &SwarmTask{
		ID:           uuid.New().String(),
		Type:         taskType,
		Priority:     priority,
		Requirements: requirements,
		Data:         data,
		Status:       "pending",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		Deadline:     deadline,
	}
	
	// Find suitable agents
	suitableAgents := sm.findSuitableAgents(requirements)
	if len(suitableAgents) == 0 {
		return nil, errors.New("no suitable agents found for task")
	}
	
	task.AssignedTo = suitableAgents
	task.Status = "assigned"
	task.UpdatedAt = time.Now()
	
	sm.mu.Lock()
	sm.tasks[task.ID] = task
	sm.mu.Unlock()
	
	// Broadcast task assignment
	message := map[string]interface{}{
		"type":   "task_assigned",
		"task":   task,
		"sender": sm.agentID,
	}
	
	if err := sm.broadcastSwarmMessage(message); err != nil {
		return nil, fmt.Errorf("failed to broadcast task assignment: %w", err)
	}
	
	sm.logger.Info("Assigned task %s to agents: %v", task.ID, suitableAgents)
	return task, nil
}

// UpdateTaskStatus updates the status of a task.
func (sm *SwarmManager) UpdateTaskStatus(taskID, status string, result map[string]interface{}) error {
	sm.mu.Lock()
	task, exists := sm.tasks[taskID]
	if !exists {
		sm.mu.Unlock()
		return errors.New("task not found")
	}
	
	task.Status = status
	task.UpdatedAt = time.Now()
	if result != nil {
		task.Data["result"] = result
	}
	sm.mu.Unlock()
	
	// Broadcast task update
	message := map[string]interface{}{
		"type":   "task_updated",
		"task":   task,
		"sender": sm.agentID,
	}
	
	return sm.broadcastSwarmMessage(message)
}

// SetFormation sets a formation for the swarm.
func (sm *SwarmManager) SetFormation(formation *SwarmFormation) error {
	sm.mu.Lock()
	sm.formations[formation.Name] = formation
	sm.mu.Unlock()
	
	// Broadcast formation update
	message := map[string]interface{}{
		"type":      "formation_set",
		"formation": formation,
		"sender":    sm.agentID,
	}
	
	return sm.broadcastSwarmMessage(message)
}

// GetSwarmStatus returns the current status of the swarm.
func (sm *SwarmManager) GetSwarmStatus() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	activeAgents := 0
	busyAgents := 0
	for _, agent := range sm.agents {
		if agent.Status == "active" {
			activeAgents++
		} else if agent.Status == "busy" {
			busyAgents++
		}
	}
	
	pendingTasks := 0
	runningTasks := 0
	completedTasks := 0
	for _, task := range sm.tasks {
		switch task.Status {
		case "pending", "assigned":
			pendingTasks++
		case "running":
			runningTasks++
		case "completed":
			completedTasks++
		}
	}
	
	return map[string]interface{}{
		"swarm_id":        sm.swarmID,
		"agent_count":     len(sm.agents),
		"active_agents":   activeAgents,
		"busy_agents":     busyAgents,
		"pending_tasks":   pendingTasks,
		"running_tasks":   runningTasks,
		"completed_tasks": completedTasks,
		"formations":      len(sm.formations),
		"current_role":    sm.currentRole,
	}
}

// GetAgents returns a copy of all known agents.
func (sm *SwarmManager) GetAgents() map[string]*SwarmAgent {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	result := make(map[string]*SwarmAgent)
	for id, agent := range sm.agents {
		result[id] = &SwarmAgent{
			ID:           agent.ID,
			Role:         agent.Role,
			Capabilities: append([]string{}, agent.Capabilities...),
			Status:       agent.Status,
			LastSeen:     agent.LastSeen,
			Position:     make(map[string]float64),
			Metadata:     make(map[string]interface{}),
		}
		
		// Copy position
		for k, v := range agent.Position {
			result[id].Position[k] = v
		}
		
		// Copy metadata
		for k, v := range agent.Metadata {
			result[id].Metadata[k] = v
		}
	}
	
	return result
}

// GetTasks returns a copy of all tasks.
func (sm *SwarmManager) GetTasks() map[string]*SwarmTask {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	result := make(map[string]*SwarmTask)
	for id, task := range sm.tasks {
		result[id] = &SwarmTask{
			ID:           task.ID,
			Type:         task.Type,
			Priority:     task.Priority,
			Requirements: append([]string{}, task.Requirements...),
			Data:         make(map[string]interface{}),
			AssignedTo:   append([]string{}, task.AssignedTo...),
			Status:       task.Status,
			CreatedAt:    task.CreatedAt,
			UpdatedAt:    task.UpdatedAt,
			Deadline:     task.Deadline,
		}
		
		// Copy data
		for k, v := range task.Data {
			result[id].Data[k] = v
		}
	}
	
	return result
}

// OnTaskAssigned registers a handler for task assignments.
func (sm *SwarmManager) OnTaskAssigned(handler func(context.Context, *SwarmTask) error) {
	sm.taskHandlers = append(sm.taskHandlers, handler)
}

// OnAgentJoined registers a handler for agent joins.
func (sm *SwarmManager) OnAgentJoined(handler func(context.Context, *SwarmAgent) error) {
	sm.agentHandlers = append(sm.agentHandlers, handler)
}

// OnFormationChanged registers a handler for formation changes.
func (sm *SwarmManager) OnFormationChanged(handler func(context.Context, *SwarmFormation) error) {
	sm.formationHandlers = append(sm.formationHandlers, handler)
}

// findSuitableAgents finds agents that meet the task requirements.
func (sm *SwarmManager) findSuitableAgents(requirements []string) []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	
	var suitable []string
	for agentID, agent := range sm.agents {
		if agent.Status != "active" {
			continue
		}
		
		// Check if agent has all required capabilities
		hasAll := true
		for _, req := range requirements {
			found := false
			for _, cap := range agent.Capabilities {
				if cap == req {
					found = true
					break
				}
			}
			if !found {
				hasAll = false
				break
			}
		}
		
		if hasAll {
			suitable = append(suitable, agentID)
		}
	}
	
	return suitable
}

// broadcastSwarmMessage broadcasts a message to all swarm members.
func (sm *SwarmManager) broadcastSwarmMessage(message map[string]interface{}) error {
	topic := fmt.Sprintf("swarm/%s/messages", sm.swarmID)
	return sm.transport.Publish(context.Background(), topic, message, nil)
}

// handleSwarmMessage handles incoming swarm messages.
func (sm *SwarmManager) handleSwarmMessage(ctx context.Context, message interface{}) error {
	data, ok := message.(*map[string]interface{})
	if !ok {
		return errors.New("invalid swarm message type")
	}
	
	msgType, ok := (*data)["type"].(string)
	if !ok {
		return errors.New("missing message type")
	}
	
	sender, ok := (*data)["sender"].(string)
	if !ok {
		return errors.New("missing sender")
	}
	
	// Ignore messages from self
	if sender == sm.agentID {
		return nil
	}
	
	switch msgType {
	case "agent_join":
		return sm.handleAgentJoin(ctx, *data)
	case "agent_leave":
		return sm.handleAgentLeave(ctx, *data)
	case "task_assigned":
		return sm.handleTaskAssigned(ctx, *data)
	case "task_updated":
		return sm.handleTaskUpdated(ctx, *data)
	case "formation_set":
		return sm.handleFormationSet(ctx, *data)
	case "heartbeat":
		return sm.handleHeartbeat(ctx, *data)
	default:
		sm.logger.Debug("Unknown swarm message type: %s", msgType)
	}
	
	return nil
}

// handleAgentJoin handles agent join messages.
func (sm *SwarmManager) handleAgentJoin(ctx context.Context, data map[string]interface{}) error {
	agentData, ok := data["agent"].(map[string]interface{})
	if !ok {
		return errors.New("invalid agent data")
	}
	
	agent := &SwarmAgent{
		ID:           agentData["id"].(string),
		Role:         SwarmRole(agentData["role"].(string)),
		Status:       agentData["status"].(string),
		LastSeen:     time.Now(),
		Capabilities: make([]string, 0),
		Position:     make(map[string]float64),
		Metadata:     make(map[string]interface{}),
	}
	
	// Extract capabilities
	if caps, ok := agentData["capabilities"].([]interface{}); ok {
		for _, cap := range caps {
			if capStr, ok := cap.(string); ok {
				agent.Capabilities = append(agent.Capabilities, capStr)
			}
		}
	}
	
	sm.mu.Lock()
	sm.agents[agent.ID] = agent
	sm.mu.Unlock()
	
	sm.logger.Info("Agent %s joined swarm %s", agent.ID, sm.swarmID)
	
	// Notify handlers
	for _, handler := range sm.agentHandlers {
		if err := handler(ctx, agent); err != nil {
			sm.logger.Error("Error in agent join handler: %v", err)
		}
	}
	
	return nil
}

// handleAgentLeave handles agent leave messages.
func (sm *SwarmManager) handleAgentLeave(ctx context.Context, data map[string]interface{}) error {
	agentID, ok := data["agent_id"].(string)
	if !ok {
		return errors.New("missing agent_id")
	}
	
	sm.mu.Lock()
	delete(sm.agents, agentID)
	sm.mu.Unlock()
	
	sm.logger.Info("Agent %s left swarm %s", agentID, sm.swarmID)
	return nil
}

// handleTaskAssigned handles task assignment messages.
func (sm *SwarmManager) handleTaskAssigned(ctx context.Context, data map[string]interface{}) error {
	taskData, ok := data["task"].(map[string]interface{})
	if !ok {
		return errors.New("invalid task data")
	}
	
	task := &SwarmTask{
		ID:       taskData["id"].(string),
		Type:     taskData["type"].(string),
		Priority: int(taskData["priority"].(float64)),
		Status:   taskData["status"].(string),
	}
	
	// Check if this agent is assigned to the task
	if assignedTo, ok := taskData["assigned_to"].([]interface{}); ok {
		for _, agentID := range assignedTo {
			if agentID.(string) == sm.agentID {
				sm.mu.Lock()
				sm.tasks[task.ID] = task
				sm.mu.Unlock()
				
				// Notify handlers
				for _, handler := range sm.taskHandlers {
					if err := handler(ctx, task); err != nil {
						sm.logger.Error("Error in task handler: %v", err)
					}
				}
				break
			}
		}
	}
	
	return nil
}

// handleTaskUpdated handles task update messages.
func (sm *SwarmManager) handleTaskUpdated(ctx context.Context, data map[string]interface{}) error {
	taskData, ok := data["task"].(map[string]interface{})
	if !ok {
		return errors.New("invalid task data")
	}
	
	taskID := taskData["id"].(string)
	
	sm.mu.Lock()
	if task, exists := sm.tasks[taskID]; exists {
		task.Status = taskData["status"].(string)
		task.UpdatedAt = time.Now()
	}
	sm.mu.Unlock()
	
	return nil
}

// handleFormationSet handles formation set messages.
func (sm *SwarmManager) handleFormationSet(ctx context.Context, data map[string]interface{}) error {
	formationData, ok := data["formation"].(map[string]interface{})
	if !ok {
		return errors.New("invalid formation data")
	}
	
	formation := &SwarmFormation{
		Name: formationData["name"].(string),
		Type: formationData["type"].(string),
	}
	
	sm.mu.Lock()
	sm.formations[formation.Name] = formation
	sm.mu.Unlock()
	
	// Notify handlers
	for _, handler := range sm.formationHandlers {
		if err := handler(context.Background(), formation); err != nil {
			sm.logger.Error("Error in formation handler: %v", err)
		}
	}
	
	return nil
}

// handleHeartbeat handles heartbeat messages from other agents.
func (sm *SwarmManager) handleHeartbeat(ctx context.Context, data map[string]interface{}) error {
	agentID, ok := data["agent_id"].(string)
	if !ok {
		return errors.New("missing agent_id in heartbeat")
	}
	
	sm.mu.Lock()
	if agent, exists := sm.agents[agentID]; exists {
		agent.LastSeen = time.Now()
		if status, ok := data["status"].(string); ok {
			agent.Status = status
		}
	}
	sm.mu.Unlock()
	
	return nil
}

// heartbeat sends periodic heartbeat messages.
func (sm *SwarmManager) heartbeat(ctx context.Context) {
	ticker := time.NewTicker(sm.heartbeatInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			message := map[string]interface{}{
				"type":     "heartbeat",
				"agent_id": sm.agentID,
				"status":   "active",
				"sender":   sm.agentID,
			}
			
			if err := sm.broadcastSwarmMessage(message); err != nil {
				sm.logger.Error("Failed to send heartbeat: %v", err)
			}
		}
	}
}

// processMessages processes incoming messages.
func (sm *SwarmManager) processMessages(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case task := <-sm.taskChan:
			sm.logger.Debug("Processing task: %s", task.ID)
		case agent := <-sm.agentChan:
			sm.logger.Debug("Processing agent: %s", agent.ID)
		case formation := <-sm.formationChan:
			sm.logger.Debug("Processing formation: %s", formation.Name)
		}
	}
}

// monitorAgents monitors agent health and removes inactive agents.
func (sm *SwarmManager) monitorAgents(ctx context.Context) {
	ticker := time.NewTicker(sm.agentTimeout / 2)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for agentID, agent := range sm.agents {
				if agentID != sm.agentID && now.Sub(agent.LastSeen) > sm.agentTimeout {
					delete(sm.agents, agentID)
					sm.logger.Info("Removed inactive agent: %s", agentID)
				}
			}
			sm.mu.Unlock()
		}
	}
}

// manageTasks manages task lifecycle and timeouts.
func (sm *SwarmManager) manageTasks(ctx context.Context) {
	ticker := time.NewTicker(sm.taskTimeout / 4)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-sm.stopChan:
			return
		case <-ticker.C:
			sm.mu.Lock()
			now := time.Now()
			for taskID, task := range sm.tasks {
				if !task.Deadline.IsZero() && now.After(task.Deadline) && task.Status != "completed" {
					task.Status = "failed"
					task.UpdatedAt = now
					sm.logger.Info("Task %s timed out", taskID)
				}
			}
			sm.mu.Unlock()
		}
	}
}