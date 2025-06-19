// Package coordination provides intelligent task distribution capabilities for ECPS.
package coordination

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ecps/ecps-go/pkg/core"
)

// TaskPriority represents the priority level of a task.
type TaskPriority int

const (
	LowPriority TaskPriority = iota
	MediumPriority
	HighPriority
	CriticalPriority
)

func (p TaskPriority) String() string {
	switch p {
	case LowPriority:
		return "low"
	case MediumPriority:
		return "medium"
	case HighPriority:
		return "high"
	case CriticalPriority:
		return "critical"
	default:
		return "unknown"
	}
}

// TaskDistributionRequest represents a request to distribute a task.
type TaskDistributionRequest struct {
	ID                string                 `json:"id"`
	TaskType          string                 `json:"task_type"`
	Priority          TaskPriority           `json:"priority"`
	RequiredCapabilities []string            `json:"required_capabilities"`
	PreferredAgents   []string               `json:"preferred_agents,omitempty"`
	ExcludedAgents    []string               `json:"excluded_agents,omitempty"`
	Data              map[string]interface{} `json:"data"`
	Constraints       map[string]interface{} `json:"constraints,omitempty"`
	Deadline          time.Time              `json:"deadline,omitempty"`
	MaxRetries        int                    `json:"max_retries"`
	CreatedAt         time.Time              `json:"created_at"`
}

// TaskAssignment represents an assignment of a task to an agent.
type TaskAssignment struct {
	ID           string                 `json:"id"`
	RequestID    string                 `json:"request_id"`
	AgentID      string                 `json:"agent_id"`
	TaskType     string                 `json:"task_type"`
	Priority     TaskPriority           `json:"priority"`
	Data         map[string]interface{} `json:"data"`
	Status       string                 `json:"status"` // "assigned", "accepted", "running", "completed", "failed", "cancelled"
	AssignedAt   time.Time              `json:"assigned_at"`
	StartedAt    time.Time              `json:"started_at,omitempty"`
	CompletedAt  time.Time              `json:"completed_at,omitempty"`
	Result       map[string]interface{} `json:"result,omitempty"`
	Error        string                 `json:"error,omitempty"`
	RetryCount   int                    `json:"retry_count"`
}

// AgentWorkload represents the current workload of an agent.
type AgentWorkload struct {
	AgentID           string    `json:"agent_id"`
	ActiveTasks       int       `json:"active_tasks"`
	QueuedTasks       int       `json:"queued_tasks"`
	TotalCapacity     int       `json:"total_capacity"`
	AvailableCapacity int       `json:"available_capacity"`
	LoadPercentage    float64   `json:"load_percentage"`
	LastUpdated       time.Time `json:"last_updated"`
}

// TaskDistributor manages intelligent distribution of tasks across agents.
type TaskDistributor struct {
	distributorID string
	transport     core.Transport
	logger        core.Logger
	coordinator   *A2ACoordinator
	
	// State management
	mu                sync.RWMutex
	pendingRequests   map[string]*TaskDistributionRequest
	activeAssignments map[string]*TaskAssignment
	agentWorkloads    map[string]*AgentWorkload
	agentCapabilities map[string][]string
	
	// Configuration
	maxTasksPerAgent     int
	loadBalanceThreshold float64
	reassignmentDelay    time.Duration
	workloadUpdateInterval time.Duration
	
	// Channels
	requestChan    chan *TaskDistributionRequest
	assignmentChan chan *TaskAssignment
	workloadChan   chan *AgentWorkload
	stopChan       chan struct{}
	
	// Handlers
	assignmentHandlers []func(context.Context, *TaskAssignment) error
	completionHandlers []func(context.Context, *TaskAssignment) error
}

// NewTaskDistributor creates a new task distributor.
func NewTaskDistributor(
	distributorID string,
	transport core.Transport,
	logger core.Logger,
	coordinator *A2ACoordinator,
) *TaskDistributor {
	return &TaskDistributor{
		distributorID:          distributorID,
		transport:              transport,
		logger:                 logger,
		coordinator:            coordinator,
		pendingRequests:        make(map[string]*TaskDistributionRequest),
		activeAssignments:      make(map[string]*TaskAssignment),
		agentWorkloads:         make(map[string]*AgentWorkload),
		agentCapabilities:      make(map[string][]string),
		maxTasksPerAgent:       10,
		loadBalanceThreshold:   0.8,
		reassignmentDelay:      30 * time.Second,
		workloadUpdateInterval: 5 * time.Second,
		requestChan:            make(chan *TaskDistributionRequest, 100),
		assignmentChan:         make(chan *TaskAssignment, 100),
		workloadChan:           make(chan *AgentWorkload, 100),
		stopChan:               make(chan struct{}),
	}
}

// Start starts the task distributor.
func (td *TaskDistributor) Start(ctx context.Context) error {
	// Subscribe to task distribution messages
	distributionTopic := fmt.Sprintf("task_distribution/%s/messages", td.distributorID)
	if err := td.transport.Subscribe(ctx, distributionTopic, &map[string]interface{}{}, td.handleDistributionMessage, nil); err != nil {
		return fmt.Errorf("failed to subscribe to distribution messages: %w", err)
	}
	
	// Subscribe to agent workload updates
	workloadTopic := "task_distribution/workload_updates"
	if err := td.transport.Subscribe(ctx, workloadTopic, &AgentWorkload{}, td.handleWorkloadUpdate, nil); err != nil {
		return fmt.Errorf("failed to subscribe to workload updates: %w", err)
	}
	
	// Start background goroutines
	go td.processRequests(ctx)
	go td.processAssignments(ctx)
	go td.monitorWorkloads(ctx)
	go td.rebalanceTasks(ctx)
	
	td.logger.Info("Task distributor %s started", td.distributorID)
	return nil
}

// Stop stops the task distributor.
func (td *TaskDistributor) Stop() error {
	close(td.stopChan)
	td.logger.Info("Task distributor %s stopped", td.distributorID)
	return nil
}

// DistributeTask distributes a task to the most suitable agent.
func (td *TaskDistributor) DistributeTask(request *TaskDistributionRequest) (*TaskAssignment, error) {
	if request.ID == "" {
		request.ID = uuid.New().String()
	}
	request.CreatedAt = time.Now()
	
	td.mu.Lock()
	td.pendingRequests[request.ID] = request
	td.mu.Unlock()
	
	// Find the best agent for this task
	agentID, score := td.findBestAgent(request)
	if agentID == "" {
		return nil, errors.New("no suitable agent found for task")
	}
	
	// Create task assignment
	assignment := &TaskAssignment{
		ID:         uuid.New().String(),
		RequestID:  request.ID,
		AgentID:    agentID,
		TaskType:   request.TaskType,
		Priority:   request.Priority,
		Data:       request.Data,
		Status:     "assigned",
		AssignedAt: time.Now(),
		RetryCount: 0,
	}
	
	td.mu.Lock()
	td.activeAssignments[assignment.ID] = assignment
	delete(td.pendingRequests, request.ID)
	
	// Update agent workload
	if workload, exists := td.agentWorkloads[agentID]; exists {
		workload.ActiveTasks++
		workload.AvailableCapacity--
		workload.LoadPercentage = float64(workload.ActiveTasks) / float64(workload.TotalCapacity)
		workload.LastUpdated = time.Now()
	}
	td.mu.Unlock()
	
	// Send assignment to agent
	if err := td.sendAssignmentToAgent(assignment); err != nil {
		td.logger.Error("Failed to send assignment to agent %s: %v", agentID, err)
		return nil, err
	}
	
	td.logger.Info("Assigned task %s to agent %s (score: %.2f)", assignment.ID, agentID, score)
	
	// Notify handlers
	for _, handler := range td.assignmentHandlers {
		if err := handler(context.Background(), assignment); err != nil {
			td.logger.Error("Error in assignment handler: %v", err)
		}
	}
	
	return assignment, nil
}

// UpdateAssignmentStatus updates the status of a task assignment.
func (td *TaskDistributor) UpdateAssignmentStatus(
	assignmentID string,
	status string,
	result map[string]interface{},
	errorMsg string,
) error {
	td.mu.Lock()
	assignment, exists := td.activeAssignments[assignmentID]
	if !exists {
		td.mu.Unlock()
		return errors.New("assignment not found")
	}
	
	oldStatus := assignment.Status
	assignment.Status = status
	
	switch status {
	case "accepted":
		// No additional action needed
	case "running":
		assignment.StartedAt = time.Now()
	case "completed":
		assignment.CompletedAt = time.Now()
		assignment.Result = result
		td.updateAgentWorkloadOnCompletion(assignment.AgentID)
	case "failed":
		assignment.Error = errorMsg
		assignment.CompletedAt = time.Now()
		td.updateAgentWorkloadOnCompletion(assignment.AgentID)
	case "cancelled":
		assignment.CompletedAt = time.Now()
		td.updateAgentWorkloadOnCompletion(assignment.AgentID)
	}
	td.mu.Unlock()
	
	td.logger.Info("Assignment %s status changed from %s to %s", assignmentID, oldStatus, status)
	
	// Handle completion
	if status == "completed" || status == "failed" || status == "cancelled" {
		for _, handler := range td.completionHandlers {
			if err := handler(context.Background(), assignment); err != nil {
				td.logger.Error("Error in completion handler: %v", err)
			}
		}
		
		// Handle retries for failed tasks
		if status == "failed" && assignment.RetryCount < td.getMaxRetries(assignment.RequestID) {
			go td.retryAssignment(assignment)
		}
	}
	
	return nil
}

// GetAssignmentStatus returns the status of a task assignment.
func (td *TaskDistributor) GetAssignmentStatus(assignmentID string) (*TaskAssignment, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	assignment, exists := td.activeAssignments[assignmentID]
	if !exists {
		return nil, errors.New("assignment not found")
	}
	
	// Return a copy
	result := *assignment
	result.Data = make(map[string]interface{})
	for k, v := range assignment.Data {
		result.Data[k] = v
	}
	
	if assignment.Result != nil {
		result.Result = make(map[string]interface{})
		for k, v := range assignment.Result {
			result.Result[k] = v
		}
	}
	
	return &result, nil
}

// GetAgentWorkload returns the current workload of an agent.
func (td *TaskDistributor) GetAgentWorkload(agentID string) (*AgentWorkload, error) {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	workload, exists := td.agentWorkloads[agentID]
	if !exists {
		return nil, errors.New("agent workload not found")
	}
	
	// Return a copy
	result := *workload
	return &result, nil
}

// GetDistributionStats returns statistics about task distribution.
func (td *TaskDistributor) GetDistributionStats() map[string]interface{} {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	totalAssignments := len(td.activeAssignments)
	completedAssignments := 0
	failedAssignments := 0
	runningAssignments := 0
	
	for _, assignment := range td.activeAssignments {
		switch assignment.Status {
		case "completed":
			completedAssignments++
		case "failed":
			failedAssignments++
		case "running":
			runningAssignments++
		}
	}
	
	totalAgents := len(td.agentWorkloads)
	overloadedAgents := 0
	averageLoad := 0.0
	
	for _, workload := range td.agentWorkloads {
		averageLoad += workload.LoadPercentage
		if workload.LoadPercentage > td.loadBalanceThreshold {
			overloadedAgents++
		}
	}
	
	if totalAgents > 0 {
		averageLoad /= float64(totalAgents)
	}
	
	return map[string]interface{}{
		"total_assignments":     totalAssignments,
		"completed_assignments": completedAssignments,
		"failed_assignments":    failedAssignments,
		"running_assignments":   runningAssignments,
		"pending_requests":      len(td.pendingRequests),
		"total_agents":          totalAgents,
		"overloaded_agents":     overloadedAgents,
		"average_load":          averageLoad,
		"load_threshold":        td.loadBalanceThreshold,
	}
}

// OnTaskAssigned registers a handler for task assignments.
func (td *TaskDistributor) OnTaskAssigned(handler func(context.Context, *TaskAssignment) error) {
	td.assignmentHandlers = append(td.assignmentHandlers, handler)
}

// OnTaskCompleted registers a handler for task completions.
func (td *TaskDistributor) OnTaskCompleted(handler func(context.Context, *TaskAssignment) error) {
	td.completionHandlers = append(td.completionHandlers, handler)
}

// findBestAgent finds the best agent for a task using a scoring algorithm.
func (td *TaskDistributor) findBestAgent(request *TaskDistributionRequest) (string, float64) {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	type agentScore struct {
		agentID string
		score   float64
	}
	
	var candidates []agentScore
	
	// Evaluate each agent
	for agentID, capabilities := range td.agentCapabilities {
		// Skip excluded agents
		if td.isAgentExcluded(agentID, request.ExcludedAgents) {
			continue
		}
		
		// Check if agent has required capabilities
		if !td.hasRequiredCapabilities(capabilities, request.RequiredCapabilities) {
			continue
		}
		
		// Get agent workload
		workload, exists := td.agentWorkloads[agentID]
		if !exists || workload.AvailableCapacity <= 0 {
			continue
		}
		
		// Calculate assignment score
		score := td.calculateAssignmentScore(agentID, request, workload)
		candidates = append(candidates, agentScore{agentID: agentID, score: score})
	}
	
	if len(candidates) == 0 {
		return "", 0
	}
	
	// Sort by score (highest first)
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})
	
	return candidates[0].agentID, candidates[0].score
}

// calculateAssignmentScore calculates a score for assigning a task to an agent.
func (td *TaskDistributor) calculateAssignmentScore(
	agentID string,
	request *TaskDistributionRequest,
	workload *AgentWorkload,
) float64 {
	score := 0.0
	
	// Base score for availability
	availabilityScore := float64(workload.AvailableCapacity) / float64(workload.TotalCapacity)
	score += availabilityScore * 40.0
	
	// Load balancing score (prefer less loaded agents)
	loadScore := 1.0 - workload.LoadPercentage
	score += loadScore * 30.0
	
	// Priority bonus
	priorityBonus := float64(request.Priority) * 10.0
	score += priorityBonus
	
	// Preferred agent bonus
	if td.isPreferredAgent(agentID, request.PreferredAgents) {
		score += 20.0
	}
	
	// Capability match bonus (more capabilities = higher score)
	capabilities := td.agentCapabilities[agentID]
	capabilityScore := float64(len(capabilities)) / 10.0
	score += capabilityScore
	
	return score
}

// hasRequiredCapabilities checks if an agent has all required capabilities.
func (td *TaskDistributor) hasRequiredCapabilities(agentCapabilities, requiredCapabilities []string) bool {
	for _, required := range requiredCapabilities {
		found := false
		for _, capability := range agentCapabilities {
			if capability == required {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// isAgentExcluded checks if an agent is in the excluded list.
func (td *TaskDistributor) isAgentExcluded(agentID string, excludedAgents []string) bool {
	for _, excluded := range excludedAgents {
		if excluded == agentID {
			return true
		}
	}
	return false
}

// isPreferredAgent checks if an agent is in the preferred list.
func (td *TaskDistributor) isPreferredAgent(agentID string, preferredAgents []string) bool {
	for _, preferred := range preferredAgents {
		if preferred == agentID {
			return true
		}
	}
	return false
}

// sendAssignmentToAgent sends a task assignment to an agent.
func (td *TaskDistributor) sendAssignmentToAgent(assignment *TaskAssignment) error {
	topic := fmt.Sprintf("task_distribution/assignments/%s", assignment.AgentID)
	return td.transport.Publish(context.Background(), topic, assignment, nil)
}

// updateAgentWorkloadOnCompletion updates agent workload when a task completes.
func (td *TaskDistributor) updateAgentWorkloadOnCompletion(agentID string) {
	if workload, exists := td.agentWorkloads[agentID]; exists {
		workload.ActiveTasks = int(math.Max(0, float64(workload.ActiveTasks-1)))
		workload.AvailableCapacity = workload.TotalCapacity - workload.ActiveTasks
		workload.LoadPercentage = float64(workload.ActiveTasks) / float64(workload.TotalCapacity)
		workload.LastUpdated = time.Now()
	}
}

// getMaxRetries gets the maximum retry count for a request.
func (td *TaskDistributor) getMaxRetries(requestID string) int {
	if request, exists := td.pendingRequests[requestID]; exists {
		return request.MaxRetries
	}
	return 3 // Default
}

// retryAssignment retries a failed assignment.
func (td *TaskDistributor) retryAssignment(assignment *TaskAssignment) {
	time.Sleep(td.reassignmentDelay)
	
	td.mu.Lock()
	request, exists := td.pendingRequests[assignment.RequestID]
	if !exists {
		td.mu.Unlock()
		return
	}
	
	assignment.RetryCount++
	assignment.Status = "assigned"
	assignment.AssignedAt = time.Now()
	assignment.Error = ""
	td.mu.Unlock()
	
	// Find a new agent (excluding the previous one)
	request.ExcludedAgents = append(request.ExcludedAgents, assignment.AgentID)
	agentID, _ := td.findBestAgent(request)
	if agentID == "" {
		td.logger.Error("No agent available for retry of assignment %s", assignment.ID)
		return
	}
	
	assignment.AgentID = agentID
	
	if err := td.sendAssignmentToAgent(assignment); err != nil {
		td.logger.Error("Failed to retry assignment %s: %v", assignment.ID, err)
	} else {
		td.logger.Info("Retried assignment %s with agent %s (attempt %d)", assignment.ID, agentID, assignment.RetryCount)
	}
}

// handleDistributionMessage handles incoming distribution messages.
func (td *TaskDistributor) handleDistributionMessage(ctx context.Context, message interface{}) error {
	data, ok := message.(*map[string]interface{})
	if !ok {
		return errors.New("invalid distribution message type")
	}
	
	msgType, ok := (*data)["type"].(string)
	if !ok {
		return errors.New("missing message type")
	}
	
	switch msgType {
	case "assignment_status":
		return td.handleAssignmentStatusUpdate(ctx, *data)
	case "agent_capabilities":
		return td.handleAgentCapabilitiesUpdate(ctx, *data)
	default:
		td.logger.Debug("Unknown distribution message type: %s", msgType)
	}
	
	return nil
}

// handleAssignmentStatusUpdate handles assignment status updates.
func (td *TaskDistributor) handleAssignmentStatusUpdate(ctx context.Context, data map[string]interface{}) error {
	assignmentID, ok := data["assignment_id"].(string)
	if !ok {
		return errors.New("missing assignment_id")
	}
	
	status, ok := data["status"].(string)
	if !ok {
		return errors.New("missing status")
	}
	
	var result map[string]interface{}
	if r, ok := data["result"].(map[string]interface{}); ok {
		result = r
	}
	
	errorMsg := ""
	if e, ok := data["error"].(string); ok {
		errorMsg = e
	}
	
	return td.UpdateAssignmentStatus(assignmentID, status, result, errorMsg)
}

// handleAgentCapabilitiesUpdate handles agent capabilities updates.
func (td *TaskDistributor) handleAgentCapabilitiesUpdate(ctx context.Context, data map[string]interface{}) error {
	agentID, ok := data["agent_id"].(string)
	if !ok {
		return errors.New("missing agent_id")
	}
	
	capabilitiesData, ok := data["capabilities"].([]interface{})
	if !ok {
		return errors.New("missing capabilities")
	}
	
	capabilities := make([]string, 0, len(capabilitiesData))
	for _, cap := range capabilitiesData {
		if capStr, ok := cap.(string); ok {
			capabilities = append(capabilities, capStr)
		}
	}
	
	td.mu.Lock()
	td.agentCapabilities[agentID] = capabilities
	td.mu.Unlock()
	
	td.logger.Debug("Updated capabilities for agent %s: %v", agentID, capabilities)
	return nil
}

// handleWorkloadUpdate handles agent workload updates.
func (td *TaskDistributor) handleWorkloadUpdate(ctx context.Context, workload interface{}) error {
	w, ok := workload.(*AgentWorkload)
	if !ok {
		return errors.New("invalid workload update type")
	}
	
	td.mu.Lock()
	td.agentWorkloads[w.AgentID] = w
	td.mu.Unlock()
	
	td.logger.Debug("Updated workload for agent %s: %.1f%% load", w.AgentID, w.LoadPercentage*100)
	return nil
}

// processRequests processes pending task distribution requests.
func (td *TaskDistributor) processRequests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-td.stopChan:
			return
		case request := <-td.requestChan:
			if _, err := td.DistributeTask(request); err != nil {
				td.logger.Error("Failed to distribute task %s: %v", request.ID, err)
			}
		}
	}
}

// processAssignments processes task assignments.
func (td *TaskDistributor) processAssignments(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-td.stopChan:
			return
		case assignment := <-td.assignmentChan:
			td.logger.Debug("Processing assignment: %s", assignment.ID)
		}
	}
}

// monitorWorkloads monitors agent workloads and updates them periodically.
func (td *TaskDistributor) monitorWorkloads(ctx context.Context) {
	ticker := time.NewTicker(td.workloadUpdateInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-td.stopChan:
			return
		case <-ticker.C:
			td.updateWorkloadMetrics()
		}
	}
}

// rebalanceTasks periodically rebalances tasks across agents.
func (td *TaskDistributor) rebalanceTasks(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-td.stopChan:
			return
		case <-ticker.C:
			td.performLoadBalancing()
		}
	}
}

// updateWorkloadMetrics updates workload metrics for all agents.
func (td *TaskDistributor) updateWorkloadMetrics() {
	td.mu.Lock()
	defer td.mu.Unlock()
	
	for agentID, workload := range td.agentWorkloads {
		// Count active assignments for this agent
		activeCount := 0
		for _, assignment := range td.activeAssignments {
			if assignment.AgentID == agentID && 
			   (assignment.Status == "assigned" || assignment.Status == "accepted" || assignment.Status == "running") {
				activeCount++
			}
		}
		
		workload.ActiveTasks = activeCount
		workload.AvailableCapacity = workload.TotalCapacity - activeCount
		workload.LoadPercentage = float64(activeCount) / float64(workload.TotalCapacity)
		workload.LastUpdated = time.Now()
	}
}

// performLoadBalancing performs load balancing across agents.
func (td *TaskDistributor) performLoadBalancing() {
	td.mu.RLock()
	defer td.mu.RUnlock()
	
	// Find overloaded and underloaded agents
	var overloaded, underloaded []string
	
	for agentID, workload := range td.agentWorkloads {
		if workload.LoadPercentage > td.loadBalanceThreshold {
			overloaded = append(overloaded, agentID)
		} else if workload.LoadPercentage < td.loadBalanceThreshold/2 {
			underloaded = append(underloaded, agentID)
		}
	}
	
	if len(overloaded) > 0 && len(underloaded) > 0 {
		td.logger.Info("Load balancing: %d overloaded agents, %d underloaded agents", 
			len(overloaded), len(underloaded))
		
		// In a real implementation, we would reassign tasks from overloaded to underloaded agents
		// This is a simplified version that just logs the imbalance
	}
}