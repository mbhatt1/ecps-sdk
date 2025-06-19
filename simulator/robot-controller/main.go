package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RobotController implements the Go-based robot controller for ECPS Golden Path
type RobotController struct {
	mu           sync.RWMutex
	position     Position3D
	joints       []float64
	gripper      GripperState
	status       RobotStatus
	actionQueue  []Action
	isExecuting  bool
	safetyLimits SafetyLimits
	metrics      *RobotMetrics
}

type Position3D struct {
	X, Y, Z    float64 `json:"x,y,z"`
	Roll, Pitch, Yaw float64 `json:"roll,pitch,yaw"`
}

type GripperState struct {
	IsOpen bool    `json:"is_open"`
	Force  float64 `json:"force"`
}

type RobotStatus struct {
	Connected    bool      `json:"connected"`
	Ready        bool      `json:"ready"`
	Error        string    `json:"error,omitempty"`
	LastUpdate   time.Time `json:"last_update"`
	BatteryLevel float64   `json:"battery_level"`
	Temperature  float64   `json:"temperature"`
}

type Action struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
	Timeout     time.Duration          `json:"timeout"`
	Status      string                 `json:"status"`
	CreatedAt   time.Time              `json:"created_at"`
	StartedAt   *time.Time             `json:"started_at,omitempty"`
	CompletedAt *time.Time             `json:"completed_at,omitempty"`
	Result      map[string]interface{} `json:"result,omitempty"`
	Error       string                 `json:"error,omitempty"`
}

type SafetyLimits struct {
	MaxVelocity     float64 `json:"max_velocity"`
	MaxAcceleration float64 `json:"max_acceleration"`
	MaxForce        float64 `json:"max_force"`
	WorkspaceMin    Position3D `json:"workspace_min"`
	WorkspaceMax    Position3D `json:"workspace_max"`
}

type RobotMetrics struct {
	ActionsExecuted   prometheus.Counter
	ActionLatency     prometheus.Histogram
	SafetyViolations  prometheus.Counter
	RobotUptime       prometheus.Gauge
	BatteryLevel      prometheus.Gauge
	Temperature       prometheus.Gauge
	JointPositions    prometheus.GaugeVec
}

func NewRobotController() *RobotController {
	metrics := &RobotMetrics{
		ActionsExecuted: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "robot_actions_executed_total",
			Help: "Total number of robot actions executed",
		}),
		ActionLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "robot_action_latency_seconds",
			Help:    "Robot action execution latency",
			Buckets: prometheus.DefBuckets,
		}),
		SafetyViolations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "robot_safety_violations_total",
			Help: "Total number of safety violations detected",
		}),
		RobotUptime: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "robot_uptime_seconds",
			Help: "Robot uptime in seconds",
		}),
		BatteryLevel: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "robot_battery_level_percent",
			Help: "Robot battery level percentage",
		}),
		Temperature: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "robot_temperature_celsius",
			Help: "Robot temperature in Celsius",
		}),
		JointPositions: *prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "robot_joint_positions_radians",
			Help: "Robot joint positions in radians",
		}, []string{"joint"}),
	}

	// Register metrics
	prometheus.MustRegister(
		metrics.ActionsExecuted,
		metrics.ActionLatency,
		metrics.SafetyViolations,
		metrics.RobotUptime,
		metrics.BatteryLevel,
		metrics.Temperature,
		metrics.JointPositions,
	)

	return &RobotController{
		position: Position3D{X: 0, Y: 0, Z: 0.5}, // Home position
		joints:   []float64{0, 0, 0, 0, 0, 0},     // 6-DOF arm
		gripper:  GripperState{IsOpen: true, Force: 0},
		status: RobotStatus{
			Connected:    true,
			Ready:        true,
			LastUpdate:   time.Now(),
			BatteryLevel: 95.0,
			Temperature:  35.0,
		},
		actionQueue: make([]Action, 0),
		safetyLimits: SafetyLimits{
			MaxVelocity:     1.0, // m/s
			MaxAcceleration: 2.0, // m/s²
			MaxForce:        50.0, // N
			WorkspaceMin:    Position3D{X: -0.8, Y: -0.8, Z: 0.0},
			WorkspaceMax:    Position3D{X: 0.8, Y: 0.8, Z: 1.5},
		},
		metrics: metrics,
	}
}

func (rc *RobotController) Start() error {
	log.Println("Starting ECPS Robot Controller...")

	// Start background processes
	go rc.actionExecutor()
	go rc.statusUpdater()
	go rc.safetyMonitor()

	// Setup HTTP server
	router := mux.NewRouter()
	
	// Health endpoints
	router.HandleFunc("/health", rc.healthHandler).Methods("GET")
	router.HandleFunc("/ready", rc.readyHandler).Methods("GET")
	router.HandleFunc("/status", rc.statusHandler).Methods("GET")
	
	// Action endpoints
	router.HandleFunc("/actions", rc.executeActionHandler).Methods("POST")
	router.HandleFunc("/actions/{id}", rc.getActionHandler).Methods("GET")
	router.HandleFunc("/actions/{id}", rc.cancelActionHandler).Methods("DELETE")
	router.HandleFunc("/actions", rc.listActionsHandler).Methods("GET")
	
	// Robot control endpoints
	router.HandleFunc("/position", rc.getPositionHandler).Methods("GET")
	router.HandleFunc("/position", rc.setPositionHandler).Methods("POST")
	router.HandleFunc("/joints", rc.getJointsHandler).Methods("GET")
	router.HandleFunc("/joints", rc.setJointsHandler).Methods("POST")
	router.HandleFunc("/gripper", rc.getGripperHandler).Methods("GET")
	router.HandleFunc("/gripper", rc.setGripperHandler).Methods("POST")
	
	// Safety endpoints
	router.HandleFunc("/safety/limits", rc.getSafetyLimitsHandler).Methods("GET")
	router.HandleFunc("/safety/stop", rc.emergencyStopHandler).Methods("POST")
	
	// Metrics endpoint
	router.Handle("/metrics", promhttp.Handler())

	log.Println("Robot Controller listening on :8081")
	return http.ListenAndServe(":8081", router)
}

func (rc *RobotController) executeActionHandler(w http.ResponseWriter, r *http.Request) {
	var action Action
	if err := json.NewDecoder(r.Body).Decode(&action); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate action
	if err := rc.validateAction(&action); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate ID and set timestamps
	action.ID = fmt.Sprintf("action_%d", time.Now().UnixNano())
	action.Status = "queued"
	action.CreatedAt = time.Now()

	// Add to queue
	rc.mu.Lock()
	rc.actionQueue = append(rc.actionQueue, action)
	rc.mu.Unlock()

	log.Printf("Action queued: %s (%s)", action.ID, action.Type)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(action)
}

func (rc *RobotController) validateAction(action *Action) error {
	// Validate action type
	validTypes := []string{"move_to", "grasp", "release", "set_pose", "navigate"}
	valid := false
	for _, t := range validTypes {
		if action.Type == t {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid action type: %s", action.Type)
	}

	// Validate parameters based on action type
	switch action.Type {
	case "move_to", "set_pose":
		if x, ok := action.Parameters["x"].(float64); ok {
			if y, ok := action.Parameters["y"].(float64); ok {
				if z, ok := action.Parameters["z"].(float64); ok {
					// Check workspace limits
					if x < rc.safetyLimits.WorkspaceMin.X || x > rc.safetyLimits.WorkspaceMax.X ||
					   y < rc.safetyLimits.WorkspaceMin.Y || y > rc.safetyLimits.WorkspaceMax.Y ||
					   z < rc.safetyLimits.WorkspaceMin.Z || z > rc.safetyLimits.WorkspaceMax.Z {
						return fmt.Errorf("position outside workspace limits")
					}
				} else {
					return fmt.Errorf("missing z parameter")
				}
			} else {
				return fmt.Errorf("missing y parameter")
			}
		} else {
			return fmt.Errorf("missing x parameter")
		}
	case "grasp":
		if force, ok := action.Parameters["force"].(float64); ok {
			if force > rc.safetyLimits.MaxForce {
				return fmt.Errorf("force exceeds safety limit")
			}
		}
	}

	return nil
}

func (rc *RobotController) actionExecutor() {
	for {
		rc.mu.Lock()
		if len(rc.actionQueue) > 0 && !rc.isExecuting {
			action := rc.actionQueue[0]
			rc.actionQueue = rc.actionQueue[1:]
			rc.isExecuting = true
			rc.mu.Unlock()

			// Execute action
			go rc.executeAction(&action)
		} else {
			rc.mu.Unlock()
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (rc *RobotController) executeAction(action *Action) {
	start := time.Now()
	defer func() {
		rc.metrics.ActionLatency.Observe(time.Since(start).Seconds())
		rc.metrics.ActionsExecuted.Inc()
		rc.mu.Lock()
		rc.isExecuting = false
		rc.mu.Unlock()
	}()

	log.Printf("Executing action: %s (%s)", action.ID, action.Type)

	// Update action status
	now := time.Now()
	action.Status = "executing"
	action.StartedAt = &now

	// Simulate action execution based on type
	switch action.Type {
	case "move_to", "set_pose":
		rc.executeMoveAction(action)
	case "grasp":
		rc.executeGraspAction(action)
	case "release":
		rc.executeReleaseAction(action)
	case "navigate":
		rc.executeNavigateAction(action)
	default:
		action.Status = "failed"
		action.Error = "Unknown action type"
		return
	}

	// Complete action
	completed := time.Now()
	action.Status = "completed"
	action.CompletedAt = &completed

	log.Printf("Action completed: %s", action.ID)
}

func (rc *RobotController) executeMoveAction(action *Action) {
	targetX := action.Parameters["x"].(float64)
	targetY := action.Parameters["y"].(float64)
	targetZ := action.Parameters["z"].(float64)

	// Calculate movement trajectory
	startPos := rc.position
	distance := math.Sqrt(
		math.Pow(targetX-startPos.X, 2) +
		math.Pow(targetY-startPos.Y, 2) +
		math.Pow(targetZ-startPos.Z, 2),
	)

	// Simulate movement with realistic timing
	movementTime := distance / 0.5 // 0.5 m/s average speed
	steps := int(movementTime * 10) // 10 Hz update rate

	for i := 0; i <= steps; i++ {
		progress := float64(i) / float64(steps)
		
		rc.mu.Lock()
		rc.position.X = startPos.X + (targetX-startPos.X)*progress
		rc.position.Y = startPos.Y + (targetY-startPos.Y)*progress
		rc.position.Z = startPos.Z + (targetZ-startPos.Z)*progress
		rc.mu.Unlock()

		time.Sleep(100 * time.Millisecond)
	}

	action.Result = map[string]interface{}{
		"final_position": rc.position,
		"movement_time":  movementTime,
	}
}

func (rc *RobotController) executeGraspAction(action *Action) {
	force := 10.0 // Default force
	if f, ok := action.Parameters["force"].(float64); ok {
		force = f
	}

	// Simulate grasping
	time.Sleep(500 * time.Millisecond) // Approach time
	
	rc.mu.Lock()
	rc.gripper.IsOpen = false
	rc.gripper.Force = force
	rc.mu.Unlock()

	time.Sleep(200 * time.Millisecond) // Grasp time

	action.Result = map[string]interface{}{
		"grasped":    true,
		"force_used": force,
	}
}

func (rc *RobotController) executeReleaseAction(action *Action) {
	time.Sleep(200 * time.Millisecond) // Release time
	
	rc.mu.Lock()
	rc.gripper.IsOpen = true
	rc.gripper.Force = 0
	rc.mu.Unlock()

	action.Result = map[string]interface{}{
		"released": true,
	}
}

func (rc *RobotController) executeNavigateAction(action *Action) {
	// Simulate navigation (for mobile robots)
	targetX := action.Parameters["x"].(float64)
	targetY := action.Parameters["y"].(float64)

	// Simple navigation simulation
	time.Sleep(2 * time.Second)

	rc.mu.Lock()
	rc.position.X = targetX
	rc.position.Y = targetY
	rc.mu.Unlock()

	action.Result = map[string]interface{}{
		"navigated_to": map[string]float64{"x": targetX, "y": targetY},
	}
}

func (rc *RobotController) statusUpdater() {
	startTime := time.Now()
	for {
		rc.mu.Lock()
		rc.status.LastUpdate = time.Now()
		
		// Simulate battery drain
		rc.status.BatteryLevel -= 0.01
		if rc.status.BatteryLevel < 0 {
			rc.status.BatteryLevel = 0
		}

		// Simulate temperature variation
		rc.status.Temperature = 35.0 + 5.0*math.Sin(float64(time.Now().Unix())/100.0)

		// Update metrics
		rc.metrics.RobotUptime.Set(time.Since(startTime).Seconds())
		rc.metrics.BatteryLevel.Set(rc.status.BatteryLevel)
		rc.metrics.Temperature.Set(rc.status.Temperature)

		// Update joint positions
		for i, pos := range rc.joints {
			rc.metrics.JointPositions.WithLabelValues(fmt.Sprintf("joint_%d", i)).Set(pos)
		}

		rc.mu.Unlock()
		time.Sleep(1 * time.Second)
	}
}

func (rc *RobotController) safetyMonitor() {
	for {
		rc.mu.RLock()
		
		// Check workspace limits
		if rc.position.X < rc.safetyLimits.WorkspaceMin.X || rc.position.X > rc.safetyLimits.WorkspaceMax.X ||
		   rc.position.Y < rc.safetyLimits.WorkspaceMin.Y || rc.position.Y > rc.safetyLimits.WorkspaceMax.Y ||
		   rc.position.Z < rc.safetyLimits.WorkspaceMin.Z || rc.position.Z > rc.safetyLimits.WorkspaceMax.Z {
			log.Println("WARNING: Robot position outside workspace limits")
			rc.metrics.SafetyViolations.Inc()
		}

		// Check temperature
		if rc.status.Temperature > 60.0 {
			log.Println("WARNING: Robot temperature too high")
			rc.metrics.SafetyViolations.Inc()
		}

		// Check battery level
		if rc.status.BatteryLevel < 10.0 {
			log.Println("WARNING: Low battery level")
		}

		rc.mu.RUnlock()
		time.Sleep(1 * time.Second)
	}
}

// HTTP Handlers
func (rc *RobotController) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (rc *RobotController) readyHandler(w http.ResponseWriter, r *http.Request) {
	rc.mu.RLock()
	ready := rc.status.Ready && rc.status.Connected
	rc.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	if ready {
		json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
	}
}

func (rc *RobotController) statusHandler(w http.ResponseWriter, r *http.Request) {
	rc.mu.RLock()
	status := rc.status
	position := rc.position
	gripper := rc.gripper
	rc.mu.RUnlock()

	response := map[string]interface{}{
		"status":   status,
		"position": position,
		"gripper":  gripper,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (rc *RobotController) getPositionHandler(w http.ResponseWriter, r *http.Request) {
	rc.mu.RLock()
	position := rc.position
	rc.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(position)
}

func (rc *RobotController) setPositionHandler(w http.ResponseWriter, r *http.Request) {
	var pos Position3D
	if err := json.NewDecoder(r.Body).Decode(&pos); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Create move action
	action := Action{
		Type: "move_to",
		Parameters: map[string]interface{}{
			"x": pos.X,
			"y": pos.Y,
			"z": pos.Z,
		},
	}

	if err := rc.validateAction(&action); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Execute immediately for direct position commands
	rc.executeMoveAction(&action)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "position set"})
}

func (rc *RobotController) getGripperHandler(w http.ResponseWriter, r *http.Request) {
	rc.mu.RLock()
	gripper := rc.gripper
	rc.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(gripper)
}

func (rc *RobotController) setGripperHandler(w http.ResponseWriter, r *http.Request) {
	var gripper GripperState
	if err := json.NewDecoder(r.Body).Decode(&gripper); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	rc.mu.Lock()
	rc.gripper = gripper
	rc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "gripper set"})
}

func (rc *RobotController) getJointsHandler(w http.ResponseWriter, r *http.Request) {
	rc.mu.RLock()
	joints := rc.joints
	rc.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]float64{"joints": joints})
}

func (rc *RobotController) setJointsHandler(w http.ResponseWriter, r *http.Request) {
	var request map[string][]float64
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	joints, ok := request["joints"]
	if !ok || len(joints) != 6 {
		http.Error(w, "Invalid joints array", http.StatusBadRequest)
		return
	}

	rc.mu.Lock()
	rc.joints = joints
	rc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "joints set"})
}

func (rc *RobotController) getSafetyLimitsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rc.safetyLimits)
}

func (rc *RobotController) emergencyStopHandler(w http.ResponseWriter, r *http.Request) {
	log.Println("EMERGENCY STOP ACTIVATED")
	
	rc.mu.Lock()
	rc.status.Ready = false
	rc.actionQueue = make([]Action, 0) // Clear action queue
	rc.isExecuting = false
	rc.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "emergency stop activated"})
}

func (rc *RobotController) getActionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	actionID := vars["id"]

	// In a real implementation, you'd store actions in a database
	// For demo purposes, return a mock action
	action := Action{
		ID:     actionID,
		Status: "completed",
		Type:   "move_to",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(action)
}

func (rc *RobotController) cancelActionHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	actionID := vars["id"]

	log.Printf("Cancelling action: %s", actionID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "cancelled"})
}

func (rc *RobotController) listActionsHandler(w http.ResponseWriter, r *http.Request) {
	rc.mu.RLock()
	actions := rc.actionQueue
	rc.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"actions": actions})
}

func main() {
	controller := NewRobotController()
	
	log.Println("ECPS Robot Controller - Agentic AI Robotics")
	log.Println("===========================================")
	
	if err := controller.Start(); err != nil {
		log.Fatalf("Failed to start robot controller: %v", err)
	}
}