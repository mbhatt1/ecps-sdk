// Package coordination provides consensus capabilities for ECPS using Raft algorithm.
package coordination

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/ecps/ecps-go/pkg/core"
)

// NodeState represents the state of a Raft node.
type NodeState int

const (
	Follower NodeState = iota
	Candidate
	Leader
)

func (s NodeState) String() string {
	switch s {
	case Follower:
		return "Follower"
	case Candidate:
		return "Candidate"
	case Leader:
		return "Leader"
	default:
		return "Unknown"
	}
}

// LogEntry represents an entry in the Raft log.
type LogEntry struct {
	Index     int64                  `json:"index"`
	Term      int64                  `json:"term"`
	Command   string                 `json:"command"`
	Data      map[string]interface{} `json:"data"`
	Timestamp time.Time              `json:"timestamp"`
}

// VoteRequest represents a request for votes during leader election.
type VoteRequest struct {
	Term         int64  `json:"term"`
	CandidateID  string `json:"candidate_id"`
	LastLogIndex int64  `json:"last_log_index"`
	LastLogTerm  int64  `json:"last_log_term"`
}

// VoteResponse represents a response to a vote request.
type VoteResponse struct {
	Term        int64  `json:"term"`
	VoteGranted bool   `json:"vote_granted"`
	VoterID     string `json:"voter_id"`
}

// AppendEntriesRequest represents a request to append entries to the log.
type AppendEntriesRequest struct {
	Term         int64       `json:"term"`
	LeaderID     string      `json:"leader_id"`
	PrevLogIndex int64       `json:"prev_log_index"`
	PrevLogTerm  int64       `json:"prev_log_term"`
	Entries      []*LogEntry `json:"entries"`
	LeaderCommit int64       `json:"leader_commit"`
}

// AppendEntriesResponse represents a response to an append entries request.
type AppendEntriesResponse struct {
	Term    int64  `json:"term"`
	Success bool   `json:"success"`
	NodeID  string `json:"node_id"`
}

// RaftNode represents a node in the Raft consensus cluster.
type RaftNode struct {
	// Node identification
	nodeID    string
	clusterID string
	peers     []string
	
	// Transport and logging
	transport core.Transport
	logger    core.Logger
	
	// Raft state
	mu           sync.RWMutex
	state        NodeState
	currentTerm  int64
	votedFor     string
	log          []*LogEntry
	commitIndex  int64
	lastApplied  int64
	
	// Leader state (reinitialized after election)
	nextIndex  map[string]int64
	matchIndex map[string]int64
	
	// Election state
	electionTimeout  time.Duration
	heartbeatTimeout time.Duration
	lastHeartbeat    time.Time
	votesReceived    map[string]bool
	
	// Channels
	appendEntriesChan chan *AppendEntriesRequest
	voteRequestChan   chan *VoteRequest
	stopChan          chan struct{}
	
	// State machine
	stateMachine map[string]interface{}
	applyChan    chan *LogEntry
}

// NewRaftNode creates a new Raft consensus node.
func NewRaftNode(
	nodeID string,
	clusterID string,
	peers []string,
	transport core.Transport,
	logger core.Logger,
) *RaftNode {
	return &RaftNode{
		nodeID:           nodeID,
		clusterID:        clusterID,
		peers:            peers,
		transport:        transport,
		logger:           logger,
		state:            Follower,
		currentTerm:      0,
		votedFor:         "",
		log:              make([]*LogEntry, 0),
		commitIndex:      0,
		lastApplied:      0,
		nextIndex:        make(map[string]int64),
		matchIndex:       make(map[string]int64),
		electionTimeout:  time.Duration(150+rand.Intn(150)) * time.Millisecond,
		heartbeatTimeout: 50 * time.Millisecond,
		lastHeartbeat:    time.Now(),
		votesReceived:    make(map[string]bool),
		appendEntriesChan: make(chan *AppendEntriesRequest, 100),
		voteRequestChan:   make(chan *VoteRequest, 100),
		stopChan:          make(chan struct{}),
		stateMachine:      make(map[string]interface{}),
		applyChan:         make(chan *LogEntry, 100),
	}
}

// Start starts the Raft node.
func (r *RaftNode) Start(ctx context.Context) error {
	// Subscribe to vote requests
	voteRequestTopic := fmt.Sprintf("raft/%s/vote_request/%s", r.clusterID, r.nodeID)
	if err := r.transport.Subscribe(ctx, voteRequestTopic, &VoteRequest{}, r.handleVoteRequest, nil); err != nil {
		return fmt.Errorf("failed to subscribe to vote requests: %w", err)
	}
	
	// Subscribe to append entries requests
	appendEntriesTopic := fmt.Sprintf("raft/%s/append_entries/%s", r.clusterID, r.nodeID)
	if err := r.transport.Subscribe(ctx, appendEntriesTopic, &AppendEntriesRequest{}, r.handleAppendEntries, nil); err != nil {
		return fmt.Errorf("failed to subscribe to append entries: %w", err)
	}
	
	// Start background goroutines
	go r.electionTimer(ctx)
	go r.heartbeatTimer(ctx)
	go r.applyStateMachine(ctx)
	
	r.logger.Info("Raft node %s started in cluster %s", r.nodeID, r.clusterID)
	return nil
}

// Stop stops the Raft node.
func (r *RaftNode) Stop() error {
	close(r.stopChan)
	r.logger.Info("Raft node %s stopped", r.nodeID)
	return nil
}

// ProposeCommand proposes a new command to be added to the log.
func (r *RaftNode) ProposeCommand(command string, data map[string]interface{}) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if r.state != Leader {
		return errors.New("only leader can propose commands")
	}
	
	entry := &LogEntry{
		Index:     int64(len(r.log)) + 1,
		Term:      r.currentTerm,
		Command:   command,
		Data:      data,
		Timestamp: time.Now(),
	}
	
	r.log = append(r.log, entry)
	r.logger.Info("Proposed command %s at index %d", command, entry.Index)
	
	// Replicate to followers
	go r.replicateToFollowers()
	
	return nil
}

// GetState returns the current state of the node.
func (r *RaftNode) GetState() (NodeState, int64, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	return r.state, r.currentTerm, r.state == Leader
}

// GetStateMachine returns a copy of the current state machine.
func (r *RaftNode) GetStateMachine() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	result := make(map[string]interface{})
	for k, v := range r.stateMachine {
		result[k] = v
	}
	
	return result
}

// electionTimer handles election timeouts.
func (r *RaftNode) electionTimer(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopChan:
			return
		default:
			r.mu.RLock()
			state := r.state
			lastHeartbeat := r.lastHeartbeat
			electionTimeout := r.electionTimeout
			r.mu.RUnlock()
			
			if state != Leader && time.Since(lastHeartbeat) > electionTimeout {
				r.startElection()
			}
			
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// heartbeatTimer sends periodic heartbeats when leader.
func (r *RaftNode) heartbeatTimer(ctx context.Context) {
	ticker := time.NewTicker(r.heartbeatTimeout)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopChan:
			return
		case <-ticker.C:
			r.mu.RLock()
			if r.state == Leader {
				r.mu.RUnlock()
				r.sendHeartbeats()
			} else {
				r.mu.RUnlock()
			}
		}
	}
}

// startElection starts a new election.
func (r *RaftNode) startElection() {
	r.mu.Lock()
	r.state = Candidate
	r.currentTerm++
	r.votedFor = r.nodeID
	r.lastHeartbeat = time.Now()
	r.votesReceived = make(map[string]bool)
	r.votesReceived[r.nodeID] = true // Vote for self
	
	currentTerm := r.currentTerm
	lastLogIndex := int64(len(r.log))
	var lastLogTerm int64
	if lastLogIndex > 0 {
		lastLogTerm = r.log[lastLogIndex-1].Term
	}
	r.mu.Unlock()
	
	r.logger.Info("Starting election for term %d", currentTerm)
	
	// Send vote requests to all peers
	voteRequest := &VoteRequest{
		Term:         currentTerm,
		CandidateID:  r.nodeID,
		LastLogIndex: lastLogIndex,
		LastLogTerm:  lastLogTerm,
	}
	
	for _, peer := range r.peers {
		if peer != r.nodeID {
			go r.sendVoteRequest(peer, voteRequest)
		}
	}
}

// sendVoteRequest sends a vote request to a peer.
func (r *RaftNode) sendVoteRequest(peerID string, request *VoteRequest) {
	topic := fmt.Sprintf("raft/%s/vote_request/%s", r.clusterID, peerID)
	if err := r.transport.Publish(context.Background(), topic, request, nil); err != nil {
		r.logger.Error("Failed to send vote request to %s: %v", peerID, err)
	}
}

// handleVoteRequest handles incoming vote requests.
func (r *RaftNode) handleVoteRequest(ctx context.Context, request interface{}) error {
	req, ok := request.(*VoteRequest)
	if !ok {
		return errors.New("invalid vote request type")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	response := &VoteResponse{
		Term:        r.currentTerm,
		VoteGranted: false,
		VoterID:     r.nodeID,
	}
	
	// Update term if necessary
	if req.Term > r.currentTerm {
		r.currentTerm = req.Term
		r.votedFor = ""
		r.state = Follower
	}
	
	// Grant vote if conditions are met
	if req.Term >= r.currentTerm &&
		(r.votedFor == "" || r.votedFor == req.CandidateID) &&
		r.isLogUpToDate(req.LastLogIndex, req.LastLogTerm) {
		
		r.votedFor = req.CandidateID
		r.lastHeartbeat = time.Now()
		response.VoteGranted = true
		response.Term = r.currentTerm
		
		r.logger.Info("Granted vote to %s for term %d", req.CandidateID, req.Term)
	}
	
	// Send response
	responseTopic := fmt.Sprintf("raft/%s/vote_response/%s", r.clusterID, req.CandidateID)
	return r.transport.Publish(ctx, responseTopic, response, nil)
}

// isLogUpToDate checks if the candidate's log is at least as up-to-date as ours.
func (r *RaftNode) isLogUpToDate(lastLogIndex, lastLogTerm int64) bool {
	ourLastIndex := int64(len(r.log))
	var ourLastTerm int64
	if ourLastIndex > 0 {
		ourLastTerm = r.log[ourLastIndex-1].Term
	}
	
	return lastLogTerm > ourLastTerm || (lastLogTerm == ourLastTerm && lastLogIndex >= ourLastIndex)
}

// sendHeartbeats sends heartbeat messages to all followers.
func (r *RaftNode) sendHeartbeats() {
	r.mu.RLock()
	currentTerm := r.currentTerm
	commitIndex := r.commitIndex
	r.mu.RUnlock()
	
	for _, peer := range r.peers {
		if peer != r.nodeID {
			go r.sendAppendEntries(peer, currentTerm, commitIndex, nil)
		}
	}
}

// sendAppendEntries sends append entries request to a peer.
func (r *RaftNode) sendAppendEntries(peerID string, term, leaderCommit int64, entries []*LogEntry) {
	r.mu.RLock()
	nextIndex := r.nextIndex[peerID]
	var prevLogIndex, prevLogTerm int64
	if nextIndex > 1 {
		prevLogIndex = nextIndex - 1
		if prevLogIndex <= int64(len(r.log)) {
			prevLogTerm = r.log[prevLogIndex-1].Term
		}
	}
	r.mu.RUnlock()
	
	request := &AppendEntriesRequest{
		Term:         term,
		LeaderID:     r.nodeID,
		PrevLogIndex: prevLogIndex,
		PrevLogTerm:  prevLogTerm,
		Entries:      entries,
		LeaderCommit: leaderCommit,
	}
	
	topic := fmt.Sprintf("raft/%s/append_entries/%s", r.clusterID, peerID)
	if err := r.transport.Publish(context.Background(), topic, request, nil); err != nil {
		r.logger.Error("Failed to send append entries to %s: %v", peerID, err)
	}
}

// handleAppendEntries handles incoming append entries requests.
func (r *RaftNode) handleAppendEntries(ctx context.Context, request interface{}) error {
	req, ok := request.(*AppendEntriesRequest)
	if !ok {
		return errors.New("invalid append entries request type")
	}
	
	r.mu.Lock()
	defer r.mu.Unlock()
	
	r.lastHeartbeat = time.Now()
	
	response := &AppendEntriesResponse{
		Term:    r.currentTerm,
		Success: false,
		NodeID:  r.nodeID,
	}
	
	// Update term if necessary
	if req.Term > r.currentTerm {
		r.currentTerm = req.Term
		r.votedFor = ""
		r.state = Follower
	}
	
	// Reject if term is outdated
	if req.Term < r.currentTerm {
		response.Term = r.currentTerm
		return r.sendAppendEntriesResponse(req.LeaderID, response)
	}
	
	// Convert to follower if we're a candidate
	if r.state == Candidate {
		r.state = Follower
	}
	
	// Check log consistency
	if req.PrevLogIndex > 0 {
		if req.PrevLogIndex > int64(len(r.log)) ||
			r.log[req.PrevLogIndex-1].Term != req.PrevLogTerm {
			return r.sendAppendEntriesResponse(req.LeaderID, response)
		}
	}
	
	// Append new entries
	if len(req.Entries) > 0 {
		// Remove conflicting entries
		if req.PrevLogIndex < int64(len(r.log)) {
			r.log = r.log[:req.PrevLogIndex]
		}
		
		// Append new entries
		r.log = append(r.log, req.Entries...)
	}
	
	// Update commit index
	if req.LeaderCommit > r.commitIndex {
		r.commitIndex = min(req.LeaderCommit, int64(len(r.log)))
	}
	
	response.Success = true
	response.Term = r.currentTerm
	
	return r.sendAppendEntriesResponse(req.LeaderID, response)
}

// sendAppendEntriesResponse sends a response to an append entries request.
func (r *RaftNode) sendAppendEntriesResponse(leaderID string, response *AppendEntriesResponse) error {
	topic := fmt.Sprintf("raft/%s/append_entries_response/%s", r.clusterID, leaderID)
	return r.transport.Publish(context.Background(), topic, response, nil)
}

// replicateToFollowers replicates log entries to all followers.
func (r *RaftNode) replicateToFollowers() {
	r.mu.RLock()
	if r.state != Leader {
		r.mu.RUnlock()
		return
	}
	
	currentTerm := r.currentTerm
	commitIndex := r.commitIndex
	r.mu.RUnlock()
	
	for _, peer := range r.peers {
		if peer != r.nodeID {
			go func(peerID string) {
				r.mu.RLock()
				nextIndex := r.nextIndex[peerID]
				var entries []*LogEntry
				if nextIndex <= int64(len(r.log)) {
					entries = r.log[nextIndex-1:]
				}
				r.mu.RUnlock()
				
				r.sendAppendEntries(peerID, currentTerm, commitIndex, entries)
			}(peer)
		}
	}
}

// applyStateMachine applies committed log entries to the state machine.
func (r *RaftNode) applyStateMachine(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-r.stopChan:
			return
		default:
			r.mu.Lock()
			if r.lastApplied < r.commitIndex {
				r.lastApplied++
				if r.lastApplied <= int64(len(r.log)) {
					entry := r.log[r.lastApplied-1]
					r.mu.Unlock()
					
					// Apply to state machine
					r.applyCommand(entry)
				} else {
					r.mu.Unlock()
				}
			} else {
				r.mu.Unlock()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}
}

// applyCommand applies a command to the state machine.
func (r *RaftNode) applyCommand(entry *LogEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	switch entry.Command {
	case "set":
		if key, ok := entry.Data["key"].(string); ok {
			r.stateMachine[key] = entry.Data["value"]
		}
	case "delete":
		if key, ok := entry.Data["key"].(string); ok {
			delete(r.stateMachine, key)
		}
	}
	
	r.logger.Debug("Applied command %s at index %d", entry.Command, entry.Index)
}

// min returns the minimum of two int64 values.
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}