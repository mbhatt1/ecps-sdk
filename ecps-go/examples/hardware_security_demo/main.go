// Package main demonstrates hardware security and log versioning features.
package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/ecps/ecps-go/pkg/actuation"
	"github.com/ecps/ecps-go/pkg/trust"
)

func main() {
	fmt.Println("=== ECPS-UV Go Hardware Security & Log Versioning Demo ===\n")
	
	// Create demo directory
	demoDir := "demo_output"
	if err := os.MkdirAll(demoDir, 0755); err != nil {
		log.Fatalf("Failed to create demo directory: %v", err)
	}
	
	// Demo 1: Hardware Security Integration
	fmt.Println("1. Hardware Security Integration Demo")
	fmt.Println("=====================================")
	
	if err := demoHardwareSecurity(); err != nil {
		log.Printf("Hardware security demo failed: %v", err)
	}
	
	fmt.Println()
	
	// Demo 2: Log Versioning System
	fmt.Println("2. Log Versioning System Demo")
	fmt.Println("=============================")
	
	if err := demoLogVersioning(demoDir); err != nil {
		log.Printf("Log versioning demo failed: %v", err)
	}
	
	fmt.Println()
	
	// Demo 3: Integration Demo
	fmt.Println("3. Integration Demo")
	fmt.Println("==================")
	
	if err := demoIntegration(demoDir); err != nil {
		log.Printf("Integration demo failed: %v", err)
	}
	
	fmt.Println("\n=== Demo Complete ===")
	fmt.Printf("Demo files created in: %s\n", demoDir)
}

// demoHardwareSecurity demonstrates hardware security features
func demoHardwareSecurity() error {
	fmt.Println("Initializing Hardware Security Manager...")
	
	// Create hardware security manager
	manager := trust.NewHardwareSecurityManager()
	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize hardware security manager: %w", err)
	}
	defer manager.Cleanup()
	
	activeProvider := manager.GetActiveProvider()
	fmt.Printf("Active provider: %s\n", activeProvider.GetHardwareType())
	
	// List available providers
	providers := manager.GetAvailableProviders()
	fmt.Printf("Available providers: ")
	for i, provider := range providers {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Print(provider.GetHardwareType())
	}
	fmt.Println()
	
	// Generate device identity
	fmt.Println("\nGenerating device identity...")
	identity, err := activeProvider.GenerateKey("demo_key")
	if err != nil {
		return fmt.Errorf("failed to generate device identity: %w", err)
	}
	
	fmt.Printf("Device ID: %s\n", identity.DeviceID)
	fmt.Printf("Hardware Type: %s\n", identity.HardwareType)
	fmt.Printf("Public Key Length: %d bytes\n", len(identity.PublicKey))
	
	if identity.PlatformInfo != nil {
		fmt.Println("Platform Info:")
		for key, value := range identity.PlatformInfo {
			fmt.Printf("  %s: %s\n", key, value)
		}
	}
	
	// Test signing and verification
	fmt.Println("\nTesting signing and verification...")
	testData := []byte("Hello, ECPS-UV Hardware Security!")
	
	signature, err := activeProvider.Sign("demo_key", testData)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}
	
	fmt.Printf("Signature length: %d bytes\n", len(signature))
	
	if err := activeProvider.Verify("demo_key", testData, signature); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	
	fmt.Println("✓ Signature verification successful")
	
	// Create attestation report
	fmt.Println("\nCreating attestation report...")
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	report, err := activeProvider.CreateAttestation(nonce, trust.AttestationDeviceIdentity)
	if err != nil {
		return fmt.Errorf("failed to create attestation: %w", err)
	}
	
	fmt.Printf("Attestation Type: %s\n", report.AttestationType)
	fmt.Printf("Device ID: %s\n", report.DeviceID)
	fmt.Printf("Timestamp: %s\n", time.Unix(int64(report.Timestamp), 0).Format(time.RFC3339))
	fmt.Printf("Measurements: %d entries\n", len(report.Measurements))
	
	for name, value := range report.Measurements {
		fmt.Printf("  %s: %s\n", name, value)
	}
	
	// Verify attestation
	fmt.Println("\nVerifying attestation report...")
	if err := activeProvider.VerifyAttestation(report); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}
	
	fmt.Println("✓ Attestation verification successful")
	
	return nil
}

// demoLogVersioning demonstrates log versioning features
func demoLogVersioning(demoDir string) error {
	fmt.Println("Testing log versioning system...")
	
	// Test different log versions
	versions := []actuation.LogVersion{
		actuation.LogVersionV10,
		actuation.LogVersionV11,
		actuation.LogVersionV20,
		actuation.LogVersionV21,
	}
	
	for _, version := range versions {
		fmt.Printf("\nTesting version %s...\n", version)
		
		// Create log file
		logFile := filepath.Join(demoDir, fmt.Sprintf("test_%s.eaplog", version))
		robotID := "robot_demo_001"
		sessionID := fmt.Sprintf("session_%d", time.Now().Unix())
		metadata := map[string]interface{}{
			"demo":        true,
			"version":     string(version),
			"created_by":  "go_demo",
		}
		
		writer := actuation.NewLogWriter(logFile, version, &robotID, &sessionID, metadata)
		if err := writer.Open(); err != nil {
			return fmt.Errorf("failed to create log file: %w", err)
		}
		
		// Write test messages
		for i := 0; i < 5; i++ {
			message := fmt.Sprintf(`{"message_id": %d, "action": "test_action_%d", "timestamp": %d}`, 
				i, i, time.Now().UnixNano())
			
			if err := writer.WriteMessage([]byte(message)); err != nil {
				writer.Close()
				return fmt.Errorf("failed to write message: %w", err)
			}
		}
		
		writer.Close()
		fmt.Printf("✓ Created %s with %d messages\n", logFile, writer.GetMessageCount())
		
		// Read and validate log file
		reader := actuation.NewLogReader(logFile)
		if err := reader.Open(); err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		
		info, err := reader.GetInfo()
		if err != nil {
			reader.Close()
			return fmt.Errorf("failed to get log info: %w", err)
		}
		
		fmt.Printf("  File size: %v bytes\n", info["file_size"])
		fmt.Printf("  Version: %s\n", info["version"])
		if info["robot_id"] != nil {
			fmt.Printf("  Robot ID: %s\n", info["robot_id"])
		}
		
		messages, err := reader.ReadMessages()
		if err != nil {
			reader.Close()
			return fmt.Errorf("failed to read messages: %w", err)
		}
		
		reader.Close()
		fmt.Printf("✓ Read %d messages successfully\n", len(messages))
	}
	
	// Test migration
	fmt.Println("\nTesting log migration...")
	sourceFile := filepath.Join(demoDir, "test_1.0.eaplog")
	targetFile := filepath.Join(demoDir, "migrated_2.1.eaplog")
	
	migrator := actuation.NewLogMigrator()
	robotID := "migrated_robot"
	sessionID := "migrated_session"
	metadata := map[string]interface{}{
		"migrated": true,
		"source_version": "1.0",
		"target_version": "2.1",
	}
	
	if err := migrator.MigrateFile(sourceFile, targetFile, actuation.LogVersionV21, &robotID, &sessionID, metadata); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	
	fmt.Printf("✓ Successfully migrated %s to %s\n", sourceFile, targetFile)
	
	// Validate migrated file
	if err := migrator.ValidateFile(targetFile); err != nil {
		return fmt.Errorf("migrated file validation failed: %w", err)
	}
	
	fmt.Println("✓ Migrated file validation successful")
	
	return nil
}

// demoIntegration demonstrates integration of hardware security and log versioning
func demoIntegration(demoDir string) error {
	fmt.Println("Demonstrating integrated hardware security and log versioning...")
	
	// Initialize hardware security
	manager := trust.NewHardwareSecurityManager()
	if err := manager.Initialize(); err != nil {
		return fmt.Errorf("failed to initialize hardware security: %w", err)
	}
	defer manager.Cleanup()
	
	provider := manager.GetActiveProvider()
	
	// Generate device identity
	identity, err := provider.GenerateKey("integration_key")
	if err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}
	
	// Create secure log file with hardware identity
	logFile := filepath.Join(demoDir, "secure_integrated.eaplog")
	metadata := map[string]interface{}{
		"hardware_secured": true,
		"device_id":        identity.DeviceID,
		"hardware_type":    string(identity.HardwareType),
		"security_level":   "high",
	}
	
	writer := actuation.NewLogWriter(logFile, actuation.LogVersionV21, &identity.DeviceID, nil, metadata)
	if err := writer.Open(); err != nil {
		return fmt.Errorf("failed to create secure log: %w", err)
	}
	
	// Create and log secure actions
	for i := 0; i < 3; i++ {
		// Create action data
		actionData := map[string]interface{}{
			"action_id":   fmt.Sprintf("secure_action_%d", i),
			"timestamp":   time.Now().UnixNano(),
			"device_id":   identity.DeviceID,
			"action_type": "secure_operation",
			"parameters": map[string]interface{}{
				"operation": fmt.Sprintf("secure_op_%d", i),
				"priority":  i + 1,
			},
		}
		
		actionJSON, err := json.Marshal(actionData)
		if err != nil {
			writer.Close()
			return fmt.Errorf("failed to marshal action: %w", err)
		}
		
		// Sign the action data
		signature, err := provider.Sign("integration_key", actionJSON)
		if err != nil {
			writer.Close()
			return fmt.Errorf("failed to sign action: %w", err)
		}
		
		// Create signed message
		signedMessage := map[string]interface{}{
			"action":    actionData,
			"signature": fmt.Sprintf("%x", signature),
			"signed_by": identity.DeviceID,
		}
		
		signedJSON, err := json.Marshal(signedMessage)
		if err != nil {
			writer.Close()
			return fmt.Errorf("failed to marshal signed message: %w", err)
		}
		
		// Write to log
		if err := writer.WriteMessage(signedJSON); err != nil {
			writer.Close()
			return fmt.Errorf("failed to write secure message: %w", err)
		}
		
		fmt.Printf("✓ Logged secure action %d with hardware signature\n", i)
	}
	
	writer.Close()
	
	// Create attestation for the log file
	fmt.Println("\nCreating attestation for the secure log...")
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate nonce: %w", err)
	}
	
	report, err := provider.CreateAttestation(nonce, trust.AttestationRuntimeIntegrity)
	if err != nil {
		return fmt.Errorf("failed to create attestation: %w", err)
	}
	
	// Save attestation report
	attestationFile := filepath.Join(demoDir, "log_attestation.json")
	attestationJSON, err := json.MarshalIndent(report.ToDict(), "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal attestation: %w", err)
	}
	
	if err := os.WriteFile(attestationFile, attestationJSON, 0644); err != nil {
		return fmt.Errorf("failed to save attestation: %w", err)
	}
	
	fmt.Printf("✓ Attestation report saved to %s\n", attestationFile)
	
	// Verify the complete integration
	fmt.Println("\nVerifying integrated security...")
	
	// Read and verify log file
	reader := actuation.NewLogReader(logFile)
	if err := reader.Open(); err != nil {
		return fmt.Errorf("failed to open secure log: %w", err)
	}
	
	messages, err := reader.ReadMessages()
	if err != nil {
		reader.Close()
		return fmt.Errorf("failed to read secure messages: %w", err)
	}
	
	reader.Close()
	
	// Verify signatures on all messages
	for i, message := range messages {
		var signedMessage map[string]interface{}
		if err := json.Unmarshal(message, &signedMessage); err != nil {
			return fmt.Errorf("failed to unmarshal message %d: %w", i, err)
		}
		
		// Extract action and signature
		actionData, ok := signedMessage["action"]
		if !ok {
			return fmt.Errorf("message %d missing action data", i)
		}
		
		signatureHex, ok := signedMessage["signature"].(string)
		if !ok {
			return fmt.Errorf("message %d missing signature", i)
		}
		
		// Re-marshal action for verification
		actionJSON, err := json.Marshal(actionData)
		if err != nil {
			return fmt.Errorf("failed to re-marshal action %d: %w", i, err)
		}
		
		// Decode signature
		signature := make([]byte, len(signatureHex)/2)
		for j := 0; j < len(signature); j++ {
			fmt.Sscanf(signatureHex[j*2:j*2+2], "%02x", &signature[j])
		}
		
		// Verify signature
		if err := provider.Verify("integration_key", actionJSON, signature); err != nil {
			return fmt.Errorf("signature verification failed for message %d: %w", i, err)
		}
		
		fmt.Printf("✓ Message %d signature verified\n", i)
	}
	
	// Verify attestation
	if err := provider.VerifyAttestation(report); err != nil {
		return fmt.Errorf("attestation verification failed: %w", err)
	}
	
	fmt.Println("✓ Attestation verification successful")
	
	// Display summary
	info, err := reader.GetInfo()
	if err == nil {
		fmt.Println("\nIntegration Summary:")
		fmt.Printf("  Secure log file: %s\n", logFile)
		fmt.Printf("  Log version: %s\n", info["version"])
		fmt.Printf("  Device ID: %s\n", info["robot_id"])
		fmt.Printf("  Hardware type: %s\n", provider.GetHardwareType())
		fmt.Printf("  Messages: %d (all signed and verified)\n", len(messages))
		fmt.Printf("  Attestation: verified\n")
	}
	
	return nil
}