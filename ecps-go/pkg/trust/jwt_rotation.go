// Package trust provides JWT secret rotation for ECPS-Go SDK
package trust

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTSecret represents a JWT signing secret with metadata
type JWTSecret struct {
	Secret    string    `json:"secret"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID     string    `json:"key_id"`
	Algorithm string    `json:"algorithm"`
}

// IsExpired checks if the secret has expired
func (s *JWTSecret) IsExpired() bool {
	return time.Now().UTC().After(s.ExpiresAt)
}

// IsNearExpiry checks if the secret is near expiry
func (s *JWTSecret) IsNearExpiry(thresholdHours int) bool {
	threshold := time.Now().UTC().Add(time.Duration(thresholdHours) * time.Hour)
	return s.ExpiresAt.Before(threshold)
}

// JWTSecretManager manages JWT secret rotation and validation
type JWTSecretManager struct {
	rotationIntervalHours int
	secretLength          int
	algorithm             string
	storagePath           string
	currentSecret         *JWTSecret
	previousSecret        *JWTSecret
	mutex                 sync.RWMutex
	stopChan              chan struct{}
	callbacks             map[string]func(*JWTSecret)
}

// NewJWTSecretManager creates a new JWT secret manager
func NewJWTSecretManager(rotationIntervalHours, secretLength int, algorithm, storagePath string) *JWTSecretManager {
	if storagePath == "" {
		homeDir, _ := os.UserHomeDir()
		storagePath = filepath.Join(homeDir, ".ecps", "jwt_secrets.json")
	}

	// Ensure storage directory exists
	os.MkdirAll(filepath.Dir(storagePath), 0700)

	return &JWTSecretManager{
		rotationIntervalHours: rotationIntervalHours,
		secretLength:          secretLength,
		algorithm:             algorithm,
		storagePath:           storagePath,
		stopChan:              make(chan struct{}),
		callbacks:             make(map[string]func(*JWTSecret)),
	}
}

// RegisterRotationCallback registers a callback for secret rotation
func (m *JWTSecretManager) RegisterRotationCallback(name string, callback func(*JWTSecret)) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.callbacks[name] = callback
	log.Printf("Registered rotation callback: %s", name)
}

// UnregisterRotationCallback unregisters a rotation callback
func (m *JWTSecretManager) UnregisterRotationCallback(name string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	delete(m.callbacks, name)
	log.Printf("Unregistered rotation callback: %s", name)
}

// generateSecret generates a new JWT secret
func (m *JWTSecretManager) generateSecret() (*JWTSecret, error) {
	// Generate random bytes
	secretBytes := make([]byte, m.secretLength)
	if _, err := rand.Read(secretBytes); err != nil {
		return nil, fmt.Errorf("failed to generate secret: %w", err)
	}

	// Generate key ID
	keyIDBytes := make([]byte, 8)
	if _, err := rand.Read(keyIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key ID: %w", err)
	}

	secret := base64.URLEncoding.EncodeToString(secretBytes)
	keyID := fmt.Sprintf("%x", keyIDBytes)

	now := time.Now().UTC()
	expiresAt := now.Add(time.Duration(m.rotationIntervalHours*2) * time.Hour) // Grace period

	jwtSecret := &JWTSecret{
		Secret:    secret,
		CreatedAt: now,
		ExpiresAt: expiresAt,
		KeyID:     keyID,
		Algorithm: m.algorithm,
	}

	log.Printf("Generated new JWT secret with key_id: %s", keyID)
	return jwtSecret, nil
}

// RotateSecretOnStartup rotates JWT secret on startup
func (m *JWTSecretManager) RotateSecretOnStartup() (*JWTSecret, error) {
	log.Println("Rotating JWT secret on startup")

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Load previous secrets if they exist
	if err := m.loadSecretsFromStorage(); err != nil {
		log.Printf("Warning: failed to load existing secrets: %v", err)
	}

	// Store current as previous
	if m.currentSecret != nil {
		m.previousSecret = m.currentSecret
		log.Printf("Moved current secret %s to previous", m.currentSecret.KeyID)
	}

	// Generate new current secret
	newSecret, err := m.generateSecret()
	if err != nil {
		return nil, fmt.Errorf("failed to generate new secret: %w", err)
	}
	m.currentSecret = newSecret

	// Save to storage
	if err := m.saveSecretsToStorage(); err != nil {
		log.Printf("Warning: failed to save secrets: %v", err)
	}

	// Notify callbacks
	m.notifyRotationCallbacks()

	log.Printf("JWT secret rotated on startup. New key_id: %s", newSecret.KeyID)
	return newSecret, nil
}

// StartAutomaticRotation starts automatic JWT secret rotation
func (m *JWTSecretManager) StartAutomaticRotation() {
	log.Printf("Starting automatic JWT secret rotation every %d hours", m.rotationIntervalHours)

	go func() {
		ticker := time.NewTicker(time.Duration(m.rotationIntervalHours) * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				m.mutex.Lock()
				if m.currentSecret == nil || m.currentSecret.IsNearExpiry(m.rotationIntervalHours) {
					log.Println("Performing scheduled JWT secret rotation")
					if err := m.performRotation(); err != nil {
						log.Printf("Error in scheduled rotation: %v", err)
					}
				}
				m.mutex.Unlock()

			case <-m.stopChan:
				log.Println("JWT rotation loop stopped")
				return
			}
		}
	}()
}

// StopAutomaticRotation stops automatic JWT secret rotation
func (m *JWTSecretManager) StopAutomaticRotation() {
	close(m.stopChan)
	log.Println("Stopped automatic JWT secret rotation")
}

// performRotation performs secret rotation (must be called with lock held)
func (m *JWTSecretManager) performRotation() error {
	// Store current as previous
	if m.currentSecret != nil {
		m.previousSecret = m.currentSecret
		log.Printf("Moved current secret %s to previous", m.currentSecret.KeyID)
	}

	// Generate new current secret
	newSecret, err := m.generateSecret()
	if err != nil {
		return fmt.Errorf("failed to generate new secret: %w", err)
	}
	m.currentSecret = newSecret

	// Save to storage
	if err := m.saveSecretsToStorage(); err != nil {
		log.Printf("Warning: failed to save secrets: %v", err)
	}

	// Notify callbacks
	m.notifyRotationCallbacks()

	log.Printf("JWT secret rotated. New key_id: %s", newSecret.KeyID)
	return nil
}

// notifyRotationCallbacks notifies all registered callbacks
func (m *JWTSecretManager) notifyRotationCallbacks() {
	if m.currentSecret == nil {
		return
	}

	for name, callback := range m.callbacks {
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Error in rotation callback %s: %v", name, r)
				}
			}()
			callback(m.currentSecret)
			log.Printf("Notified rotation callback: %s", name)
		}()
	}
}

// GetCurrentSecret returns the current JWT secret
func (m *JWTSecretManager) GetCurrentSecret() *JWTSecret {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.currentSecret
}

// GetPreviousSecret returns the previous JWT secret
func (m *JWTSecretManager) GetPreviousSecret() *JWTSecret {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.previousSecret
}

// ValidateToken validates a JWT token using current or previous secret
func (m *JWTSecretManager) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	var secretsToTry []*JWTSecret
	if m.currentSecret != nil {
		secretsToTry = append(secretsToTry, m.currentSecret)
	}
	if m.previousSecret != nil && !m.previousSecret.IsExpired() {
		secretsToTry = append(secretsToTry, m.previousSecret)
	}

	var lastErr error
	for _, jwtSecret := range secretsToTry {
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret.Secret), nil
		})

		if err == nil && token.Valid {
			if claims, ok := token.Claims.(jwt.MapClaims); ok {
				log.Printf("Token validated with key_id: %s", jwtSecret.KeyID)
				return claims, nil
			}
		}
		lastErr = err
	}

	log.Println("JWT token validation failed with all available secrets")
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no valid secrets available")
}

// CreateToken creates a JWT token with the current secret
func (m *JWTSecretManager) CreateToken(payload jwt.MapClaims, expiresInHours int) (string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.currentSecret == nil {
		return "", fmt.Errorf("no current JWT secret available")
	}

	// Add standard claims
	now := time.Now().UTC()
	payload["iat"] = now.Unix()
	payload["exp"] = now.Add(time.Duration(expiresInHours) * time.Hour).Unix()
	payload["kid"] = m.currentSecret.KeyID

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	tokenString, err := token.SignedString([]byte(m.currentSecret.Secret))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	log.Printf("Created JWT token with key_id: %s", m.currentSecret.KeyID)
	return tokenString, nil
}

// saveSecretsToStorage saves secrets to persistent storage
func (m *JWTSecretManager) saveSecretsToStorage() error {
	data := map[string]interface{}{
		"updated_at": time.Now().UTC(),
	}

	if m.currentSecret != nil {
		data["current"] = m.currentSecret
	}
	if m.previousSecret != nil {
		data["previous"] = m.previousSecret
	}

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal secrets: %w", err)
	}

	if err := ioutil.WriteFile(m.storagePath, jsonData, 0600); err != nil {
		return fmt.Errorf("failed to write secrets file: %w", err)
	}

	log.Printf("Saved JWT secrets to %s", m.storagePath)
	return nil
}

// loadSecretsFromStorage loads secrets from persistent storage
func (m *JWTSecretManager) loadSecretsFromStorage() error {
	if _, err := os.Stat(m.storagePath); os.IsNotExist(err) {
		log.Println("No existing JWT secrets found")
		return nil
	}

	data, err := ioutil.ReadFile(m.storagePath)
	if err != nil {
		return fmt.Errorf("failed to read secrets file: %w", err)
	}

	var secretsData map[string]interface{}
	if err := json.Unmarshal(data, &secretsData); err != nil {
		return fmt.Errorf("failed to unmarshal secrets: %w", err)
	}

	if currentData, ok := secretsData["current"]; ok {
		currentBytes, _ := json.Marshal(currentData)
		var current JWTSecret
		if err := json.Unmarshal(currentBytes, &current); err == nil {
			m.currentSecret = &current
			log.Printf("Loaded current secret with key_id: %s", current.KeyID)
		}
	}

	if previousData, ok := secretsData["previous"]; ok {
		previousBytes, _ := json.Marshal(previousData)
		var previous JWTSecret
		if err := json.Unmarshal(previousBytes, &previous); err == nil {
			m.previousSecret = &previous
			log.Printf("Loaded previous secret with key_id: %s", previous.KeyID)
		}
	}

	return nil
}

// Global JWT secret manager instance
var globalJWTManager *JWTSecretManager

// InitializeJWTRotation initializes JWT secret rotation on startup
func InitializeJWTRotation(rotationIntervalHours, secretLength int, algorithm, storagePath string) (*JWTSecret, error) {
	globalJWTManager = NewJWTSecretManager(rotationIntervalHours, secretLength, algorithm, storagePath)
	return globalJWTManager.RotateSecretOnStartup()
}

// GetJWTManager returns the global JWT secret manager instance
func GetJWTManager() *JWTSecretManager {
	return globalJWTManager
}

// StartJWTRotation starts automatic JWT secret rotation
func StartJWTRotation() {
	if globalJWTManager != nil {
		globalJWTManager.StartAutomaticRotation()
	}
}

// StopJWTRotation stops automatic JWT secret rotation
func StopJWTRotation() {
	if globalJWTManager != nil {
		globalJWTManager.StopAutomaticRotation()
	}
}