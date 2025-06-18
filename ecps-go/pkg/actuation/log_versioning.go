// Package actuation provides log versioning support for .eaplog files.
package actuation

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// LogVersion represents supported log file versions
type LogVersion string

const (
	LogVersionV10 LogVersion = "1.0" // Legacy format (no header)
	LogVersionV11 LogVersion = "1.1" // Added basic header with version
	LogVersionV20 LogVersion = "2.0" // Enhanced header with metadata and checksums
	LogVersionV21 LogVersion = "2.1" // Added compression and encryption support
)

// Latest returns the latest supported log version
func (LogVersion) Latest() LogVersion {
	return LogVersionV21
}

// FromString creates LogVersion from string
func LogVersionFromString(versionStr string) (LogVersion, error) {
	switch versionStr {
	case "1.0":
		return LogVersionV10, nil
	case "1.1":
		return LogVersionV11, nil
	case "2.0":
		return LogVersionV20, nil
	case "2.1":
		return LogVersionV21, nil
	default:
		return "", fmt.Errorf("unsupported log version: %s", versionStr)
	}
}

// LogHeader represents the header structure for versioned .eaplog files
type LogHeader struct {
	Magic        string            `json:"magic"`         // Magic string to identify EAP log files
	Version      string            `json:"version"`       // Log format version
	CreatedAt    float64           `json:"created_at"`    // Unix timestamp
	SDKVersion   string            `json:"sdk_version"`   // SDK version
	RobotID      *string           `json:"robot_id"`      // Robot identifier
	SessionID    *string           `json:"session_id"`    // Session identifier
	Compression  string            `json:"compression"`   // none, gzip, lz4
	Encryption   string            `json:"encryption"`    // none, aes256
	ChecksumType string            `json:"checksum_type"` // crc32, sha256
	Metadata     map[string]interface{} `json:"metadata"`      // Additional metadata
}

// NewLogHeader creates a new log header with default values
func NewLogHeader(version LogVersion, robotID, sessionID *string, metadata map[string]interface{}) *LogHeader {
	if metadata == nil {
		metadata = make(map[string]interface{})
	}
	
	return &LogHeader{
		Magic:        "EAPLOG",
		Version:      string(version),
		CreatedAt:    float64(time.Now().Unix()),
		SDKVersion:   "1.0.0",
		RobotID:      robotID,
		SessionID:    sessionID,
		Compression:  "none",
		Encryption:   "none",
		ChecksumType: "crc32",
		Metadata:     metadata,
	}
}

// ToBytes serializes header to bytes
func (h *LogHeader) ToBytes() ([]byte, error) {
	// Serialize to JSON
	headerJSON, err := json.Marshal(h)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal header: %w", err)
	}
	
	// Create header with length prefix (little-endian uint32)
	headerLength := uint32(len(headerJSON))
	buf := new(bytes.Buffer)
	
	if err := binary.Write(buf, binary.LittleEndian, headerLength); err != nil {
		return nil, fmt.Errorf("failed to write header length: %w", err)
	}
	
	buf.Write(headerJSON)
	return buf.Bytes(), nil
}

// FromBytes deserializes header from bytes
func LogHeaderFromBytes(data []byte) (*LogHeader, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("invalid header: too short")
	}
	
	// Read header length (little-endian uint32)
	headerLength := binary.LittleEndian.Uint32(data[:4])
	
	// Read header JSON
	if len(data) < int(4+headerLength) {
		return nil, fmt.Errorf("invalid header: incomplete")
	}
	
	headerJSON := data[4 : 4+headerLength]
	var header LogHeader
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, fmt.Errorf("failed to unmarshal header: %w", err)
	}
	
	return &header, nil
}

// GetHeaderSize returns the total size of the header in bytes
func (h *LogHeader) GetHeaderSize() (int, error) {
	headerBytes, err := h.ToBytes()
	if err != nil {
		return 0, err
	}
	return len(headerBytes), nil
}

// LogReader provides reading functionality for versioned .eaplog files with backward compatibility
type LogReader struct {
	filePath        string
	header          *LogHeader
	version         LogVersion
	fileHandle      *os.File
	dataStartOffset int64
}

// NewLogReader creates a new log reader
func NewLogReader(filePath string) *LogReader {
	return &LogReader{
		filePath:        filePath,
		version:         LogVersionV10, // Default to legacy
		dataStartOffset: 0,
	}
}

// Open opens and analyzes the log file
func (r *LogReader) Open() error {
	if _, err := os.Stat(r.filePath); os.IsNotExist(err) {
		return fmt.Errorf("log file not found: %s", r.filePath)
	}
	
	file, err := os.Open(r.filePath)
	if err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	r.fileHandle = file
	
	// Try to detect version
	if err := r.detectVersion(); err != nil {
		// Assume legacy format on error
		r.version = LogVersionV10
		r.dataStartOffset = 0
		r.fileHandle.Seek(0, io.SeekStart)
	}
	
	return nil
}

// detectVersion detects the log file version
func (r *LogReader) detectVersion() error {
	// Read potential magic bytes
	magicBytes := make([]byte, 6)
	n, err := r.fileHandle.Read(magicBytes)
	if err != nil || n < 6 {
		return fmt.Errorf("failed to read magic bytes")
	}
	
	if string(magicBytes) == "EAPLOG" {
		// This is a versioned log file
		r.fileHandle.Seek(0, io.SeekStart)
		
		// Read header length
		var headerLength uint32
		if err := binary.Read(r.fileHandle, binary.LittleEndian, &headerLength); err != nil {
			return fmt.Errorf("failed to read header length: %w", err)
		}
		
		// Read header data
		headerData := make([]byte, 4+headerLength)
		binary.LittleEndian.PutUint32(headerData[:4], headerLength)
		
		if _, err := r.fileHandle.Read(headerData[4:]); err != nil {
			return fmt.Errorf("failed to read header data: %w", err)
		}
		
		header, err := LogHeaderFromBytes(headerData)
		if err != nil {
			return fmt.Errorf("failed to parse header: %w", err)
		}
		
		r.header = header
		version, err := LogVersionFromString(header.Version)
		if err != nil {
			return fmt.Errorf("invalid version in header: %w", err)
		}
		r.version = version
		r.dataStartOffset = int64(len(headerData))
		
		return nil
	}
	
	// This is a legacy log file (no header)
	r.version = LogVersionV10
	r.dataStartOffset = 0
	r.fileHandle.Seek(0, io.SeekStart)
	
	return nil
}

// ReadMessages reads all messages from the log file
func (r *LogReader) ReadMessages() ([][]byte, error) {
	if r.fileHandle == nil {
		return nil, fmt.Errorf("log file not opened")
	}
	
	var messages [][]byte
	r.fileHandle.Seek(r.dataStartOffset, io.SeekStart)
	
	for {
		// Read message length (little-endian uint32)
		var messageLength uint32
		if err := binary.Read(r.fileHandle, binary.LittleEndian, &messageLength); err != nil {
			if err == io.EOF {
				break // End of file
			}
			return nil, fmt.Errorf("failed to read message length: %w", err)
		}
		
		// Read message data
		messageData := make([]byte, messageLength)
		if _, err := r.fileHandle.Read(messageData); err != nil {
			if err == io.EOF {
				break // Incomplete message at end of file
			}
			return nil, fmt.Errorf("failed to read message data: %w", err)
		}
		
		messages = append(messages, messageData)
	}
	
	return messages, nil
}

// Close closes the log file
func (r *LogReader) Close() error {
	if r.fileHandle != nil {
		err := r.fileHandle.Close()
		r.fileHandle = nil
		return err
	}
	return nil
}

// GetInfo returns information about the log file
func (r *LogReader) GetInfo() (map[string]interface{}, error) {
	info := map[string]interface{}{
		"file_path":         r.filePath,
		"version":           string(r.version),
		"data_start_offset": r.dataStartOffset,
	}
	
	if stat, err := os.Stat(r.filePath); err == nil {
		info["file_size"] = stat.Size()
	}
	
	if r.header != nil {
		info["created_at"] = r.header.CreatedAt
		info["sdk_version"] = r.header.SDKVersion
		info["robot_id"] = r.header.RobotID
		info["session_id"] = r.header.SessionID
		info["compression"] = r.header.Compression
		info["encryption"] = r.header.Encryption
		info["metadata"] = r.header.Metadata
	}
	
	return info, nil
}

// LogWriter provides writing functionality for versioned .eaplog files
type LogWriter struct {
	filePath     string
	version      LogVersion
	header       *LogHeader
	fileHandle   *os.File
	messageCount int
}

// NewLogWriter creates a new log writer
func NewLogWriter(filePath string, version LogVersion, robotID, sessionID *string, metadata map[string]interface{}) *LogWriter {
	header := NewLogHeader(version, robotID, sessionID, metadata)
	
	return &LogWriter{
		filePath:     filePath,
		version:      version,
		header:       header,
		messageCount: 0,
	}
}

// Open opens the log file for writing
func (w *LogWriter) Open() error {
	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(w.filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	file, err := os.Create(w.filePath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	w.fileHandle = file
	
	// Write header for versioned formats
	if w.version != LogVersionV10 {
		headerBytes, err := w.header.ToBytes()
		if err != nil {
			return fmt.Errorf("failed to serialize header: %w", err)
		}
		
		if _, err := w.fileHandle.Write(headerBytes); err != nil {
			return fmt.Errorf("failed to write header: %w", err)
		}
		
		if err := w.fileHandle.Sync(); err != nil {
			return fmt.Errorf("failed to sync header: %w", err)
		}
	}
	
	return nil
}

// WriteMessage writes a message to the log file
func (w *LogWriter) WriteMessage(messageData []byte) error {
	if w.fileHandle == nil {
		return fmt.Errorf("log file not opened")
	}
	
	// Write message length and data (same format as legacy)
	messageLength := uint32(len(messageData))
	if err := binary.Write(w.fileHandle, binary.LittleEndian, messageLength); err != nil {
		return fmt.Errorf("failed to write message length: %w", err)
	}
	
	if _, err := w.fileHandle.Write(messageData); err != nil {
		return fmt.Errorf("failed to write message data: %w", err)
	}
	
	if err := w.fileHandle.Sync(); err != nil {
		return fmt.Errorf("failed to sync message: %w", err)
	}
	
	w.messageCount++
	return nil
}

// Close closes the log file
func (w *LogWriter) Close() error {
	if w.fileHandle != nil {
		err := w.fileHandle.Close()
		w.fileHandle = nil
		return err
	}
	return nil
}

// GetMessageCount returns the number of messages written
func (w *LogWriter) GetMessageCount() int {
	return w.messageCount
}

// LogMigrator provides utilities for migrating log files between versions
type LogMigrator struct{}

// NewLogMigrator creates a new log migrator
func NewLogMigrator() *LogMigrator {
	return &LogMigrator{}
}

// MigrateFile migrates a log file from one version to another
func (m *LogMigrator) MigrateFile(sourcePath, targetPath string, targetVersion LogVersion, robotID, sessionID *string, metadata map[string]interface{}) error {
	// Open source file
	reader := NewLogReader(sourcePath)
	if err := reader.Open(); err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer reader.Close()
	
	// Read all messages
	messages, err := reader.ReadMessages()
	if err != nil {
		return fmt.Errorf("failed to read messages: %w", err)
	}
	
	// Create target file
	writer := NewLogWriter(targetPath, targetVersion, robotID, sessionID, metadata)
	if err := writer.Open(); err != nil {
		return fmt.Errorf("failed to create target file: %w", err)
	}
	defer writer.Close()
	
	// Write all messages to target file
	for _, message := range messages {
		if err := writer.WriteMessage(message); err != nil {
			return fmt.Errorf("failed to write message: %w", err)
		}
	}
	
	return nil
}

// ValidateFile validates the integrity of a log file
func (m *LogMigrator) ValidateFile(filePath string) error {
	reader := NewLogReader(filePath)
	if err := reader.Open(); err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer reader.Close()
	
	// Try to read all messages
	_, err := reader.ReadMessages()
	if err != nil {
		return fmt.Errorf("file validation failed: %w", err)
	}
	
	return nil
}