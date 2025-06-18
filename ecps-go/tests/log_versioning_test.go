package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ecps/ecps-go/pkg/actuation"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogVersioning(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "log_versioning_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("LogVersionFromString", func(t *testing.T) {
		tests := []struct {
			input    string
			expected actuation.LogVersion
			hasError bool
		}{
			{"1.0", actuation.LogVersionV10, false},
			{"1.1", actuation.LogVersionV11, false},
			{"2.0", actuation.LogVersionV20, false},
			{"2.1", actuation.LogVersionV21, false},
			{"3.0", "", true},
			{"invalid", "", true},
		}

		for _, test := range tests {
			version, err := actuation.LogVersionFromString(test.input)
			if test.hasError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.expected, version)
			}
		}
	})

	t.Run("LogHeader", func(t *testing.T) {
		robotID := "test_robot"
		sessionID := "test_session"
		metadata := map[string]interface{}{
			"test": true,
			"value": 42,
		}

		header := actuation.NewLogHeader(actuation.LogVersionV21, &robotID, &sessionID, metadata)
		
		assert.Equal(t, "EAPLOG", header.Magic)
		assert.Equal(t, "2.1", header.Version)
		assert.Equal(t, &robotID, header.RobotID)
		assert.Equal(t, &sessionID, header.SessionID)
		assert.Equal(t, metadata, header.Metadata)

		// Test serialization
		headerBytes, err := header.ToBytes()
		require.NoError(t, err)
		assert.Greater(t, len(headerBytes), 0)

		// Test deserialization
		deserializedHeader, err := actuation.LogHeaderFromBytes(headerBytes)
		require.NoError(t, err)
		assert.Equal(t, header.Magic, deserializedHeader.Magic)
		assert.Equal(t, header.Version, deserializedHeader.Version)
		assert.Equal(t, header.RobotID, deserializedHeader.RobotID)
		assert.Equal(t, header.SessionID, deserializedHeader.SessionID)
	})

	t.Run("LogWriter", func(t *testing.T) {
		logFile := filepath.Join(tempDir, "test_writer.eaplog")
		robotID := "writer_robot"
		sessionID := "writer_session"
		metadata := map[string]interface{}{"test": "writer"}

		writer := actuation.NewLogWriter(logFile, actuation.LogVersionV21, &robotID, &sessionID, metadata)
		
		err := writer.Open()
		require.NoError(t, err)

		// Write test messages
		testMessages := []string{
			`{"message": 1, "data": "test1"}`,
			`{"message": 2, "data": "test2"}`,
			`{"message": 3, "data": "test3"}`,
		}

		for _, msg := range testMessages {
			err := writer.WriteMessage([]byte(msg))
			require.NoError(t, err)
		}

		assert.Equal(t, len(testMessages), writer.GetMessageCount())

		err = writer.Close()
		require.NoError(t, err)

		// Verify file exists
		_, err = os.Stat(logFile)
		assert.NoError(t, err)
	})

	t.Run("LogReader", func(t *testing.T) {
		logFile := filepath.Join(tempDir, "test_reader.eaplog")
		robotID := "reader_robot"
		sessionID := "reader_session"
		metadata := map[string]interface{}{"test": "reader"}

		// Create test file
		writer := actuation.NewLogWriter(logFile, actuation.LogVersionV20, &robotID, &sessionID, metadata)
		require.NoError(t, writer.Open())

		testMessages := []string{
			`{"message": 1}`,
			`{"message": 2}`,
		}

		for _, msg := range testMessages {
			require.NoError(t, writer.WriteMessage([]byte(msg)))
		}
		require.NoError(t, writer.Close())

		// Read the file
		reader := actuation.NewLogReader(logFile)
		require.NoError(t, reader.Open())

		info, err := reader.GetInfo()
		require.NoError(t, err)
		assert.Equal(t, "2.0", info["version"])
		assert.Equal(t, &robotID, info["robot_id"])
		assert.Equal(t, &sessionID, info["session_id"])

		messages, err := reader.ReadMessages()
		require.NoError(t, err)
		assert.Len(t, messages, len(testMessages))

		for i, msg := range messages {
			assert.Equal(t, testMessages[i], string(msg))
		}

		require.NoError(t, reader.Close())
	})

	t.Run("LegacyLogSupport", func(t *testing.T) {
		legacyFile := filepath.Join(tempDir, "legacy.eaplog")

		// Create legacy log (version 1.0 - no header)
		writer := actuation.NewLogWriter(legacyFile, actuation.LogVersionV10, nil, nil, nil)
		require.NoError(t, writer.Open())

		testMessage := `{"legacy": true}`
		require.NoError(t, writer.WriteMessage([]byte(testMessage)))
		require.NoError(t, writer.Close())

		// Read legacy log
		reader := actuation.NewLogReader(legacyFile)
		require.NoError(t, reader.Open())

		info, err := reader.GetInfo()
		require.NoError(t, err)
		assert.Equal(t, "1.0", info["version"])
		assert.Equal(t, int64(0), info["data_start_offset"])

		messages, err := reader.ReadMessages()
		require.NoError(t, err)
		assert.Len(t, messages, 1)
		assert.Equal(t, testMessage, string(messages[0]))

		require.NoError(t, reader.Close())
	})

	t.Run("LogMigration", func(t *testing.T) {
		sourceFile := filepath.Join(tempDir, "source.eaplog")
		targetFile := filepath.Join(tempDir, "target.eaplog")

		// Create source file (v1.0)
		writer := actuation.NewLogWriter(sourceFile, actuation.LogVersionV10, nil, nil, nil)
		require.NoError(t, writer.Open())

		testMessages := []string{
			`{"msg": 1}`,
			`{"msg": 2}`,
		}

		for _, msg := range testMessages {
			require.NoError(t, writer.WriteMessage([]byte(msg)))
		}
		require.NoError(t, writer.Close())

		// Migrate to v2.1
		migrator := actuation.NewLogMigrator()
		robotID := "migrated_robot"
		sessionID := "migrated_session"
		metadata := map[string]interface{}{"migrated": true}

		err := migrator.MigrateFile(sourceFile, targetFile, actuation.LogVersionV21, &robotID, &sessionID, metadata)
		require.NoError(t, err)

		// Verify target file
		reader := actuation.NewLogReader(targetFile)
		require.NoError(t, reader.Open())

		info, err := reader.GetInfo()
		require.NoError(t, err)
		assert.Equal(t, "2.1", info["version"])
		assert.Equal(t, &robotID, info["robot_id"])
		assert.Equal(t, &sessionID, info["session_id"])

		messages, err := reader.ReadMessages()
		require.NoError(t, err)
		assert.Len(t, messages, len(testMessages))

		require.NoError(t, reader.Close())
	})

	t.Run("LogValidation", func(t *testing.T) {
		validFile := filepath.Join(tempDir, "valid.eaplog")
		invalidFile := filepath.Join(tempDir, "invalid.eaplog")

		// Create valid file
		writer := actuation.NewLogWriter(validFile, actuation.LogVersionV21, nil, nil, nil)
		require.NoError(t, writer.Open())
		require.NoError(t, writer.WriteMessage([]byte(`{"valid": true}`)))
		require.NoError(t, writer.Close())

		// Create invalid file (corrupted)
		require.NoError(t, os.WriteFile(invalidFile, []byte("invalid data"), 0644))

		migrator := actuation.NewLogMigrator()

		// Valid file should pass
		err := migrator.ValidateFile(validFile)
		assert.NoError(t, err)

		// Invalid file should fail
		err = migrator.ValidateFile(invalidFile)
		assert.Error(t, err)
	})
}