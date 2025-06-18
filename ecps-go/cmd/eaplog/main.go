// Package main provides a command-line tool for managing EAP log files.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ecps/ecps-go/pkg/actuation"
)

const (
	toolVersion = "1.0.0"
	toolName    = "eaplog"
)

// Command represents a CLI command
type Command struct {
	Name        string
	Description string
	Handler     func(args []string) error
}

// CLI represents the command-line interface
type CLI struct {
	commands map[string]*Command
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	cli := &CLI{
		commands: make(map[string]*Command),
	}
	
	// Register commands
	cli.registerCommand("info", "Display information about a log file", cli.handleInfo)
	cli.registerCommand("validate", "Validate the integrity of a log file", cli.handleValidate)
	cli.registerCommand("migrate", "Migrate a log file to a different version", cli.handleMigrate)
	cli.registerCommand("list", "List messages in a log file", cli.handleList)
	cli.registerCommand("create", "Create a new versioned log file", cli.handleCreate)
	cli.registerCommand("help", "Show help information", cli.handleHelp)
	cli.registerCommand("version", "Show version information", cli.handleVersion)
	
	return cli
}

// registerCommand registers a new command
func (c *CLI) registerCommand(name, description string, handler func(args []string) error) {
	c.commands[name] = &Command{
		Name:        name,
		Description: description,
		Handler:     handler,
	}
}

// Run executes the CLI with the given arguments
func (c *CLI) Run(args []string) error {
	if len(args) < 1 {
		return c.handleHelp(args)
	}
	
	commandName := args[0]
	command, exists := c.commands[commandName]
	if !exists {
		return fmt.Errorf("unknown command: %s", commandName)
	}
	
	return command.Handler(args[1:])
}

// handleInfo displays information about a log file
func (c *CLI) handleInfo(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s info <log_file>", toolName)
	}
	
	logFile := args[0]
	reader := actuation.NewLogReader(logFile)
	
	if err := reader.Open(); err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer reader.Close()
	
	info, err := reader.GetInfo()
	if err != nil {
		return fmt.Errorf("failed to get log info: %w", err)
	}
	
	// Pretty print the information
	infoJSON, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal info: %w", err)
	}
	
	fmt.Printf("Log File Information:\n%s\n", string(infoJSON))
	return nil
}

// handleValidate validates the integrity of a log file
func (c *CLI) handleValidate(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: %s validate <log_file>", toolName)
	}
	
	logFile := args[0]
	migrator := actuation.NewLogMigrator()
	
	if err := migrator.ValidateFile(logFile); err != nil {
		fmt.Printf("Validation FAILED: %v\n", err)
		return err
	}
	
	fmt.Printf("Validation PASSED: %s\n", logFile)
	return nil
}

// handleMigrate migrates a log file to a different version
func (c *CLI) handleMigrate(args []string) error {
	var (
		sourceFile    string
		targetFile    string
		targetVersion string
		robotID       string
		sessionID     string
		metadataStr   string
	)
	
	// Parse flags
	flagSet := flag.NewFlagSet("migrate", flag.ExitOnError)
	flagSet.StringVar(&sourceFile, "source", "", "Source log file")
	flagSet.StringVar(&targetFile, "target", "", "Target log file")
	flagSet.StringVar(&targetVersion, "version", "2.1", "Target version (1.0, 1.1, 2.0, 2.1)")
	flagSet.StringVar(&robotID, "robot-id", "", "Robot ID for the new log file")
	flagSet.StringVar(&sessionID, "session-id", "", "Session ID for the new log file")
	flagSet.StringVar(&metadataStr, "metadata", "{}", "Metadata as JSON string")
	
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	
	if sourceFile == "" || targetFile == "" {
		return fmt.Errorf("usage: %s migrate -source <source_file> -target <target_file> [options]", toolName)
	}
	
	// Parse target version
	version, err := actuation.LogVersionFromString(targetVersion)
	if err != nil {
		return fmt.Errorf("invalid target version: %w", err)
	}
	
	// Parse metadata
	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
		return fmt.Errorf("invalid metadata JSON: %w", err)
	}
	
	// Prepare optional parameters
	var robotIDPtr, sessionIDPtr *string
	if robotID != "" {
		robotIDPtr = &robotID
	}
	if sessionID != "" {
		sessionIDPtr = &sessionID
	}
	
	// Perform migration
	migrator := actuation.NewLogMigrator()
	if err := migrator.MigrateFile(sourceFile, targetFile, version, robotIDPtr, sessionIDPtr, metadata); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}
	
	fmt.Printf("Successfully migrated %s to %s (version %s)\n", sourceFile, targetFile, targetVersion)
	return nil
}

// handleList lists messages in a log file
func (c *CLI) handleList(args []string) error {
	var (
		logFile   string
		maxCount  int
		showBytes bool
	)
	
	// Parse flags
	flagSet := flag.NewFlagSet("list", flag.ExitOnError)
	flagSet.StringVar(&logFile, "file", "", "Log file to list")
	flagSet.IntVar(&maxCount, "max", 10, "Maximum number of messages to show")
	flagSet.BoolVar(&showBytes, "bytes", false, "Show raw message bytes")
	
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	
	if logFile == "" {
		return fmt.Errorf("usage: %s list -file <log_file> [options]", toolName)
	}
	
	reader := actuation.NewLogReader(logFile)
	if err := reader.Open(); err != nil {
		return fmt.Errorf("failed to open log file: %w", err)
	}
	defer reader.Close()
	
	messages, err := reader.ReadMessages()
	if err != nil {
		return fmt.Errorf("failed to read messages: %w", err)
	}
	
	fmt.Printf("Found %d messages in %s\n", len(messages), logFile)
	
	count := len(messages)
	if maxCount > 0 && maxCount < count {
		count = maxCount
	}
	
	for i := 0; i < count; i++ {
		fmt.Printf("\nMessage %d (size: %d bytes):\n", i+1, len(messages[i]))
		
		if showBytes {
			fmt.Printf("Raw bytes: %x\n", messages[i])
		} else {
			// Try to display as text if possible
			if isPrintable(messages[i]) {
				fmt.Printf("Content: %s\n", string(messages[i]))
			} else {
				fmt.Printf("Binary content (use -bytes to see raw data)\n")
			}
		}
	}
	
	if maxCount > 0 && len(messages) > maxCount {
		fmt.Printf("\n... and %d more messages (use -max 0 to see all)\n", len(messages)-maxCount)
	}
	
	return nil
}

// handleCreate creates a new versioned log file
func (c *CLI) handleCreate(args []string) error {
	var (
		logFile     string
		version     string
		robotID     string
		sessionID   string
		metadataStr string
	)
	
	// Parse flags
	flagSet := flag.NewFlagSet("create", flag.ExitOnError)
	flagSet.StringVar(&logFile, "file", "", "Log file to create")
	flagSet.StringVar(&version, "version", "2.1", "Log version (1.0, 1.1, 2.0, 2.1)")
	flagSet.StringVar(&robotID, "robot-id", "", "Robot ID")
	flagSet.StringVar(&sessionID, "session-id", "", "Session ID")
	flagSet.StringVar(&metadataStr, "metadata", "{}", "Metadata as JSON string")
	
	if err := flagSet.Parse(args); err != nil {
		return err
	}
	
	if logFile == "" {
		return fmt.Errorf("usage: %s create -file <log_file> [options]", toolName)
	}
	
	// Parse version
	logVersion, err := actuation.LogVersionFromString(version)
	if err != nil {
		return fmt.Errorf("invalid version: %w", err)
	}
	
	// Parse metadata
	var metadata map[string]interface{}
	if err := json.Unmarshal([]byte(metadataStr), &metadata); err != nil {
		return fmt.Errorf("invalid metadata JSON: %w", err)
	}
	
	// Prepare optional parameters
	var robotIDPtr, sessionIDPtr *string
	if robotID != "" {
		robotIDPtr = &robotID
	}
	if sessionID != "" {
		sessionIDPtr = &sessionID
	}
	
	// Create log file
	writer := actuation.NewLogWriter(logFile, logVersion, robotIDPtr, sessionIDPtr, metadata)
	if err := writer.Open(); err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}
	defer writer.Close()
	
	fmt.Printf("Successfully created log file: %s (version %s)\n", logFile, version)
	return nil
}

// handleHelp shows help information
func (c *CLI) handleHelp(args []string) error {
	fmt.Printf("%s - EAP Log Management Tool v%s\n\n", toolName, toolVersion)
	fmt.Printf("Usage: %s <command> [options]\n\n", toolName)
	fmt.Printf("Commands:\n")
	
	for name, command := range c.commands {
		fmt.Printf("  %-10s %s\n", name, command.Description)
	}
	
	fmt.Printf("\nExamples:\n")
	fmt.Printf("  %s info mylog.eaplog\n", toolName)
	fmt.Printf("  %s validate mylog.eaplog\n", toolName)
	fmt.Printf("  %s migrate -source old.eaplog -target new.eaplog -version 2.1\n", toolName)
	fmt.Printf("  %s list -file mylog.eaplog -max 5\n", toolName)
	fmt.Printf("  %s create -file new.eaplog -version 2.1 -robot-id robot1\n", toolName)
	
	return nil
}

// handleVersion shows version information
func (c *CLI) handleVersion(args []string) error {
	fmt.Printf("%s version %s\n", toolName, toolVersion)
	fmt.Printf("EAP Log Management Tool for ECPS-UV SDK\n")
	return nil
}

// isPrintable checks if bytes contain printable text
func isPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	
	for _, b := range data {
		if b < 32 || b > 126 {
			// Allow common whitespace characters
			if b != '\n' && b != '\r' && b != '\t' && b != ' ' {
				return false
			}
		}
	}
	return true
}

// findLogFiles finds .eaplog files in the current directory
func findLogFiles() ([]string, error) {
	var logFiles []string
	
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(strings.ToLower(path), ".eaplog") {
			logFiles = append(logFiles, path)
		}
		
		return nil
	})
	
	return logFiles, err
}

func main() {
	cli := NewCLI()
	
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}