// Package main provides protobuf fuzzing for ECPS-Go SDK
package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"google.golang.org/protobuf/proto"
	// Import generated protobuf messages
	// pb "github.com/ecps/ecps-go/proto"
)

// MockMessage represents a mock protobuf message for fuzzing
type MockMessage struct {
	data []byte
}

func (m *MockMessage) Reset()         {}
func (m *MockMessage) String() string { return fmt.Sprintf("MockMessage{%d bytes}", len(m.data)) }
func (m *MockMessage) ProtoMessage()  {}

// ProtobufFuzzer provides fuzzing capabilities for ECPS protobuf messages
type ProtobufFuzzer struct {
	stats map[string]int
}

// NewProtobufFuzzer creates a new protobuf fuzzer
func NewProtobufFuzzer() *ProtobufFuzzer {
	return &ProtobufFuzzer{
		stats: make(map[string]int),
	}
}

// FuzzMessageType fuzzes a specific message type with given data
func (f *ProtobufFuzzer) FuzzMessageType(messageType string, data []byte) map[string]interface{} {
	result := map[string]interface{}{
		"message_type": messageType,
		"input_size":   len(data),
		"success":      false,
		"error":        nil,
	}

	f.stats["total_inputs"]++

	defer func() {
		if r := recover(); r != nil {
			result["error"] = fmt.Sprintf("Panic: %v", r)
			result["exception_type"] = "panic"
			f.stats["crashes"]++
		}
	}()

	// Simulate parsing different message types
	switch messageType {
	case "MCP":
		err := f.fuzzMCPMessage(data)
		if err != nil {
			result["error"] = err.Error()
			f.stats["parse_errors"]++
		} else {
			result["success"] = true
			f.stats["successful_parses"]++
		}

	case "LTP":
		err := f.fuzzLTPMessage(data)
		if err != nil {
			result["error"] = err.Error()
			f.stats["parse_errors"]++
		} else {
			result["success"] = true
			f.stats["successful_parses"]++
		}

	case "EAP":
		err := f.fuzzEAPMessage(data)
		if err != nil {
			result["error"] = err.Error()
			f.stats["parse_errors"]++
		} else {
			result["success"] = true
			f.stats["successful_parses"]++
		}

	default:
		result["error"] = fmt.Sprintf("Unknown message type: %s", messageType)
		f.stats["parse_errors"]++
	}

	return result
}

// fuzzMCPMessage simulates fuzzing MCP message parsing
func (f *ProtobufFuzzer) fuzzMCPMessage(data []byte) error {
	// Simulate various parsing conditions
	if len(data) == 0 {
		return fmt.Errorf("empty message")
	}

	if bytes.HasPrefix(data, []byte{0xff, 0xff}) {
		return fmt.Errorf("invalid message format")
	}

	if len(data) > 16*1024 { // 16 KiB limit for MCP prompts
		return fmt.Errorf("message exceeds size limit")
	}

	// Simulate successful parsing for most inputs
	return nil
}

// fuzzLTPMessage simulates fuzzing LTP message parsing
func (f *ProtobufFuzzer) fuzzLTPMessage(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty message")
	}

	if len(data) > 1024*1024 { // 1 MiB limit for LTP frames
		return fmt.Errorf("frame exceeds size limit")
	}

	if bytes.Contains(data, []byte{0x00, 0x00, 0x00, 0x00}) {
		return fmt.Errorf("invalid field encoding")
	}

	return nil
}

// fuzzEAPMessage simulates fuzzing EAP message parsing
func (f *ProtobufFuzzer) fuzzEAPMessage(data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("empty message")
	}

	if len(data) < 32 { // Minimum size for state hash
		return fmt.Errorf("message too small")
	}

	return nil
}

// FuzzAllMessageTypes fuzzes all message types with the same data
func (f *ProtobufFuzzer) FuzzAllMessageTypes(data []byte) []map[string]interface{} {
	messageTypes := []string{"MCP", "LTP", "EAP"}
	results := make([]map[string]interface{}, 0, len(messageTypes))

	for _, msgType := range messageTypes {
		result := f.FuzzMessageType(msgType, data)
		results = append(results, result)
	}

	return results
}

// GenerateTestCases generates interesting test cases for fuzzing
func (f *ProtobufFuzzer) GenerateTestCases() [][]byte {
	testCases := [][]byte{
		// Empty message
		{},

		// Single bytes
		{0x00},
		{0xff},
		{0x01},

		// Common protobuf patterns
		{0x08, 0x96, 0x01}, // varint
		{0x12, 0x04, 't', 'e', 's', 't'}, // length-delimited
		{0x1a, 0x00}, // empty string

		// Invalid patterns
		{0xff, 0xff, 0xff, 0xff}, // Invalid start
		{0x00, 0x00, 0x00, 0x00}, // Null bytes
		{0x12, 0xff, 0xff, 0xff, 0xff}, // Invalid length

		// Nested messages
		{0x1a, 0x08, 0x08, 0x01, 0x12, 0x04, 't', 'e', 's', 't'},

		// Repeated fields
		{0x08, 0x01, 0x08, 0x02, 0x08, 0x03},
	}

	// Add large messages
	largeString := make([]byte, 1000)
	for i := range largeString {
		largeString[i] = 0xff
	}
	testCases = append(testCases, append([]byte{0x12}, largeString...))

	// Add random test cases
	for i := 0; i < 50; i++ {
		size := i * 20 // Variable sizes
		randomData := make([]byte, size)
		rand.Read(randomData)
		testCases = append(testCases, randomData)
	}

	return testCases
}

// GetStats returns fuzzing statistics
func (f *ProtobufFuzzer) GetStats() map[string]int {
	return f.stats
}

// RunStandaloneFuzzing runs standalone fuzzing without external tools
func RunStandaloneFuzzing() {
	fmt.Println("Running standalone protobuf fuzzing...")

	fuzzer := NewProtobufFuzzer()
	testCases := fuzzer.GenerateTestCases()

	fmt.Printf("Testing %d cases...\n", len(testCases))

	for i, testCase := range testCases {
		if i%20 == 0 {
			fmt.Printf("Progress: %d/%d\n", i, len(testCases))
		}

		results := fuzzer.FuzzAllMessageTypes(testCase)

		// Check for interesting results
		for _, result := range results {
			if errorMsg, ok := result["error"].(string); ok {
				if errorMsg != "" {
					fmt.Printf("Interesting result: %v\n", result)
				}
			}
		}
	}

	// Print statistics
	fmt.Println("\nFuzzing Statistics:")
	stats := fuzzer.GetStats()
	for key, value := range stats {
		fmt.Printf("  %s: %d\n", key, value)
	}

	if totalInputs := stats["total_inputs"]; totalInputs > 0 {
		successRate := float64(stats["successful_parses"]) / float64(totalInputs) * 100
		fmt.Printf("  success_rate: %.2f%%\n", successRate)
	}
}

// CreateLibFuzzerHarness creates a libFuzzer harness for C++ fuzzing
func CreateLibFuzzerHarness() {
	harnessCode := `// libFuzzer harness for ECPS protobuf fuzzing
#include <cstdint>
#include <cstddef>
#include <string>
#include "ecps.pb.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::string input(reinterpret_cast<const char*>(data), size);
    
    // Test MCP parsing
    ecps::MCP mcp;
    mcp.ParseFromString(input);
    
    // Test LTP parsing
    ecps::LTP ltp;
    ltp.ParseFromString(input);
    
    // Test EAP parsing
    ecps::EAP eap;
    eap.ParseFromString(input);
    
    // Test QueryReq parsing
    ecps::QueryReq query;
    query.ParseFromString(input);
    
    return 0;
}
`

	err := os.WriteFile("libfuzzer_harness.cpp", []byte(harnessCode), 0644)
	if err != nil {
		log.Printf("Failed to create libFuzzer harness: %v", err)
		return
	}

	fmt.Println("libFuzzer harness created: libfuzzer_harness.cpp")

	// Create build script
	buildScript := `#!/bin/bash
# Build script for libFuzzer harness

# Compile protobuf definitions
protoc --cpp_out=. ../proto/ecps.proto

# Compile fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address -I. \
    libfuzzer_harness.cpp ecps.pb.cc \
    -lprotobuf -o ecps_protobuf_fuzzer

echo "Fuzzer built: ecps_protobuf_fuzzer"
echo "Run with: ./ecps_protobuf_fuzzer"
`

	err = os.WriteFile("build_libfuzzer.sh", []byte(buildScript), 0755)
	if err != nil {
		log.Printf("Failed to create build script: %v", err)
		return
	}

	fmt.Println("Build script created: build_libfuzzer.sh")
}

// GoFuzzTarget provides a target function for go-fuzz
func GoFuzzTarget(data []byte) int {
	fuzzer := NewProtobufFuzzer()
	results := fuzzer.FuzzAllMessageTypes(data)

	// Return 1 if we find interesting behavior
	for _, result := range results {
		if errorMsg, ok := result["error"].(string); ok {
			if errorMsg != "" {
				return 1 // Interesting input
			}
		}
	}

	return 0 // Normal input
}

func main() {
	var (
		mode = flag.String("mode", "standalone", "Fuzzing mode: standalone, libfuzzer, go-fuzz")
		help = flag.Bool("help", false, "Show help message")
	)
	flag.Parse()

	if *help {
		fmt.Println("ECPS Go Protobuf Fuzzer")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  -mode standalone  Run standalone fuzzing")
		fmt.Println("  -mode libfuzzer   Generate libFuzzer harness")
		fmt.Println("  -mode go-fuzz     Run with go-fuzz")
		fmt.Println("  -help             Show this help")
		fmt.Println()
		fmt.Println("Examples:")
		fmt.Println("  go run main.go -mode standalone")
		fmt.Println("  go run main.go -mode libfuzzer")
		fmt.Println("  go-fuzz-build && go-fuzz -bin=./fuzz-fuzz.zip -workdir=workdir")
		return
	}

	switch *mode {
	case "standalone":
		RunStandaloneFuzzing()

	case "libfuzzer":
		CreateLibFuzzerHarness()

	case "go-fuzz":
		fmt.Println("Use go-fuzz-build and go-fuzz to run fuzzing")
		fmt.Println("Example:")
		fmt.Println("  go-fuzz-build")
		fmt.Println("  go-fuzz -bin=./fuzz-fuzz.zip -workdir=workdir")

	default:
		fmt.Printf("Unknown mode: %s\n", *mode)
		fmt.Println("Use -help for usage information")
		os.Exit(1)
	}
}

// Fuzz is the entry point for go-fuzz
func Fuzz(data []byte) int {
	return GoFuzzTarget(data)
}