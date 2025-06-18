// Package tests provides unit tests for the ECPS Go SDK.
package tests

import (
	"testing"
	"github.com/ecps/ecps-go/pkg/cognition"
	"github.com/ecps/ecps-go/pkg/perception"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestMEPClientPutWithStrongConsistency(t *testing.T) {
	client := cognition.NewMEPClient(nil, nil, nil) // Mock transport and serializer
	tensor := []float32{1.0, 2.0, 3.0, 4.0}
	metadata := &cognition.MemoryEventMetadata{
		ContentType: "application/octet-stream",
	}

	success, message := client.Put(tensor, metadata, "test_frame", 1234567890, cognition.ConsistencyModelStrong)
	assert.True(t, success)
	assert.Equal(t, "Embedding stored successfully", message)
}

func TestMEPClientQueryWithEventualConsistency(t *testing.T) {
	client := cognition.NewMEPClient(nil, nil, nil) // Mock transport and serializer
	tensor := []float32{1.0, 2.0, 3.0, 4.0}
	client.Put(tensor, nil, "test_frame", 1234567890, cognition.ConsistencyModelEventual)

	results := client.Query(tensor, 1, 0.7, cognition.ConsistencyModelEventual)
	assert.NotEmpty(t, results)
}

func TestMEPClientPutWithEventualConsistency(t *testing.T) {
	client := cognition.NewMEPClient(nil, nil, nil) // Mock transport and serializer
	tensor := []float32{1.0, 2.0, 3.0, 4.0}
	metadata := &cognition.MemoryEventMetadata{
		ContentType: "application/octet-stream",
	}

	success, message := client.Put(tensor, metadata, "test_frame", 1234567890, cognition.ConsistencyModelEventual)
	assert.True(t, success)
	assert.Equal(t, "Embedding stored successfully", message)
}