// Package perception provides implementations for the Perception Data Layer (L5).
package perception

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/klauspost/compress/zstd"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	"github.com/ecps/ecps-go/pkg/core"
	pb "github.com/ecps/ecps-go/proto"
)

// LTPHandler handles Latent Tensor Protocol (LTP) messages.
type LTPHandler struct {
	transport      core.Transport
	serializer     core.Serializer
	telemetry      core.Telemetry
	logger         core.Logger
	compressor     *zstd.Encoder
	decompressor   *zstd.Decoder
	compressionLvl int
	maxSizeBytes   int
}

// NewLTPHandler creates a new LTPHandler.
func NewLTPHandler(
	transport core.Transport,
	serializer core.Serializer,
	telemetry core.Telemetry,
	logger core.Logger,
	options ...LTPOption,
) (*LTPHandler, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}

	// Default configuration
	handler := &LTPHandler{
		transport:      transport,
		serializer:     serializer,
		telemetry:      telemetry,
		logger:         logger,
		compressionLvl: 3,        // Default compression level
		maxSizeBytes:   1024*1024, // Default max size: 1 MiB
	}

	// Apply options
	for _, opt := range options {
		opt(handler)
	}

	// Create zstd compressor
	var err error
	handler.compressor, err = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.EncoderLevel(handler.compressionLvl)))
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd compressor: %w", err)
	}

	// Create zstd decompressor
	handler.decompressor, err = zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create zstd decompressor: %w", err)
	}

	return handler, nil
}

// LTPOption is a function that configures an LTPHandler.
type LTPOption func(*LTPHandler)

// WithCompressionLevel sets the zstd compression level (1-22).
func WithCompressionLevel(level int) LTPOption {
	return func(h *LTPHandler) {
		h.compressionLvl = level
	}
}

// WithMaxSizeBytes sets the maximum size of LTP frames in bytes.
func WithMaxSizeBytes(maxSize int) LTPOption {
	return func(h *LTPHandler) {
		h.maxSizeBytes = maxSize
	}
}

// DType represents the data type of tensor elements.
type DType string

const (
	// DTypeFloat32 represents 32-bit floating point.
	DTypeFloat32 DType = "f32"
	// DTypeFloat16 represents 16-bit floating point.
	DTypeFloat16 DType = "f16"
	// DTypeFloat64 represents 64-bit floating point.
	DTypeFloat64 DType = "f64"
	// DTypeUint8 represents 8-bit unsigned integer.
	DTypeUint8 DType = "u8"
	// DTypeUint16 represents 16-bit unsigned integer.
	DTypeUint16 DType = "u16"
	// DTypeUint32 represents 32-bit unsigned integer.
	DTypeUint32 DType = "u32"
	// DTypeUint64 represents 64-bit unsigned integer.
	DTypeUint64 DType = "u64"
	// DTypeInt8 represents 8-bit signed integer.
	DTypeInt8 DType = "i8"
	// DTypeInt16 represents 16-bit signed integer.
	DTypeInt16 DType = "i16"
	// DTypeInt32 represents 32-bit signed integer.
	DTypeInt32 DType = "i32"
	// DTypeInt64 represents 64-bit signed integer.
	DTypeInt64 DType = "i64"
	// DTypeBool represents boolean.
	DTypeBool DType = "bool"
)

// Tensor represents a multi-dimensional array of elements.
type Tensor struct {
	// Data is the raw tensor data.
	Data []byte
	// Shape is the shape of the tensor (e.g., [B,L,D]).
	Shape []uint32
	// DType is the data type of tensor elements.
	DType DType
	// FrameID is the reference coordinate frame.
	FrameID string
	// TimestampNS is the timestamp in nanoseconds since Unix epoch.
	TimestampNS uint64
}

// BytesPerElement returns the number of bytes per element for a given data type.
func BytesPerElement(dtype DType) int {
	switch dtype {
	case DTypeFloat32:
		return 4
	case DTypeFloat16:
		return 2
	case DTypeFloat64:
		return 8
	case DTypeUint8, DTypeInt8, DTypeBool:
		return 1
	case DTypeUint16, DTypeInt16:
		return 2
	case DTypeUint32, DTypeInt32:
		return 4
	case DTypeUint64, DTypeInt64:
		return 8
	default:
		return 0
	}
}

// SizeInBytes calculates the size of the tensor in bytes.
func (t *Tensor) SizeInBytes() int {
	if t.Data != nil {
		return len(t.Data)
	}

	// Calculate size based on shape and data type
	elemSize := BytesPerElement(t.DType)
	if elemSize == 0 {
		return 0
	}

	// Calculate number of elements
	numElem := 1
	for _, dim := range t.Shape {
		numElem *= int(dim)
	}

	return numElem * elemSize
}

// CreateLTPMessage creates an LTP message from a tensor.
func (h *LTPHandler) CreateLTPMessage(tensor *Tensor) (*pb.LTP, error) {
	if tensor == nil {
		return nil, errors.New("tensor cannot be nil")
	}

	// Check if data needs compression
	var tensorZstd []byte
	if len(tensor.Data) > 0 {
		// Compress tensor data
		tensorZstd = h.compressor.EncodeAll(tensor.Data, nil)

		// Check size
		if len(tensorZstd) > h.maxSizeBytes {
			h.logger.Warn(
				"Compressed tensor size (%d bytes) exceeds max size (%d bytes)",
				len(tensorZstd),
				h.maxSizeBytes,
			)
		}
	}

	// Create LTP message
	ltp := &pb.LTP{
		Spec:        "ltp/0.9",
		TensorZstd:  tensorZstd,
		Shape:       tensor.Shape,
		Dtype:       string(tensor.DType),
		FrameId:     tensor.FrameID,
		TimestampNs: tensor.TimestampNS,
	}

	// Record metrics if telemetry is available
	if h.telemetry != nil {
		h.telemetry.RecordLTPFrameSize(len(tensorZstd), map[string]string{
			"frame_id":        tensor.FrameID,
			"dtype":           string(tensor.DType),
			"shape":           fmt.Sprintf("%v", tensor.Shape),
			"original_size":   fmt.Sprintf("%d", len(tensor.Data)),
			"compression_ratio": fmt.Sprintf("%.2f", float64(len(tensor.Data))/float64(len(tensorZstd))),
		})
	}

	return ltp, nil
}

// ExtractTensor extracts a tensor from an LTP message.
func (h *LTPHandler) ExtractTensor(ltpMessage *pb.LTP) (*Tensor, map[string]string, error) {
	if ltpMessage == nil {
		return nil, nil, errors.New("LTP message cannot be nil")
	}

	// Decompress tensor data
	var tensorData []byte
	if len(ltpMessage.TensorZstd) > 0 {
		var err error
		tensorData, err = h.decompressor.DecodeAll(ltpMessage.TensorZstd, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress tensor data: %w", err)
		}
	}

	// Create tensor
	tensor := &Tensor{
		Data:        tensorData,
		Shape:       ltpMessage.Shape,
		DType:       DType(ltpMessage.Dtype),
		FrameID:     ltpMessage.FrameId,
		TimestampNS: ltpMessage.TimestampNs,
	}

	// Extract metadata
	metadata := map[string]string{
		"frame_id":     ltpMessage.FrameId,
		"timestamp_ns": fmt.Sprintf("%d", ltpMessage.TimestampNs),
		"dtype":        ltpMessage.Dtype,
		"shape":        fmt.Sprintf("%v", ltpMessage.Shape),
	}

	return tensor, metadata, nil
}

// Send sends a tensor as an LTP message.
func (h *LTPHandler) Send(
	ctx context.Context,
	topic string,
	tensor *Tensor,
	qos map[string]interface{},
) (string, error) {
	// Create a span if telemetry is available
	var spanCtx context.Context
	var span trace.Span
	if h.telemetry != nil {
		spanCtx, span = h.telemetry.CreateSpan(ctx, "ltp.send", trace.SpanKindProducer, map[string]interface{}{
			"topic":    topic,
			"frame_id": tensor.FrameID,
			"dtype":    string(tensor.DType),
			"shape":    fmt.Sprintf("%v", tensor.Shape),
		})
		defer span.End()
		ctx = spanCtx
	}

	// Create LTP message
	ltp, err := h.CreateLTPMessage(tensor)
	if err != nil {
		return "", fmt.Errorf("failed to create LTP message: %w", err)
	}

	// Publish message
	if err := h.transport.Publish(ctx, topic, ltp, qos); err != nil {
		return "", fmt.Errorf("failed to publish LTP message: %w", err)
	}

	// Return message ID (if available)
	return ltp.Id, nil
}

// Receive subscribes to LTP messages and processes them.
func (h *LTPHandler) Receive(
	ctx context.Context,
	topic string,
	handler func(context.Context, *Tensor, map[string]string) error,
	qos map[string]interface{},
) error {
	// Define message handler
	ltpHandler := func(ctx context.Context, ltpMessage *pb.LTP) error {
		// Create a span if telemetry is available
		var spanCtx context.Context
		var span trace.Span
		startTime := time.Now()
		if h.telemetry != nil {
			spanCtx, span = h.telemetry.CreateSpan(ctx, "ltp.receive", trace.SpanKindConsumer, map[string]interface{}{
				"topic":    topic,
				"frame_id": ltpMessage.FrameId,
				"dtype":    ltpMessage.Dtype,
				"shape":    fmt.Sprintf("%v", ltpMessage.Shape),
			})
			defer span.End()
			ctx = spanCtx
		}

		// Extract tensor and metadata
		tensor, metadata, err := h.ExtractTensor(ltpMessage)
		if err != nil {
			h.logger.Error("Failed to extract tensor: %v", err)
			return err
		}

		// Call user handler
		if err := handler(ctx, tensor, metadata); err != nil {
			h.logger.Error("Error handling LTP message: %v", err)
			return err
		}

		return nil
	}

	// Subscribe to topic
	return h.transport.Subscribe(ctx, topic, &pb.LTP{}, ltpHandler, qos)
}

// SplitLargeTensor splits a large tensor into smaller chunks that fit within size limits.
func (h *LTPHandler) SplitLargeTensor(tensor *Tensor, maxSize int, axis int) ([]*Tensor, error) {
	if tensor == nil {
		return nil, errors.New("tensor cannot be nil")
	}

	// Use handler's max size if not specified
	if maxSize <= 0 {
		maxSize = h.maxSizeBytes
	}

	// Check if tensor shape is valid
	if len(tensor.Shape) == 0 {
		return nil, errors.New("tensor shape cannot be empty")
	}

	// Check if axis is valid
	if axis < 0 || axis >= len(tensor.Shape) {
		return nil, fmt.Errorf("invalid axis: %d (shape has %d dimensions)", axis, len(tensor.Shape))
	}

	// If tensor data is not provided, we can't split it
	if tensor.Data == nil {
		return []*Tensor{tensor}, nil
	}

	// Estimate compression ratio by compressing a sample
	sampleSize := min(1024*1024, len(tensor.Data))
	sample := tensor.Data[:sampleSize]
	compressedSample := h.compressor.EncodeAll(sample, nil)
	compressionRatio := float64(len(sample)) / float64(len(compressedSample))

	// Estimate max chunk size in original bytes
	maxChunkBytes := float64(maxSize) * compressionRatio * 0.9 // Add safety margin

	// Calculate bytes per element
	bytesPerElem := BytesPerElement(tensor.DType)
	if bytesPerElem <= 0 {
		return nil, fmt.Errorf("unknown data type: %s", tensor.DType)
	}

	// Calculate number of elements per chunk
	elemsPerChunk := int(maxChunkBytes) / bytesPerElem

	// If tensor is already small enough, return as is
	if len(tensor.Data) <= int(maxChunkBytes) {
		return []*Tensor{tensor}, nil
	}

	// Calculate total elements and elements per chunk
	totalElems := 1
	for _, dim := range tensor.Shape {
		totalElems *= int(dim)
	}

	// Calculate elements along the specified axis
	axisElems := int(tensor.Shape[axis])
	otherElems := totalElems / axisElems

	// Calculate elements per chunk along the specified axis
	elemsPerChunkAlongAxis := max(1, elemsPerChunk/otherElems)

	// Create chunks
	chunks := make([]*Tensor, 0)
	for i := 0; i < axisElems; i += elemsPerChunkAlongAxis {
		// Calculate end index (clamped to axis size)
		end := min(i+elemsPerChunkAlongAxis, axisElems)

		// Create new shape for the chunk
		chunkShape := make([]uint32, len(tensor.Shape))
		copy(chunkShape, tensor.Shape)
		chunkShape[axis] = uint32(end - i)

		// Extract chunk data
		// Note: In a real implementation, this would be more complex and would
		// handle proper slicing of multi-dimensional arrays
		// This is a simplified version that assumes contiguous memory layout
		startIdx := i * otherElems * bytesPerElem
		endIdx := end * otherElems * bytesPerElem
		chunkData := tensor.Data[startIdx:endIdx]

		// Create chunk tensor
		chunk := &Tensor{
			Data:        chunkData,
			Shape:       chunkShape,
			DType:       tensor.DType,
			FrameID:     tensor.FrameID,
			TimestampNS: tensor.TimestampNS,
		}

		chunks = append(chunks, chunk)
	}

	return chunks, nil
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Helper function for max
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Close releases resources used by the LTPHandler.
func (h *LTPHandler) Close() error {
	if h.compressor != nil {
		h.compressor.Close()
	}
	if h.decompressor != nil {
		h.decompressor.Close()
	}
	return nil
}