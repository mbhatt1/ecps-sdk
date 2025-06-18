// Package observability provides telemetry functionality for ECPS.
package observability

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	metricexport "go.opentelemetry.io/otel/sdk/metric/metricexporter"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/ecps/ecps-go/pkg/core"
)

// ECPSTelemetry implements the Telemetry interface for OpenTelemetry.
type ECPSTelemetry struct {
	tracer          trace.Tracer
	tracerProvider  *sdktrace.TracerProvider
	meterProvider   metric.MeterProvider
	meter           metric.Meter
	propagator      propagation.TextMapPropagator
	logger          core.Logger
	serviceName     string
	otlpEndpoint    string
	
	// Metrics
	eapLatency         metric.Float64Histogram
	ltpFrameBytes      metric.Int64Histogram
	mcpPromptChars     metric.Int64Histogram
	mepQueryLatency    metric.Float64Histogram
	transportBytesSent metric.Int64Counter
	transportBytesRecv metric.Int64Counter
}

// NewTelemetry creates a new ECPSTelemetry instance.
func NewTelemetry(
	otlpEndpoint string,
	serviceName string,
	logger core.Logger,
) (*ECPSTelemetry, error) {
	if logger == nil {
		logger = core.NewDefaultLogger()
	}
	
	t := &ECPSTelemetry{
		otlpEndpoint: otlpEndpoint,
		serviceName:  serviceName,
		logger:       logger,
	}
	
	// Initialize OpenTelemetry
	if err := t.initOpenTelemetry(); err != nil {
		return nil, fmt.Errorf("failed to initialize OpenTelemetry: %w", err)
	}
	
	return t, nil
}

// initOpenTelemetry initializes OpenTelemetry components.
func (t *ECPSTelemetry) initOpenTelemetry() error {
	// Create resource
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(t.serviceName),
			semconv.ServiceVersionKey.String("1.0.0"),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Set up OTLP exporter
	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, t.otlpEndpoint, 
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return fmt.Errorf("failed to create gRPC connection to OTLP endpoint: %w", err)
	}

	traceExporter, err := otlptrace.New(ctx, otlptracegrpc.NewClient(
		otlptracegrpc.WithGRPCConn(conn),
	))
	if err != nil {
		return fmt.Errorf("failed to create trace exporter: %w", err)
	}

	// Create trace provider
	bsp := sdktrace.NewBatchSpanProcessor(traceExporter)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)
	otel.SetTracerProvider(tracerProvider)
	t.tracerProvider = tracerProvider

	// Set up propagator
	propagator := propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)
	otel.SetTextMapPropagator(propagator)
	t.propagator = propagator

	// Create tracer
	t.tracer = tracerProvider.Tracer(
		"github.com/ecps/ecps-go",
		trace.WithInstrumentationVersion("1.0.0"),
		trace.WithSchemaURL("https://ecps.io/schemas/1.0"),
	)

	// Create meter provider
	meterProvider := otel.GetMeterProvider()
	t.meterProvider = meterProvider

	// Create meter
	meter := meterProvider.Meter(
		"github.com/ecps/ecps-go",
		metric.WithInstrumentationVersion("1.0.0"),
		metric.WithSchemaURL("https://ecps.io/schemas/1.0"),
	)
	t.meter = meter

	// Create standard metrics
	return t.createStandardMetrics()
}

// createStandardMetrics creates standard metrics for ECPS operations.
func (t *ECPSTelemetry) createStandardMetrics() error {
	var err error

	// EAP latency
	t.eapLatency, err = t.meter.Float64Histogram(
		"eap.latency_ms",
		metric.WithDescription("Latency of action execution in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return fmt.Errorf("failed to create eap.latency_ms: %w", err)
	}

	// LTP frame size
	t.ltpFrameBytes, err = t.meter.Int64Histogram(
		"ltp.frame_bytes",
		metric.WithDescription("Size of LTP frames in bytes"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return fmt.Errorf("failed to create ltp.frame_bytes: %w", err)
	}

	// MCP prompt size
	t.mcpPromptChars, err = t.meter.Int64Histogram(
		"mcp.prompt_chars",
		metric.WithDescription("Length of MCP prompts in characters"),
		metric.WithUnit("chars"),
	)
	if err != nil {
		return fmt.Errorf("failed to create mcp.prompt_chars: %w", err)
	}

	// MEP query latency
	t.mepQueryLatency, err = t.meter.Float64Histogram(
		"mep.query_latency_ms",
		metric.WithDescription("Latency of memory queries in milliseconds"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		return fmt.Errorf("failed to create mep.query_latency_ms: %w", err)
	}

	// Transport bytes sent
	t.transportBytesSent, err = t.meter.Int64Counter(
		"transport.bytes_sent",
		metric.WithDescription("Number of bytes sent over transport"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return fmt.Errorf("failed to create transport.bytes_sent: %w", err)
	}

	// Transport bytes received
	t.transportBytesRecv, err = t.meter.Int64Counter(
		"transport.bytes_received",
		metric.WithDescription("Number of bytes received over transport"),
		metric.WithUnit("bytes"),
	)
	if err != nil {
		return fmt.Errorf("failed to create transport.bytes_received: %w", err)
	}

	return nil
}

// Tracer returns the OpenTelemetry tracer.
func (t *ECPSTelemetry) Tracer() trace.Tracer {
	return t.tracer
}

// CreateSpan creates a new span for tracing.
func (t *ECPSTelemetry) CreateSpan(
	ctx context.Context,
	name string,
	kind trace.SpanKind,
	attrs map[string]interface{},
) (context.Context, trace.Span) {
	// Convert attributes
	attributes := make([]attribute.KeyValue, 0, len(attrs))
	for k, v := range attrs {
		attributes = append(attributes, attribute.String(k, fmt.Sprintf("%v", v)))
	}

	// Start span
	ctx, span := t.tracer.Start(
		ctx,
		name,
		trace.WithSpanKind(kind),
		trace.WithAttributes(attributes...),
	)

	return ctx, span
}

// RecordEAPLatency records EAP action execution latency.
func (t *ECPSTelemetry) RecordEAPLatency(latencyMs float64, attrs map[string]string) {
	if t.eapLatency != nil {
		// Convert attributes
		attributes := make([]attribute.KeyValue, 0, len(attrs))
		for k, v := range attrs {
			attributes = append(attributes, attribute.String(k, v))
		}

		t.eapLatency.Record(context.Background(), latencyMs, metric.WithAttributes(attributes...))
	}
}

// RecordLTPFrameSize records LTP frame size.
func (t *ECPSTelemetry) RecordLTPFrameSize(sizeBytes int, attrs map[string]string) {
	if t.ltpFrameBytes != nil {
		// Convert attributes
		attributes := make([]attribute.KeyValue, 0, len(attrs))
		for k, v := range attrs {
			attributes = append(attributes, attribute.String(k, v))
		}

		t.ltpFrameBytes.Record(context.Background(), int64(sizeBytes), metric.WithAttributes(attributes...))
	}
}

// RecordMCPPromptSize records MCP prompt size.
func (t *ECPSTelemetry) RecordMCPPromptSize(chars int, attrs map[string]string) {
	if t.mcpPromptChars != nil {
		// Convert attributes
		attributes := make([]attribute.KeyValue, 0, len(attrs))
		for k, v := range attrs {
			attributes = append(attributes, attribute.String(k, v))
		}

		t.mcpPromptChars.Record(context.Background(), int64(chars), metric.WithAttributes(attributes...))
	}
}

// RecordMEPQueryLatency records MEP query latency.
func (t *ECPSTelemetry) RecordMEPQueryLatency(latencyMs float64, attrs map[string]string) {
	if t.mepQueryLatency != nil {
		// Convert attributes
		attributes := make([]attribute.KeyValue, 0, len(attrs))
		for k, v := range attrs {
			attributes = append(attributes, attribute.String(k, v))
		}

		t.mepQueryLatency.Record(context.Background(), latencyMs, metric.WithAttributes(attributes...))
	}
}

// RecordBytesSent records bytes sent over transport.
func (t *ECPSTelemetry) RecordBytesSent(bytesCount int, transportType string, attrs map[string]string) {
	if t.transportBytesSent != nil {
		// Add transport type to attributes
		if attrs == nil {
			attrs = make(map[string]string)
		}
		attrs["transport_type"] = transportType

		// Convert attributes
		attributes := make([]attribute.KeyValue, 0, len(attrs))
		for k, v := range attrs {
			attributes = append(attributes, attribute.String(k, v))
		}

		t.transportBytesSent.Add(context.Background(), int64(bytesCount), metric.WithAttributes(attributes...))
	}
}

// RecordBytesReceived records bytes received over transport.
func (t *ECPSTelemetry) RecordBytesReceived(bytesCount int, transportType string, attrs map[string]string) {
	if t.transportBytesRecv != nil {
		// Add transport type to attributes
		if attrs == nil {
			attrs = make(map[string]string)
		}
		attrs["transport_type"] = transportType

		// Convert attributes
		attributes := make([]attribute.KeyValue, 0, len(attrs))
		for k, v := range attrs {
			attributes = append(attributes, attribute.String(k, v))
		}

		t.transportBytesRecv.Add(context.Background(), int64(bytesCount), metric.WithAttributes(attributes...))
	}
}

// InjectContext injects trace context into headers.
func (t *ECPSTelemetry) InjectContext(ctx context.Context, headers map[string]string) map[string]string {
	if headers == nil {
		headers = make(map[string]string)
	}

	// Create a carrier to inject context into
	carrier := propagation.MapCarrier{}
	t.propagator.Inject(ctx, carrier)

	// Copy to headers
	for k, v := range carrier {
		headers[k] = v
	}

	return headers
}

// ExtractContext extracts trace context from headers.
func (t *ECPSTelemetry) ExtractContext(ctx context.Context, headers map[string]string) context.Context {
	// Create a carrier from headers
	carrier := propagation.MapCarrier{}
	for k, v := range headers {
		carrier[k] = v
	}

	// Extract context
	return t.propagator.Extract(ctx, carrier)
}

// Shutdown shuts down telemetry providers and exporters.
func (t *ECPSTelemetry) Shutdown(ctx context.Context) error {
	// Shutdown tracer provider
	if t.tracerProvider != nil {
		if err := t.tracerProvider.Shutdown(ctx); err != nil {
			return fmt.Errorf("failed to shutdown tracer provider: %w", err)
		}
	}

	return nil
}

// WithSpan runs a function within a new span.
func (t *ECPSTelemetry) WithSpan(
	ctx context.Context,
	name string,
	kind trace.SpanKind,
	attrs map[string]interface{},
	fn func(context.Context) error,
) error {
	ctx, span := t.CreateSpan(ctx, name, kind, attrs)
	defer span.End()

	err := fn(ctx)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(trace.StatusCodeError, err.Error())
	}

	return err
}

// FormatAttributes formats attributes for logging.
func (t *ECPSTelemetry) FormatAttributes(attrs map[string]interface{}) string {
	if len(attrs) == 0 {
		return ""
	}

	result := "{"
	first := true
	for k, v := range attrs {
		if !first {
			result += ", "
		}
		result += fmt.Sprintf("%s=%v", k, v)
		first = false
	}
	result += "}"

	return result
}