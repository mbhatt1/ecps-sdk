"""
OpenTelemetry integration for ECPS.

This module provides telemetry integration using OpenTelemetry (OTLP),
including traces, metrics, and logs for comprehensive monitoring and debugging.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Union

import uv

# OpenTelemetry imports
from opentelemetry import trace, metrics
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.context import Context, get_current

logger = logging.getLogger("ecps_uv.observability.telemetry")


class ECPSTelemetry:
    """
    Telemetry integration for ECPS using OpenTelemetry.
    
    This class provides a unified interface for collecting telemetry data
    (traces, metrics, logs) from all components within the ECPS ecosystem.
    """
    
    def __init__(
        self,
        otlp_endpoint: Optional[str] = None,
        service_name: str = "ecps-service",
        loop: Optional[Any] = None,
    ):
        """
        Initialize OpenTelemetry integration.
        
        Args:
            otlp_endpoint: OpenTelemetry endpoint URL (e.g., "http://localhost:4317")
            service_name: Name of the service for telemetry data
            loop: UV event loop to use
        """
        self.otlp_endpoint = otlp_endpoint or "http://localhost:4317"
        self.service_name = service_name
        self.loop = loop or uv.Loop.current()
        
        # TracerProvider for distributed tracing
        self.tracer_provider = None
        self.tracer = None
        
        # MeterProvider for metrics
        self.meter_provider = None
        self.meter = None
        
        # Initialize if endpoint is provided
        if otlp_endpoint:
            self._initialize_telemetry()
        else:
            logger.warning("No OTLP endpoint provided, telemetry will be disabled")
    
    def _initialize_telemetry(self):
        """Initialize OpenTelemetry providers and exporters."""
        # Initialize TracerProvider
        self.tracer_provider = TracerProvider()
        trace.set_tracer_provider(self.tracer_provider)
        
        # Create and register OTLP exporter for traces
        otlp_span_exporter = OTLPSpanExporter(endpoint=self.otlp_endpoint)
        span_processor = BatchSpanProcessor(otlp_span_exporter)
        self.tracer_provider.add_span_processor(span_processor)
        
        # Initialize MeterProvider
        metric_reader = PeriodicExportingMetricReader(
            exporter=OTLPMetricExporter(endpoint=self.otlp_endpoint),
            export_interval_millis=15000,  # Export every 15 seconds
        )
        self.meter_provider = MeterProvider(metric_readers=[metric_reader])
        metrics.set_meter_provider(self.meter_provider)
        
        # Create tracer and meter for this service
        self.tracer = trace.get_tracer(__name__, schemaUrl="https://ecps.io/schemas/1.0")
        self.meter = metrics.get_meter(__name__, schemaUrl="https://ecps.io/schemas/1.0")
        
        # Create standard metrics
        self._create_standard_metrics()
        
        logger.info(f"Initialized OpenTelemetry with endpoint {self.otlp_endpoint}")
    
    def _create_standard_metrics(self):
        """Create standard metrics for ECPS operations."""
        if not self.meter:
            return
        
        # EAP latency
        self.eap_latency = self.meter.create_histogram(
            name="eap.latency_ms",
            description="Latency of action execution in milliseconds",
            unit="ms",
        )
        
        # LTP frame size
        self.ltp_frame_bytes = self.meter.create_histogram(
            name="ltp.frame_bytes",
            description="Size of LTP frames in bytes",
            unit="bytes",
        )
        
        # MCP prompt size
        self.mcp_prompt_chars = self.meter.create_histogram(
            name="mcp.prompt_chars",
            description="Length of MCP prompts in characters",
            unit="chars",
        )
        
        # MEP query latency
        self.mep_query_latency = self.meter.create_histogram(
            name="mep.query_latency_ms",
            description="Latency of memory queries in milliseconds",
            unit="ms",
        )
        
        # Transport bytes
        self.transport_bytes_sent = self.meter.create_counter(
            name="transport.bytes_sent",
            description="Number of bytes sent over transport",
            unit="bytes",
        )
        
        self.transport_bytes_received = self.meter.create_counter(
            name="transport.bytes_received",
            description="Number of bytes received over transport",
            unit="bytes",
        )
    
    def create_span(
        self,
        name: str,
        context: Optional[Context] = None,
        kind: Optional[trace.SpanKind] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> trace.Span:
        """
        Create a new span for tracing.
        
        Args:
            name: Name of the span
            context: Parent context (optional)
            kind: Span kind (optional)
            attributes: Span attributes (optional)
            
        Returns:
            span: New span
        """
        if not self.tracer:
            # Return a no-op span if telemetry is disabled
            return trace.NoOpTracer().start_span(name)
        
        # Create span with context
        return self.tracer.start_span(
            name,
            context=context or get_current(),
            kind=kind or trace.SpanKind.INTERNAL,
            attributes=attributes or {},
        )
    
    def record_eap_latency(self, latency_ms: float, attributes: Optional[Dict[str, Any]] = None):
        """
        Record EAP action execution latency.
        
        Args:
            latency_ms: Latency in milliseconds
            attributes: Additional attributes for the metric
        """
        if not self.meter:
            return
        
        self.eap_latency.record(latency_ms, attributes=attributes)
    
    def record_ltp_frame_size(self, size_bytes: int, attributes: Optional[Dict[str, Any]] = None):
        """
        Record LTP frame size.
        
        Args:
            size_bytes: Size in bytes
            attributes: Additional attributes for the metric
        """
        if not self.meter:
            return
        
        self.ltp_frame_bytes.record(size_bytes, attributes=attributes)
    
    def record_mcp_prompt_size(self, chars: int, attributes: Optional[Dict[str, Any]] = None):
        """
        Record MCP prompt size.
        
        Args:
            chars: Number of characters
            attributes: Additional attributes for the metric
        """
        if not self.meter:
            return
        
        self.mcp_prompt_chars.record(chars, attributes=attributes)
    
    def record_mep_query_latency(self, latency_ms: float, attributes: Optional[Dict[str, Any]] = None):
        """
        Record MEP query latency.
        
        Args:
            latency_ms: Latency in milliseconds
            attributes: Additional attributes for the metric
        """
        if not self.meter:
            return
        
        self.mep_query_latency.record(latency_ms, attributes=attributes)
    
    def record_bytes_sent(self, bytes_count: int, transport_type: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Record bytes sent over transport.
        
        Args:
            bytes_count: Number of bytes
            transport_type: Type of transport (e.g., "dds", "grpc", "mqtt")
            attributes: Additional attributes for the metric
        """
        if not self.meter:
            return
        
        all_attributes = {"transport_type": transport_type}
        if attributes:
            all_attributes.update(attributes)
        
        self.transport_bytes_sent.add(bytes_count, attributes=all_attributes)
    
    def record_bytes_received(self, bytes_count: int, transport_type: str, attributes: Optional[Dict[str, Any]] = None):
        """
        Record bytes received over transport.
        
        Args:
            bytes_count: Number of bytes
            transport_type: Type of transport (e.g., "dds", "grpc", "mqtt")
            attributes: Additional attributes for the metric
        """
        if not self.meter:
            return
        
        all_attributes = {"transport_type": transport_type}
        if attributes:
            all_attributes.update(attributes)
        
        self.transport_bytes_received.add(bytes_count, attributes=all_attributes)
    
    def inject_context_into_headers(self, context: Optional[Context], headers: Dict[str, str]) -> Dict[str, str]:
        """
        Inject trace context into headers for propagation.
        
        Args:
            context: Trace context to inject
            headers: HTTP headers to inject into
            
        Returns:
            headers: Updated HTTP headers with trace context
        """
        # Create new headers dictionary if needed
        headers = headers.copy() if headers else {}
        
        # Get the current context if none provided
        context = context or get_current()
        
        # Inject context into headers
        TraceContextTextMapPropagator().inject(headers, context)
        
        return headers
    
    def extract_context_from_headers(self, headers: Dict[str, str]) -> Context:
        """
        Extract trace context from headers.
        
        Args:
            headers: HTTP headers containing trace context
            
        Returns:
            context: Extracted trace context
        """
        # Extract context from headers
        return TraceContextTextMapPropagator().extract(headers)
    
    def with_span(self, name: str, kind: Optional[trace.SpanKind] = None, attributes: Optional[Dict[str, Any]] = None):
        """
        Decorator for tracing functions with spans.
        
        Args:
            name: Name of the span
            kind: Span kind (optional)
            attributes: Span attributes (optional)
            
        Returns:
            decorator: Function decorator
        """
        def decorator(func):
            async def wrapper(*args, **kwargs):
                with self.create_span(name, kind=kind, attributes=attributes) as span:
                    try:
                        result = await func(*args, **kwargs)
                        return result
                    except Exception as e:
                        span.record_exception(e)
                        raise
            
            return wrapper
        
        return decorator
    
    async def shutdown(self):
        """Shut down telemetry providers and exporters."""
        if self.tracer_provider:
            await self.tracer_provider.shutdown()
        
        if self.meter_provider:
            await self.meter_provider.shutdown()
        
        logger.info("Telemetry providers shut down")