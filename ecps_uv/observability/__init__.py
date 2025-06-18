"""
Observability Layer (L4) for ECPS.

This package provides observability integration using OpenTelemetry (OTLP),
enabling comprehensive monitoring, debugging, and performance analysis.
"""

from ecps_uv.observability.telemetry import ECPSTelemetry

__all__ = ["ECPSTelemetry"]