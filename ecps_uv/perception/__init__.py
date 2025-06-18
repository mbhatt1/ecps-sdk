"""
Perception Data Layer (L5) for ECPS.

This package provides handling for perception data, including
ROS 2 sensor_msgs/* and Latent Tensor Protocol (LTP).
"""

from ecps_uv.perception.ltp import LTPHandler

__all__ = ["LTPHandler"]