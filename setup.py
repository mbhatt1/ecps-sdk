from setuptools import setup, find_packages

setup(
    name="ecps-uv",
    version="0.1.0",
    description="UV-based Python SDK for the Embodied Cognition Protocol Stack (ECPS)",
    author="Manish Bhatt",
    author_email="example@example.com",
    packages=find_packages(),
    install_requires=[
        "uv",  # UV for high-performance async I/O
        "protobuf",  # For Protocol Buffer serialization
        "grpcio",  # For gRPC support
        "cyclonedds-python",  # For DDS/RTPS binding
        "paho-mqtt",  # For MQTT 5 binding
        "opentelemetry-api",  # For observability
        "opentelemetry-sdk",
        "opentelemetry-exporter-otlp",
        "cloudevents",  # For CloudEvents support
        "zstandard",  # For zstd compression in LTP
        "numpy",  # For tensor operations
    ],
    python_requires=">=3.8",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)