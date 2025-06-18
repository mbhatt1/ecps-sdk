#!/bin/bash
# Installation script for ECPS-UV SDK

echo "Installing ECPS-UV SDK..."

# Check if Python 3.8+ is installed
python_version=$(python3 --version 2>&1 | awk '{print $2}')
if [[ -z "$python_version" ]]; then
    echo "Error: Python 3 not found. Please install Python 3.8 or higher."
    exit 1
fi

major=$(echo $python_version | cut -d. -f1)
minor=$(echo $python_version | cut -d. -f2)
if [[ $major -lt 3 || ($major -eq 3 && $minor -lt 8) ]]; then
    echo "Error: Python 3.8 or higher is required. You have Python $python_version."
    exit 1
fi

echo "Python $python_version detected."

# Create and activate virtual environment
echo "Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install wheel setuptools

# Install core dependencies
echo "Installing core dependencies..."
pip install numpy protobuf grpc-io opentelemetry-api opentelemetry-sdk cyclonedds zstandard cloudevents

# Install trust layer dependencies
echo "Installing security dependencies for trust layer..."
pip install pyjwt[crypto] cryptography pyopenssl

# Install package in development mode
echo "Installing ECPS-UV in development mode..."
pip install -e .

echo "Installation complete!"
echo "To activate the virtual environment, run: source venv/bin/activate"