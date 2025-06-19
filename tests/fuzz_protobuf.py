#!/usr/bin/env python3
"""
Protobuf Fuzzing for ECPS-UV SDK using Atheris.

This module provides comprehensive fuzzing tests for all ECPS protobuf message parsers
to discover potential security vulnerabilities and parsing errors.
"""

import sys
import os
import logging
from typing import Any, Dict, List, Optional

# Add the parent directory to the path to import ecps_uv
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    import atheris
    ATHERIS_AVAILABLE = True
except ImportError:
    ATHERIS_AVAILABLE = False
    print("Atheris not available. Install with: pip install atheris")

try:
    import libfuzzer
    LIBFUZZER_AVAILABLE = True
except ImportError:
    LIBFUZZER_AVAILABLE = False

# Import ECPS protobuf messages (these would be generated from ecps.proto)
# For now, we'll create mock classes that simulate the actual protobuf behavior
class MockProtobufMessage:
    """Mock protobuf message for fuzzing."""
    
    def __init__(self, message_type: str):
        self.message_type = message_type
        self._data = {}
    
    def ParseFromString(self, data: bytes) -> None:
        """Mock parse from string that can trigger various exceptions."""
        if len(data) == 0:
            raise ValueError("Empty message")
        
        # Simulate various parsing errors based on input
        if data.startswith(b'\xff\xff'):
            raise RuntimeError("Invalid message format")
        
        if len(data) > 10000000:  # 10MB
            raise MemoryError("Message too large")
        
        if b'\x00\x00\x00\x00' in data:
            raise ValueError("Invalid field encoding")
        
        # Simulate successful parsing for most inputs
        self._data = {"parsed": True, "size": len(data)}
    
    def SerializeToString(self) -> bytes:
        """Mock serialization."""
        return b"mock_serialized_data"


# Mock ECPS message classes
class MCP(MockProtobufMessage):
    def __init__(self):
        super().__init__("MCP")

class LTP(MockProtobufMessage):
    def __init__(self):
        super().__init__("LTP")

class EAP(MockProtobufMessage):
    def __init__(self):
        super().__init__("EAP")

class QueryReq(MockProtobufMessage):
    def __init__(self):
        super().__init__("QueryReq")

class Ack(MockProtobufMessage):
    def __init__(self):
        super().__init__("Ack")

class LTPChunk(MockProtobufMessage):
    def __init__(self):
        super().__init__("LTPChunk")

class LTPAck(MockProtobufMessage):
    def __init__(self):
        super().__init__("LTPAck")


class ProtobufFuzzer:
    """Fuzzer for ECPS protobuf messages."""
    
    def __init__(self):
        """Initialize the fuzzer."""
        self.message_classes = {
            'MCP': MCP,
            'LTP': LTP,
            'EAP': EAP,
            'QueryReq': QueryReq,
            'Ack': Ack,
            'LTPChunk': LTPChunk,
            'LTPAck': LTPAck,
        }
        
        self.stats = {
            'total_inputs': 0,
            'successful_parses': 0,
            'parse_errors': 0,
            'crashes': 0,
            'timeouts': 0
        }
        
        # Setup logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('ecps_fuzzer')
    
    def fuzz_message_type(self, message_type: str, data: bytes) -> Dict[str, Any]:
        """
        Fuzz a specific message type with given data.
        
        Args:
            message_type: Type of message to fuzz
            data: Raw bytes to parse
            
        Returns:
            Dictionary with fuzzing results
        """
        if message_type not in self.message_classes:
            return {'error': f'Unknown message type: {message_type}'}
        
        result = {
            'message_type': message_type,
            'input_size': len(data),
            'success': False,
            'error': None,
            'exception_type': None
        }
        
        try:
            # Create message instance
            message_class = self.message_classes[message_type]
            message = message_class()
            
            # Attempt to parse
            message.ParseFromString(data)
            
            result['success'] = True
            self.stats['successful_parses'] += 1
            
        except Exception as e:
            result['error'] = str(e)
            result['exception_type'] = type(e).__name__
            self.stats['parse_errors'] += 1
            
            # Log interesting errors
            if isinstance(e, (MemoryError, RuntimeError)):
                self.logger.warning(f"Interesting error in {message_type}: {e}")
        
        self.stats['total_inputs'] += 1
        return result
    
    def fuzz_all_message_types(self, data: bytes) -> List[Dict[str, Any]]:
        """
        Fuzz all message types with the same data.
        
        Args:
            data: Raw bytes to parse
            
        Returns:
            List of fuzzing results for each message type
        """
        results = []
        
        for message_type in self.message_classes.keys():
            result = self.fuzz_message_type(message_type, data)
            results.append(result)
        
        return results
    
    def generate_test_cases(self) -> List[bytes]:
        """Generate interesting test cases for fuzzing."""
        test_cases = [
            # Empty message
            b'',
            
            # Single bytes
            b'\x00',
            b'\xff',
            b'\x01',
            
            # Common protobuf patterns
            b'\x08\x96\x01',  # varint
            b'\x12\x04test',  # length-delimited
            b'\x1a\x00',      # empty string
            
            # Large messages
            b'\x12' + b'\xff' * 1000,  # Large string
            b'\x08' + b'\xff' * 10,    # Large varint
            
            # Invalid patterns
            b'\xff\xff\xff\xff',  # Invalid start
            b'\x00\x00\x00\x00',  # Null bytes
            b'\x12\xff\xff\xff\xff',  # Invalid length
            
            # Nested messages
            b'\x1a\x08\x08\x01\x12\x04test',
            
            # Repeated fields
            b'\x08\x01\x08\x02\x08\x03',
            
            # Mixed valid/invalid
            b'\x08\x01\xff\xff\x12\x04test',
        ]
        
        return test_cases


# Atheris fuzzing functions
def fuzz_mcp(data: bytes) -> None:
    """Fuzz MCP message parsing."""
    fuzzer = ProtobufFuzzer()
    fuzzer.fuzz_message_type('MCP', data)


def fuzz_ltp(data: bytes) -> None:
    """Fuzz LTP message parsing."""
    fuzzer = ProtobufFuzzer()
    fuzzer.fuzz_message_type('LTP', data)


def fuzz_eap(data: bytes) -> None:
    """Fuzz EAP message parsing."""
    fuzzer = ProtobufFuzzer()
    fuzzer.fuzz_message_type('EAP', data)


def fuzz_all_messages(data: bytes) -> None:
    """Fuzz all message types."""
    fuzzer = ProtobufFuzzer()
    fuzzer.fuzz_all_message_types(data)


# Main fuzzing entry point for Atheris
def atheris_main():
    """Main entry point for Atheris fuzzing."""
    if not ATHERIS_AVAILABLE:
        print("Atheris not available. Please install with: pip install atheris")
        return
    
    # Initialize Atheris
    atheris.instrument_all()
    
    # Setup fuzzing targets
    fuzzing_targets = {
        'mcp': fuzz_mcp,
        'ltp': fuzz_ltp,
        'eap': fuzz_eap,
        'all': fuzz_all_messages,
    }
    
    # Get target from command line or default to 'all'
    target = sys.argv[1] if len(sys.argv) > 1 else 'all'
    
    if target not in fuzzing_targets:
        print(f"Unknown target: {target}")
        print(f"Available targets: {list(fuzzing_targets.keys())}")
        return
    
    print(f"Starting Atheris fuzzing for target: {target}")
    
    # Generate initial test cases
    fuzzer = ProtobufFuzzer()
    test_cases = fuzzer.generate_test_cases()
    
    # Run fuzzing
    atheris.Fuzz(
        fuzzing_targets[target],
        test_cases,
        enable_python_coverage=True
    )


# Standalone fuzzing for environments without Atheris
def standalone_fuzzing():
    """Run standalone fuzzing without Atheris."""
    print("Running standalone protobuf fuzzing...")
    
    fuzzer = ProtobufFuzzer()
    test_cases = fuzzer.generate_test_cases()
    
    # Add some random test cases
    import random
    for _ in range(100):
        size = random.randint(0, 1000)
        random_data = bytes([random.randint(0, 255) for _ in range(size)])
        test_cases.append(random_data)
    
    print(f"Testing {len(test_cases)} cases...")
    
    for i, test_case in enumerate(test_cases):
        if i % 20 == 0:
            print(f"Progress: {i}/{len(test_cases)}")
        
        results = fuzzer.fuzz_all_message_types(test_case)
        
        # Check for interesting results
        for result in results:
            if result.get('exception_type') in ['MemoryError', 'RuntimeError']:
                print(f"Interesting result: {result}")
    
    # Print statistics
    print("\nFuzzing Statistics:")
    for key, value in fuzzer.stats.items():
        print(f"  {key}: {value}")
    
    if fuzzer.stats['total_inputs'] > 0:
        success_rate = (fuzzer.stats['successful_parses'] / fuzzer.stats['total_inputs']) * 100
        print(f"  success_rate: {success_rate:.2f}%")


# libFuzzer integration (for C++ environments)
def create_libfuzzer_harness():
    """Create a libFuzzer harness for C++ protobuf fuzzing."""
    harness_code = '''
// libFuzzer harness for ECPS protobuf fuzzing
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
'''
    
    harness_path = os.path.join(os.path.dirname(__file__), 'libfuzzer_harness.cpp')
    with open(harness_path, 'w') as f:
        f.write(harness_code)
    
    print(f"libFuzzer harness created: {harness_path}")
    
    # Create build script
    build_script = '''#!/bin/bash
# Build script for libFuzzer harness

# Compile protobuf definitions
protoc --cpp_out=. ../ecps_uv/proto/ecps.proto

# Compile fuzzer
clang++ -g -O1 -fsanitize=fuzzer,address -I. \\
    libfuzzer_harness.cpp ecps.pb.cc \\
    -lprotobuf -o ecps_protobuf_fuzzer

echo "Fuzzer built: ecps_protobuf_fuzzer"
echo "Run with: ./ecps_protobuf_fuzzer"
'''
    
    build_path = os.path.join(os.path.dirname(__file__), 'build_libfuzzer.sh')
    with open(build_path, 'w') as f:
        f.write(build_script)
    
    os.chmod(build_path, 0o755)
    print(f"Build script created: {build_path}")


def main():
    """Main entry point."""
    if len(sys.argv) > 1 and sys.argv[1] == '--atheris':
        atheris_main()
    elif len(sys.argv) > 1 and sys.argv[1] == '--libfuzzer':
        create_libfuzzer_harness()
    else:
        standalone_fuzzing()


if __name__ == '__main__':
    main()