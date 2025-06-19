#!/usr/bin/env python3
"""
ECPS v1.0 Test Vector Generator

This script generates binary protobuf test vectors for ECPS conformance testing.
It creates both valid and invalid test cases to validate implementation behavior.
"""

import os
import json
import zstandard as zstd
import numpy as np
import hashlib
from pathlib import Path
from google.protobuf.message import Message
from google.protobuf import timestamp_pb2

# Import generated protobuf classes (these would be generated from ecps.proto)
# For this example, we'll create mock classes that represent the structure
class MockProtobufMessage:
    """Mock protobuf message for demonstration purposes."""
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def SerializeToString(self) -> bytes:
        """Mock serialization - in real implementation this would use protobuf."""
        import pickle
        return pickle.dumps(self.__dict__)

# Mock message classes based on our protobuf definitions
class MCP(MockProtobufMessage):
    def __init__(self, spec="mcp/1.0", id="", prompt="", tool_json=b"", meta=None):
        super().__init__(spec=spec, id=id, prompt=prompt, tool_json=tool_json, meta=meta or {})

class LTPFrameHeader(MockProtobufMessage):
    def __init__(self, version=1, message_type=1, payload_length=0, sequence_number=0,
                 total_chunks=0, chunk_index=0, checksum=b"", metadata=None):
        super().__init__(
            version=version, message_type=message_type, payload_length=payload_length,
            sequence_number=sequence_number, total_chunks=total_chunks, chunk_index=chunk_index,
            checksum=checksum, metadata=metadata or {}
        )

class LTP(MockProtobufMessage):
    def __init__(self, spec="ltp/0.9", header=None, tensor_zstd=b"", shape=None, dtype="f32",
                 frame_id="", timestamp_ns=0, compression_level=3, original_size=0, attributes=None):
        super().__init__(
            spec=spec, header=header or LTPFrameHeader(), tensor_zstd=tensor_zstd,
            shape=shape or [], dtype=dtype, frame_id=frame_id, timestamp_ns=timestamp_ns,
            compression_level=compression_level, original_size=original_size,
            attributes=attributes or {}
        )

class RobotPose(MockProtobufMessage):
    def __init__(self, x=0.0, y=0.0, z=0.0, qw=1.0, qx=0.0, qy=0.0, qz=0.0,
                 frame_id="base_link", timestamp_ns=0):
        super().__init__(x=x, y=y, z=z, qw=qw, qx=qx, qy=qy, qz=qz,
                        frame_id=frame_id, timestamp_ns=timestamp_ns)

class GripperOp(MockProtobufMessage):
    def __init__(self, command=1, position=0.5, force_limit=10.0):
        super().__init__(command=command, position=position, force_limit=force_limit)

class EAP(MockProtobufMessage):
    def __init__(self, spec="eap/0.1", id="", state_sha=b"", body=None, meta=None):
        super().__init__(spec=spec, id=id, state_sha=state_sha, body=body, meta=meta or {})

class QueryReq(MockProtobufMessage):
    def __init__(self, query_embedding=None, k=10, min_sim=0.8):
        super().__init__(query_embedding=query_embedding, k=k, min_sim=min_sim)

class TestVectorGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = Path(output_dir)
        self.compressor = zstd.ZstdCompressor(level=3)
        
    def generate_all_vectors(self):
        """Generate all test vectors."""
        print("Generating ECPS v1.0 test vectors...")
        
        # Create directory structure
        self._create_directories()
        
        # Generate MCP test vectors
        self._generate_mcp_vectors()
        
        # Generate LTP test vectors
        self._generate_ltp_vectors()
        
        # Generate EAP test vectors
        self._generate_eap_vectors()
        
        # Generate MEP test vectors
        self._generate_mep_vectors()
        
        # Generate transport configuration files
        self._generate_transport_configs()
        
        print("Test vector generation complete!")
    
    def _create_directories(self):
        """Create the directory structure for test vectors."""
        dirs = [
            "mcp/valid", "mcp/invalid",
            "ltp/valid", "ltp/invalid", 
            "eap/valid", "eap/invalid",
            "mep/queries", "mep/responses",
            "transport/dds", "transport/grpc", "transport/mqtt",
            "integration", "observability", "security", "performance"
        ]
        
        for dir_path in dirs:
            (self.output_dir / dir_path).mkdir(parents=True, exist_ok=True)
    
    def _generate_mcp_vectors(self):
        """Generate MCP test vectors."""
        print("  Generating MCP vectors...")
        
        # Valid: Basic prompt
        mcp_basic = MCP(
            spec="mcp/1.0",
            id="test-mcp-001",
            prompt="Move the robot to position (1, 2, 0) and pick up the red cube.",
            meta={"priority": "high", "source": "user_command"}
        )
        self._save_message(mcp_basic, "mcp/valid/basic-prompt.bin")
        self._save_json(mcp_basic, "mcp/valid/basic-prompt.json")
        
        # Valid: With tools
        tool_schema = {
            "type": "function",
            "function": {
                "name": "move_robot",
                "description": "Move robot to specified position",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "x": {"type": "number"},
                        "y": {"type": "number"},
                        "z": {"type": "number"}
                    }
                }
            }
        }
        mcp_tools = MCP(
            spec="mcp/1.0",
            id="test-mcp-002",
            prompt="Use the move_robot tool to navigate.",
            tool_json=json.dumps(tool_schema).encode('utf-8'),
            meta={"has_tools": "true"}
        )
        self._save_message(mcp_tools, "mcp/valid/with-tools.bin")
        self._save_json(mcp_tools, "mcp/valid/with-tools.json")
        
        # Invalid: Oversized prompt (> 16 KiB)
        large_prompt = "A" * (16 * 1024 + 1)  # 16 KiB + 1 byte
        mcp_oversized = MCP(
            spec="mcp/1.0",
            id="test-mcp-003",
            prompt=large_prompt
        )
        self._save_message(mcp_oversized, "mcp/invalid/oversized-prompt.bin")
        
        # Invalid: Wrong spec version
        mcp_invalid_spec = MCP(
            spec="mcp/2.0",  # Wrong version
            id="test-mcp-004",
            prompt="This should fail validation."
        )
        self._save_message(mcp_invalid_spec, "mcp/invalid/invalid-spec.bin")
    
    def _generate_ltp_vectors(self):
        """Generate LTP test vectors."""
        print("  Generating LTP vectors...")
        
        # Valid: Float32 tensor
        tensor_data = np.random.randn(2, 128, 512).astype(np.float32)
        compressed_data = self.compressor.compress(tensor_data.tobytes())
        
        header = LTPFrameHeader(
            version=1,
            message_type=1,  # DATA
            payload_length=len(compressed_data),
            sequence_number=1,
            checksum=hashlib.md5(compressed_data).digest()[:4]  # CRC32 mock
        )
        
        ltp_float32 = LTP(
            spec="ltp/0.9",
            header=header,
            tensor_zstd=compressed_data,
            shape=[2, 128, 512],
            dtype="f32",
            frame_id="camera_optical_frame",
            timestamp_ns=1640995200000000000,  # 2022-01-01 00:00:00 UTC
            compression_level=3,
            original_size=tensor_data.nbytes,
            attributes={"sensor_type": "camera", "resolution": "1920x1080"}
        )
        self._save_message(ltp_float32, "ltp/valid/float32-tensor.bin")
        self._save_json(ltp_float32, "ltp/valid/float32-tensor.json")
        
        # Valid: Chunked transmission
        large_tensor = np.random.randn(10, 1024, 1024).astype(np.float32)
        chunk_size = 256 * 1024  # 256 KB chunks
        compressed_large = self.compressor.compress(large_tensor.tobytes())
        
        # Create first chunk
        chunk_data = compressed_large[:chunk_size]
        chunk_header = LTPFrameHeader(
            version=1,
            message_type=3,  # CHUNK_START
            payload_length=len(chunk_data),
            sequence_number=1,
            total_chunks=len(compressed_large) // chunk_size + 1,
            chunk_index=0,
            checksum=hashlib.md5(chunk_data).digest()[:4]
        )
        
        # Mock LTPChunk message
        ltp_chunk = MockProtobufMessage(
            header=chunk_header,
            chunk_data=chunk_data,
            is_final=False
        )
        self._save_message(ltp_chunk, "ltp/valid/chunked-transmission.bin")
        
        # Invalid: Oversized frame (> 1 MiB)
        oversized_tensor = np.random.randn(1000, 1000, 10).astype(np.float32)  # ~40 MB
        oversized_compressed = self.compressor.compress(oversized_tensor.tobytes())
        
        ltp_oversized = LTP(
            spec="ltp/0.9",
            header=LTPFrameHeader(payload_length=len(oversized_compressed)),
            tensor_zstd=oversized_compressed,
            shape=list(oversized_tensor.shape),
            dtype="f32",
            original_size=oversized_tensor.nbytes
        )
        self._save_message(ltp_oversized, "ltp/invalid/oversized-frame.bin")
    
    def _generate_eap_vectors(self):
        """Generate EAP test vectors."""
        print("  Generating EAP vectors...")
        
        # Valid: Robot pose
        pose = RobotPose(
            x=1.5, y=2.0, z=0.0,
            qw=0.707, qx=0.0, qy=0.0, qz=0.707,  # 90 degree rotation around Z
            frame_id="map",
            timestamp_ns=1640995200000000000
        )
        
        state_hash = hashlib.sha256(b"mock_perceptual_state_data").digest()
        
        eap_pose = EAP(
            spec="eap/0.1",
            id="test-eap-001",
            state_sha=state_hash,
            body=pose,
            meta={"action_type": "set_pose", "safety": "stop_on_fail"}
        )
        self._save_message(eap_pose, "eap/valid/robot-pose.bin")
        self._save_json(eap_pose, "eap/valid/robot-pose.json")
        
        # Valid: Gripper operation
        gripper = GripperOp(
            command=2,  # CLOSE
            position=0.1,  # Nearly closed
            force_limit=15.0
        )
        
        eap_gripper = EAP(
            spec="eap/0.1",
            id="test-eap-002",
            state_sha=state_hash,
            body=gripper,
            meta={"action_type": "gripper_op"}
        )
        self._save_message(eap_gripper, "eap/valid/gripper-op.bin")
        self._save_json(eap_gripper, "eap/valid/gripper-op.json")
        
        # Valid: Navigation command
        nav_pose = RobotPose(x=5.0, y=3.0, z=0.0, qw=1.0, frame_id="map")
        nav_op = MockProtobufMessage(
            target_pose=nav_pose,
            max_velocity=1.0,
            tolerance=0.1,
            planner_id="rrt_star"
        )
        
        eap_nav = EAP(
            spec="eap/0.1",
            id="test-eap-003",
            state_sha=state_hash,
            body=nav_op,
            meta={"action_type": "navigate"}
        )
        self._save_message(eap_nav, "eap/valid/navigation.bin")
        
        # Generate action sequence for replay testing
        action_sequence = [eap_pose, eap_gripper, eap_nav]
        sequence_data = b"".join(msg.SerializeToString() for msg in action_sequence)
        self._save_binary(sequence_data, "eap/valid/action-sequence.bin")
        
        # Generate corresponding state hashes
        state_hashes = [
            hashlib.sha256(f"state_{i}".encode()).hexdigest()
            for i in range(len(action_sequence))
        ]
        self._save_text("\n".join(state_hashes), "eap/valid/state-hashes.txt")
    
    def _generate_mep_vectors(self):
        """Generate MEP test vectors."""
        print("  Generating MEP vectors...")
        
        # Query embedding
        query_tensor = np.random.randn(1, 512).astype(np.float32)
        query_compressed = self.compressor.compress(query_tensor.tobytes())
        
        query_ltp = LTP(
            spec="ltp/0.9",
            header=LTPFrameHeader(payload_length=len(query_compressed)),
            tensor_zstd=query_compressed,
            shape=[1, 512],
            dtype="f32",
            frame_id="query_embedding",
            timestamp_ns=1640995200000000000,
            original_size=query_tensor.nbytes
        )
        
        # Basic query
        basic_query = QueryReq(
            query_embedding=query_ltp,
            k=5,
            min_sim=0.7
        )
        self._save_message(basic_query, "mep/queries/basic-query.bin")
        
        # Similarity threshold query (high threshold, expect no results)
        threshold_query = QueryReq(
            query_embedding=query_ltp,
            k=10,
            min_sim=0.99  # Very high threshold
        )
        self._save_message(threshold_query, "mep/queries/similarity-threshold.bin")
        
        # K-limit query
        k_limit_query = QueryReq(
            query_embedding=query_ltp,
            k=3,  # Limit to 3 results
            min_sim=0.5
        )
        self._save_message(k_limit_query, "mep/queries/k-limit-query.bin")
        
        # Generate mock response vectors
        result_tensors = [
            np.random.randn(1, 512).astype(np.float32) for _ in range(5)
        ]
        
        result_ltps = []
        for i, tensor in enumerate(result_tensors):
            compressed = self.compressor.compress(tensor.tobytes())
            ltp = LTP(
                spec="ltp/0.9",
                header=LTPFrameHeader(payload_length=len(compressed)),
                tensor_zstd=compressed,
                shape=[1, 512],
                dtype="f32",
                frame_id=f"result_{i}",
                original_size=tensor.nbytes
            )
            result_ltps.append(ltp)
        
        # Save query results
        results_data = b"".join(ltp.SerializeToString() for ltp in result_ltps)
        self._save_binary(results_data, "mep/responses/query-results.bin")
        
        # Empty results for high threshold query
        self._save_binary(b"", "mep/responses/empty-results.bin")
        
        # K-limited results (only first 3)
        k_limited_data = b"".join(ltp.SerializeToString() for ltp in result_ltps[:3])
        self._save_binary(k_limited_data, "mep/responses/k-limited-results.bin")
    
    def _generate_transport_configs(self):
        """Generate transport layer configuration files."""
        print("  Generating transport configs...")
        
        # DDS configuration
        dds_config = {
            "qos_profile": {
                "reliability": "RELIABLE",
                "durability": "TRANSIENT_LOCAL",
                "history": "KEEP_LAST",
                "depth": 4
            },
            "domain_id": 0,
            "topic_name": "ecps_test"
        }
        self._save_yaml(dds_config, "transport/dds/reliable-qos.yaml")
        
        # gRPC configuration
        grpc_config = {
            "server_address": "localhost:50051",
            "use_tls": False,
            "max_message_size": 4194304,  # 4 MB
            "keepalive_time_ms": 30000,
            "keepalive_timeout_ms": 5000
        }
        self._save_yaml(grpc_config, "transport/grpc/streaming-config.yaml")
        
        # MQTT configuration
        mqtt_config = {
            "broker_host": "localhost",
            "broker_port": 1883,
            "qos": 1,
            "topic_prefix": "ecps/test",
            "client_id": "ecps_conformance_test",
            "keepalive": 60
        }
        self._save_yaml(mqtt_config, "transport/mqtt/qos1-config.yaml")
        
        # OTLP observability configuration
        otlp_config = {
            "endpoint": "http://localhost:4317",
            "service_name": "ecps-conformance-test",
            "trace_export_timeout": 30,
            "metric_export_interval": 10
        }
        self._save_yaml(otlp_config, "observability/otlp-config.yaml")
        
        # TLS security configuration
        tls_config = {
            "server_address": "localhost:50052",
            "use_tls": True,
            "ca_cert_file": "ca-cert.pem",
            "client_cert_file": "client-cert.pem",
            "client_key_file": "client-key.pem",
            "server_name_override": "ecps-test-server"
        }
        self._save_yaml(tls_config, "security/tls-config.yaml")
    
    def _save_message(self, message: MockProtobufMessage, filename: str):
        """Save a protobuf message to binary file."""
        filepath = self.output_dir / filename
        with open(filepath, 'wb') as f:
            f.write(message.SerializeToString())
    
    def _save_binary(self, data: bytes, filename: str):
        """Save binary data to file."""
        filepath = self.output_dir / filename
        with open(filepath, 'wb') as f:
            f.write(data)
    
    def _save_text(self, text: str, filename: str):
        """Save text data to file."""
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            f.write(text)
    
    def _save_json(self, message: MockProtobufMessage, filename: str):
        """Save message as JSON for debugging."""
        filepath = self.output_dir / filename
        # Convert message to JSON-serializable dict
        data = {
            "message_type": message.__class__.__name__,
            "fields": message.__dict__
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def _save_yaml(self, data: dict, filename: str):
        """Save data as YAML configuration file."""
        import yaml
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate ECPS v1.0 test vectors")
    parser.add_argument("--output-dir", default=".",
                       help="Output directory for test vectors")
    
    args = parser.parse_args()
    
    generator = TestVectorGenerator(args.output_dir)
    generator.generate_all_vectors()

if __name__ == "__main__":
    main()