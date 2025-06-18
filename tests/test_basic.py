import asyncio
import pytest
import numpy as np
import uuid
import os
import tempfile
from unittest.mock import MagicMock, patch

import ecps_uv
from ecps_uv.core import ECPSClient, ECPSServer, EdgeLiteProfile
from ecps_uv.transport.base import Transport
from ecps_uv.serialization.protobuf import ProtobufSerializer
from ecps_uv.cognition.mcp import MCPHandler
from ecps_uv.cognition.mep import MEPClient, MEPServer, InMemoryVectorStore
from ecps_uv.actuation.eap import EAPHandler
from ecps_uv.perception.ltp import LTPHandler


# Mock Transport implementation for testing
class MockTransport(Transport):
    """Mock transport for testing that stores messages in memory."""
    
    def __init__(self, serializer, config=None, loop=None, is_server=False):
        super().__init__(serializer, config, loop, is_server)
        self.published_messages = {}
        self.subscriptions = {}
        self.service_handlers = {}
        self.stream_service_handlers = {}
        self.connected = False
    
    async def connect(self):
        self.connected = True
    
    async def close(self):
        self.connected = False
    
    async def start(self):
        self.connected = True
    
    async def publish(self, topic, message, qos=None):
        if topic not in self.published_messages:
            self.published_messages[topic] = []
        self.published_messages[topic].append(message)
        
        # Simulate subscription delivery
        if topic in self.subscriptions:
            for handler in self.subscriptions[topic]:
                await handler(message)
    
    async def subscribe(self, topic, handler, message_type, qos=None):
        if topic not in self.subscriptions:
            self.subscriptions[topic] = []
        self.subscriptions[topic].append(handler)
    
    async def request(self, service, request, timeout=10.0, qos=None):
        if service in self.service_handlers:
            handler, _, _ = self.service_handlers[service]
            return await handler(request)
        return None
    
    async def register_service(self, service, handler, request_type, response_type, qos=None):
        self.service_handlers[service] = (handler, request_type, response_type)
    
    async def stream_request(self, service, request, handler, timeout=60.0, qos=None):
        if service in self.stream_service_handlers:
            stream_handler, _, _ = self.stream_service_handlers[service]
            
            # Mock publisher function
            async def publisher(response, is_final=False):
                await handler(response)
            
            await stream_handler(request, publisher)
    
    async def register_stream_service(self, service, handler, request_type, response_type, qos=None):
        self.stream_service_handlers[service] = (handler, request_type, response_type)


@pytest.fixture
def event_loop():
    """Create an instance of the default event loop for each test."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def mock_transport():
    """Create a mock transport for testing."""
    serializer = ProtobufSerializer()
    transport = MockTransport(serializer)
    await transport.connect()
    yield transport
    await transport.close()


@pytest.fixture
async def mcp_handler(mock_transport):
    """Create an MCP handler for testing."""
    serializer = ProtobufSerializer()
    handler = MCPHandler(mock_transport, serializer)
    yield handler


@pytest.fixture
async def eap_handler(mock_transport):
    """Create an EAP handler for testing."""
    serializer = ProtobufSerializer()
    with tempfile.TemporaryDirectory() as tmpdir:
        handler = EAPHandler(mock_transport, serializer, log_dir=tmpdir)
        yield handler


@pytest.fixture
async def ltp_handler(mock_transport):
    """Create an LTP handler for testing."""
    serializer = ProtobufSerializer()
    handler = LTPHandler(mock_transport, serializer)
    yield handler


@pytest.fixture
async def mep_client(mock_transport):
    """Create an MEP client for testing."""
    serializer = ProtobufSerializer()
    client = MEPClient(mock_transport, serializer)
    yield client


@pytest.fixture
async def mep_server(mock_transport):
    """Create an MEP server for testing."""
    serializer = ProtobufSerializer()
    storage = InMemoryVectorStore()
    server = MEPServer(mock_transport, serializer, storage_backend=storage)
    await server.start()
    yield server
    await server.stop()


@pytest.mark.asyncio
async def test_mcp_send_receive(mcp_handler, mock_transport):
    """Test sending and receiving MCP messages."""
    # Create a handler to receive MCP messages
    received_messages = []
    
    async def handle_mcp(message):
        received_messages.append(message)
    
    # Subscribe to MCP messages
    await mcp_handler.listen([handle_mcp])
    
    # Send an MCP message
    prompt = "Move the robot arm to pick up the object"
    message_id = await mcp_handler.send(prompt)
    
    # Check that the message was sent with the expected prompt
    assert mock_transport.published_messages["mcp"][-1].prompt == prompt
    assert mock_transport.published_messages["mcp"][-1].id == message_id
    
    # Check that the message was received
    assert len(received_messages) == 1
    assert received_messages[0].prompt == prompt
    assert received_messages[0].id == message_id


@pytest.mark.asyncio
async def test_eap_send_receive(eap_handler, mock_transport):
    """Test sending and receiving EAP messages."""
    # Create a handler to receive EAP messages
    received_messages = []
    
    async def handle_eap(message):
        received_messages.append(message)
    
    # Subscribe to EAP messages
    await eap_handler.listen([handle_eap], log_actions=False)
    
    # Send an EAP message (robot pose)
    pose_data = {
        "x": 0.5,
        "y": 0.3,
        "z": 0.2,
        "qw": 1.0,
        "qx": 0.0,
        "qy": 0.0,
        "qz": 0.0,
    }
    
    message_id = await eap_handler.send(
        "set_pose",
        pose_data,
        log_action=False,
    )
    
    # Check that the message was sent with the expected pose
    sent_message = mock_transport.published_messages["eap"][-1]
    assert sent_message.id == message_id
    assert sent_message.set_pose.x == 0.5
    assert sent_message.set_pose.y == 0.3
    assert sent_message.set_pose.z == 0.2
    
    # Check that the message was received
    assert len(received_messages) == 1
    assert received_messages[0].id == message_id
    assert received_messages[0].set_pose.x == 0.5
    assert received_messages[0].set_pose.y == 0.3
    assert received_messages[0].set_pose.z == 0.2


@pytest.mark.asyncio
async def test_ltp_send_receive(ltp_handler, mock_transport):
    """Test sending and receiving LTP messages."""
    # Create a handler to receive tensors
    received_tensors = []
    received_metadata = []
    
    async def handle_tensor(tensor, metadata):
        received_tensors.append(tensor)
        received_metadata.append(metadata)
    
    # Subscribe to LTP messages
    await ltp_handler.receive("ltp_topic", handle_tensor)
    
    # Create a tensor to send
    tensor = np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]], dtype=np.float32)
    frame_id = "camera_1"
    timestamp_ns = 1624012345000000
    
    # Send the tensor
    await ltp_handler.send("ltp_topic", tensor, frame_id, timestamp_ns)
    
    # Check that the tensor was received
    assert len(received_tensors) == 1
    assert np.array_equal(received_tensors[0], tensor)
    assert received_metadata[0]["frame_id"] == frame_id
    assert received_metadata[0]["timestamp_ns"] == timestamp_ns


@pytest.mark.asyncio
async def test_mep_put_query(mep_client, mep_server, mock_transport):
    """Test MEP Put and Query operations."""
    # Create a tensor
    tensor = np.array([[1.0, 2.0, 3.0], [4.0, 5.0, 6.0]], dtype=np.float32)
    
    # Compress tensor for storage
    import zstandard as zstd
    compressor = zstd.ZstdCompressor(level=3)
    tensor_bytes = tensor.tobytes()
    tensor_zstd = compressor.compress(tensor_bytes)
    
    # Store the tensor
    shape = [2, 3]
    dtype = "f32"
    frame_id = "camera_1"
    timestamp_ns = 1624012345000000
    
    success, message = await mep_client.put(
        tensor_zstd=tensor_zstd,
        shape=shape,
        dtype=dtype,
        frame_id=frame_id,
        timestamp_ns=timestamp_ns,
    )
    
    # Check that the tensor was stored
    assert success
    
    # Query for the tensor
    query_embedding = {
        "tensor_zstd": tensor_zstd,
        "shape": shape,
        "dtype": dtype,
        "frame_id": frame_id,
        "timestamp_ns": timestamp_ns,
    }
    
    results = await mep_client.query(query_embedding, k=5, min_sim=0.7)
    
    # Check that the query returned the tensor
    assert len(results) > 0


@pytest.mark.asyncio
async def test_ecps_client_server():
    """Test the ECPS client and server integration."""
    # Create client and server with mock transport
    config = EdgeLiteProfile()
    
    # Patch the transport creation to use MockTransport
    with patch('ecps_uv.core.DDSTransport', MockTransport):
        # Create server
        server = ecps_uv.ECPSServer(config)
        
        # Define handlers
        received_mcp = []
        received_eap = []
        
        async def handle_mcp(message):
            received_mcp.append(message)
        
        async def handle_eap(message):
            received_eap.append(message)
        
        # Register handlers
        server.on_mcp(handle_mcp)
        server.on_eap(handle_eap)
        
        # Start server
        await server.start()
        
        # Create client
        client = ecps_uv.ECPSClient(config)
        
        # Send MCP message
        prompt = "Move the robot arm"
        mcp_id = await client.send_mcp(prompt)
        
        # Send EAP message
        pose_data = {
            "x": 0.5, "y": 0.3, "z": 0.2,
            "qw": 1.0, "qx": 0.0, "qy": 0.0, "qz": 0.0,
        }
        eap_id = await client.send_action("set_pose", pose_data, b"dummy_state")
        
        # Check that messages were received
        assert len(received_mcp) == 1
        assert received_mcp[0].prompt == prompt
        assert received_mcp[0].id == mcp_id
        
        assert len(received_eap) == 1
        assert received_eap[0].id == eap_id
        assert received_eap[0].set_pose.x == 0.5
        
        # Close client and server
        await client.close()
        await server.close()


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])