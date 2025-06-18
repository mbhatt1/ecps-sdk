import unittest
import numpy as np
from ecps_uv.cognition.mep import MEPClient, InMemoryVectorStore, ConsistencyModel

class TestMEPClient(unittest.TestCase):
    def setUp(self):
        self.memory_store = InMemoryVectorStore(max_size=100)
        self.client = MEPClient(transport=None, serializer=None)  # Mock transport and serializer

    def test_put_with_strong_consistency(self):
        tensor = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
        metadata = {"frame_id": "test_frame", "timestamp_ns": 1234567890}
        
        success, message = self.client.put(tensor.tobytes(), tensor.shape, "f32", "test_frame", 1234567890, consistency=ConsistencyModel.STRONG)
        
        self.assertTrue(success)
        self.assertEqual(message, "Embedding stored successfully")

    def test_query_with_eventual_consistency(self):
        tensor = np.array([[1.0, 2.0], [3.0, 4.0]], dtype=np.float32)
        self.client.put(tensor.tobytes(), tensor.shape, "f32", "test_frame", 1234567890, consistency=ConsistencyModel.EVENTUAL)
        
        results = self.client.query(tensor, k=1, min_sim=0.7, consistency=ConsistencyModel.EVENTUAL)
        
        self.assertGreater(len(results), 0)

if __name__ == '__main__':
    unittest.main()