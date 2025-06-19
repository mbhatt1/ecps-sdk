#!/usr/bin/env python3
"""
ECPS Camera Simulator

Simulates realistic camera feeds for the agentic AI robotic system.
Generates synthetic perception data with object detection for testing the complete workflow.
"""

import asyncio
import cv2
import numpy as np
import time
import json
import logging
from typing import List, Dict, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
import random
import math

# ECPS imports
import ecps_uv
from ecps_uv.core import StandardProfile
from ecps_uv.perception.ltp import LTPProcessor

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class SimulatedObject:
    """Simulated object in the camera view"""
    class_name: str
    position: Tuple[float, float, float]  # x, y, z in meters
    size: Tuple[float, float, float]      # width, height, depth in meters
    color: Tuple[int, int, int]           # RGB color
    confidence: float
    velocity: Tuple[float, float, float] = (0, 0, 0)  # m/s

class CameraSimulator:
    """
    Simulates a camera feed with realistic object detection for agentic AI robotics
    """
    
    def __init__(self, width: int = 640, height: int = 480, fps: int = 30):
        self.width = width
        self.height = height
        self.fps = fps
        self.frame_interval = 1.0 / fps
        
        # Camera parameters (realistic values)
        self.focal_length = 500  # pixels
        self.camera_height = 1.2  # meters above ground
        self.camera_tilt = -15    # degrees (looking down)
        
        # Simulated objects in the scene
        self.objects = [
            SimulatedObject(
                class_name="cup",
                position=(0.3, 0.2, 0.1),
                size=(0.08, 0.08, 0.12),
                color=(200, 100, 50),
                confidence=0.92
            ),
            SimulatedObject(
                class_name="bottle",
                position=(0.5, 0.3, 0.15),
                size=(0.06, 0.06, 0.25),
                color=(50, 150, 200),
                confidence=0.87
            ),
            SimulatedObject(
                class_name="book",
                position=(-0.2, 0.4, 0.02),
                size=(0.15, 0.20, 0.03),
                color=(100, 200, 100),
                confidence=0.78
            ),
            SimulatedObject(
                class_name="phone",
                position=(0.1, -0.1, 0.01),
                size=(0.07, 0.14, 0.008),
                color=(30, 30, 30),
                confidence=0.85
            )
        ]
        
        # Animation parameters
        self.time_offset = 0
        self.noise_level = 0.02
        
        # ECPS components
        self.client = None
        self.ltp_processor = None
        
        # Statistics
        self.frames_sent = 0
        self.start_time = None
        
    async def initialize(self):
        """Initialize ECPS client and components"""
        logger.info("Initializing camera simulator...")
        
        # Initialize ECPS client
        profile = StandardProfile(transport_type="dds")
        self.client = ecps_uv.ECPSClient(profile)
        
        # Initialize LTP processor
        self.ltp_processor = LTPProcessor(compression="zstd")
        
        self.start_time = time.time()
        logger.info("Camera simulator initialized")
    
    def world_to_camera(self, world_pos: Tuple[float, float, float]) -> Tuple[int, int]:
        """Convert world coordinates to camera pixel coordinates"""
        x, y, z = world_pos
        
        # Simple perspective projection
        # Assume camera is at (0, 0, camera_height) looking down
        camera_x = x
        camera_y = y
        camera_z = self.camera_height - z
        
        if camera_z <= 0:
            return (-1, -1)  # Behind camera
        
        # Project to image plane
        pixel_x = int(self.width / 2 + (camera_x * self.focal_length) / camera_z)
        pixel_y = int(self.height / 2 + (camera_y * self.focal_length) / camera_z)
        
        return (pixel_x, pixel_y)
    
    def generate_frame(self) -> Tuple[np.ndarray, List[Dict[str, Any]]]:
        """Generate a synthetic camera frame with objects"""
        # Create background (table surface)
        frame = np.ones((self.height, self.width, 3), dtype=np.uint8) * 180
        
        # Add some texture to the background
        noise = np.random.randint(-20, 20, (self.height, self.width, 3))
        frame = np.clip(frame.astype(np.int16) + noise, 0, 255).astype(np.uint8)
        
        # Add table edges
        cv2.rectangle(frame, (50, 50), (self.width-50, self.height-50), (120, 80, 60), 3)
        
        detected_objects = []
        
        # Animate and render objects
        for obj in self.objects:
            # Add slight animation
            animated_pos = (
                obj.position[0] + 0.05 * math.sin(self.time_offset + hash(obj.class_name) % 100),
                obj.position[1] + 0.03 * math.cos(self.time_offset * 1.2 + hash(obj.class_name) % 100),
                obj.position[2]
            )
            
            # Add noise to position
            noisy_pos = (
                animated_pos[0] + random.gauss(0, self.noise_level),
                animated_pos[1] + random.gauss(0, self.noise_level),
                animated_pos[2] + random.gauss(0, self.noise_level * 0.5)
            )
            
            # Convert to camera coordinates
            pixel_x, pixel_y = self.world_to_camera(noisy_pos)
            
            if 0 <= pixel_x < self.width and 0 <= pixel_y < self.height:
                # Calculate object size in pixels (simple approximation)
                distance = math.sqrt(noisy_pos[0]**2 + noisy_pos[1]**2 + (self.camera_height - noisy_pos[2])**2)
                pixel_size = max(10, int(obj.size[0] * self.focal_length / distance))
                
                # Draw object
                top_left = (max(0, pixel_x - pixel_size//2), max(0, pixel_y - pixel_size//2))
                bottom_right = (min(self.width-1, pixel_x + pixel_size//2), min(self.height-1, pixel_y + pixel_size//2))
                
                # Draw filled rectangle for object
                cv2.rectangle(frame, top_left, bottom_right, obj.color, -1)
                
                # Add some 3D effect
                cv2.rectangle(frame, top_left, bottom_right, 
                            tuple(max(0, c-30) for c in obj.color), 2)
                
                # Add label
                label = f"{obj.class_name} {obj.confidence:.2f}"
                cv2.putText(frame, label, (top_left[0], top_left[1]-5), 
                          cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)
                
                # Create detection result
                detection = {
                    "class": obj.class_name,
                    "confidence": obj.confidence + random.gauss(0, 0.02),  # Add noise
                    "bbox": [top_left[0], top_left[1], bottom_right[0], bottom_right[1]],
                    "position": {
                        "x": noisy_pos[0],
                        "y": noisy_pos[1], 
                        "z": noisy_pos[2]
                    },
                    "pixel_position": {
                        "x": pixel_x,
                        "y": pixel_y
                    }
                }
                detected_objects.append(detection)
        
        # Add timestamp
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        cv2.putText(frame, f"Time: {timestamp}", (10, 30), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        # Add frame counter
        cv2.putText(frame, f"Frame: {self.frames_sent}", (10, 50), 
                   cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        # Add FPS
        if self.start_time:
            elapsed = time.time() - self.start_time
            current_fps = self.frames_sent / elapsed if elapsed > 0 else 0
            cv2.putText(frame, f"FPS: {current_fps:.1f}", (10, 70), 
                       cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
        
        return frame, detected_objects
    
    async def send_frame_to_ecps(self, frame: np.ndarray, detections: List[Dict[str, Any]]):
        """Send frame and detection data to ECPS gateway"""
        try:
            # Convert frame to tensor format
            tensor_data = frame.astype(np.float32) / 255.0  # Normalize to [0, 1]
            
            # Encode using LTP
            encoded_data = await self.ltp_processor.encode(tensor_data)
            
            # Create perception message with metadata
            perception_metadata = {
                "timestamp": datetime.now().isoformat(),
                "frame_id": f"frame_{self.frames_sent}",
                "detections": detections,
                "camera_info": {
                    "width": self.width,
                    "height": self.height,
                    "focal_length": self.focal_length,
                    "camera_height": self.camera_height
                }
            }
            
            # Send to ECPS gateway
            await self.client.send_perception_data(encoded_data, perception_metadata)
            
            logger.debug(f"Sent frame {self.frames_sent} with {len(detections)} detections")
            
        except Exception as e:
            logger.error(f"Failed to send frame to ECPS: {e}")
    
    async def run_simulation(self, duration: float = None, display: bool = True):
        """Run the camera simulation"""
        logger.info(f"Starting camera simulation at {self.fps} FPS...")
        
        if display:
            cv2.namedWindow("ECPS Camera Simulator", cv2.WINDOW_AUTOSIZE)
        
        start_time = time.time()
        
        try:
            while True:
                frame_start = time.time()
                
                # Generate frame
                frame, detections = self.generate_frame()
                
                # Send to ECPS
                await self.send_frame_to_ecps(frame, detections)
                
                # Display frame if requested
                if display:
                    cv2.imshow("ECPS Camera Simulator", frame)
                    
                    # Handle keyboard input
                    key = cv2.waitKey(1) & 0xFF
                    if key == ord('q'):
                        logger.info("Quit requested by user")
                        break
                    elif key == ord('s'):
                        # Save screenshot
                        filename = f"ecps_frame_{self.frames_sent}.png"
                        cv2.imwrite(filename, frame)
                        logger.info(f"Saved screenshot: {filename}")
                    elif key == ord('p'):
                        # Pause/unpause
                        logger.info("Paused - press any key to continue")
                        cv2.waitKey(0)
                
                self.frames_sent += 1
                self.time_offset += self.frame_interval
                
                # Check duration limit
                if duration and (time.time() - start_time) >= duration:
                    logger.info(f"Simulation duration {duration}s reached")
                    break
                
                # Maintain frame rate
                frame_time = time.time() - frame_start
                sleep_time = max(0, self.frame_interval - frame_time)
                if sleep_time > 0:
                    await asyncio.sleep(sleep_time)
                
                # Log statistics periodically
                if self.frames_sent % (self.fps * 10) == 0:  # Every 10 seconds
                    elapsed = time.time() - start_time
                    avg_fps = self.frames_sent / elapsed
                    logger.info(f"Sent {self.frames_sent} frames, avg FPS: {avg_fps:.1f}")
                    
        except KeyboardInterrupt:
            logger.info("Simulation interrupted by user")
        except Exception as e:
            logger.error(f"Simulation error: {e}")
        finally:
            if display:
                cv2.destroyAllWindows()
            
            # Final statistics
            elapsed = time.time() - start_time
            avg_fps = self.frames_sent / elapsed if elapsed > 0 else 0
            logger.info(f"Simulation complete: {self.frames_sent} frames in {elapsed:.1f}s (avg {avg_fps:.1f} FPS)")
    
    async def add_dynamic_object(self, obj: SimulatedObject):
        """Add a new object to the scene dynamically"""
        self.objects.append(obj)
        logger.info(f"Added dynamic object: {obj.class_name}")
    
    async def remove_object(self, class_name: str):
        """Remove an object from the scene"""
        self.objects = [obj for obj in self.objects if obj.class_name != class_name]
        logger.info(f"Removed object: {class_name}")
    
    def set_noise_level(self, noise: float):
        """Set the noise level for object positions"""
        self.noise_level = noise
        logger.info(f"Set noise level to {noise}")
    
    async def simulate_object_interaction(self, class_name: str, action: str):
        """Simulate interaction with an object (e.g., picking up, moving)"""
        for obj in self.objects:
            if obj.class_name == class_name:
                if action == "pickup":
                    # Move object up (simulating being picked up)
                    obj.position = (obj.position[0], obj.position[1], obj.position[2] + 0.2)
                    logger.info(f"Simulated pickup of {class_name}")
                elif action == "putdown":
                    # Move object down
                    obj.position = (obj.position[0], obj.position[1], 0.02)
                    logger.info(f"Simulated putdown of {class_name}")
                elif action == "move":
                    # Move object to random position
                    obj.position = (
                        random.uniform(-0.4, 0.4),
                        random.uniform(-0.4, 0.4),
                        obj.position[2]
                    )
                    logger.info(f"Simulated move of {class_name}")
                break

async def main():
    """Main entry point for camera simulator"""
    import argparse
    
    parser = argparse.ArgumentParser(description="ECPS Camera Simulator for Agentic AI Robotics")
    parser.add_argument("--width", type=int, default=640, help="Frame width")
    parser.add_argument("--height", type=int, default=480, help="Frame height")
    parser.add_argument("--fps", type=int, default=30, help="Frames per second")
    parser.add_argument("--duration", type=float, help="Simulation duration in seconds")
    parser.add_argument("--no-display", action="store_true", help="Run without display")
    parser.add_argument("--noise", type=float, default=0.02, help="Position noise level")
    
    args = parser.parse_args()
    
    # Create and initialize simulator
    simulator = CameraSimulator(args.width, args.height, args.fps)
    simulator.set_noise_level(args.noise)
    
    await simulator.initialize()
    
    # Run simulation
    await simulator.run_simulation(
        duration=args.duration,
        display=not args.no_display
    )

if __name__ == "__main__":
    asyncio.run(main())