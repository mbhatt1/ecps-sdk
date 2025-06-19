#!/usr/bin/env python3
"""
ECPS Simple Monitor

Simple command-line monitoring for the agentic AI robotic system.
Provides basic observability without a web dashboard.
"""

import asyncio
import time
import json
import logging
from datetime import datetime
import requests
import psutil

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SimpleMonitor:
    """Simple command-line monitor for ECPS Golden Path"""
    
    def __init__(self):
        self.gateway_url = "http://localhost:8080"
        self.robot_url = "http://localhost:8081"
        
    def get_system_stats(self):
        """Get basic system statistics"""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage('/').percent,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            return None
    
    def check_gateway_health(self):
        """Check ECPS Gateway health"""
        try:
            response = requests.get(f"{self.gateway_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def check_robot_health(self):
        """Check Robot Controller health"""
        try:
            response = requests.get(f"{self.robot_url}/health", timeout=5)
            return response.status_code == 200
        except:
            return False
    
    def get_robot_status(self):
        """Get robot status"""
        try:
            response = requests.get(f"{self.robot_url}/status", timeout=5)
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return None
    
    def print_status(self):
        """Print current system status"""
        print("\n" + "="*60)
        print("🤖 ECPS Golden Path - Agentic AI Robotics Monitor")
        print("="*60)
        
        # System stats
        system_stats = self.get_system_stats()
        if system_stats:
            print(f"💻 System: CPU {system_stats['cpu_percent']:.1f}% | "
                  f"Memory {system_stats['memory_percent']:.1f}% | "
                  f"Disk {system_stats['disk_percent']:.1f}%")
        
        # Service health
        gateway_healthy = self.check_gateway_health()
        robot_healthy = self.check_robot_health()
        
        gateway_status = "🟢 Online" if gateway_healthy else "🔴 Offline"
        robot_status = "🟢 Online" if robot_healthy else "🔴 Offline"
        
        print(f"🌐 Gateway: {gateway_status}")
        print(f"🤖 Robot: {robot_status}")
        
        # Robot details
        if robot_healthy:
            robot_status = self.get_robot_status()
            if robot_status:
                pos = robot_status.get('position', {})
                battery = robot_status.get('status', {}).get('battery_level', 0)
                temp = robot_status.get('status', {}).get('temperature', 0)
                
                print(f"   Position: ({pos.get('x', 0):.2f}, {pos.get('y', 0):.2f}, {pos.get('z', 0):.2f})")
                print(f"   Battery: {battery:.1f}% | Temperature: {temp:.1f}°C")
        
        print(f"⏰ Last Update: {datetime.now().strftime('%H:%M:%S')}")
    
    async def run(self, interval=5):
        """Run monitoring loop"""
        logger.info("Starting ECPS Simple Monitor...")
        
        try:
            while True:
                self.print_status()
                await asyncio.sleep(interval)
        except KeyboardInterrupt:
            print("\n\n👋 Monitor stopped by user")
        except Exception as e:
            logger.error(f"Monitor error: {e}")

async def main():
    monitor = SimpleMonitor()
    await monitor.run()

if __name__ == "__main__":
    asyncio.run(main())