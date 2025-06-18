"""
EAP Log Versioning System for ECPS-UV SDK.

This module provides versioning support for .eaplog files, including
version headers, migration utilities, and backward compatibility.
"""

import asyncio
import json
import logging
import os
import struct
import time
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Any, Dict, List, Optional, Union, BinaryIO
from pathlib import Path

logger = logging.getLogger("ecps_uv.actuation.log_versioning")


class LogVersion(Enum):
    """Supported log file versions."""
    V1_0 = "1.0"  # Legacy format (no header)
    V1_1 = "1.1"  # Added basic header with version
    V2_0 = "2.0"  # Enhanced header with metadata and checksums
    V2_1 = "2.1"  # Added compression and encryption support
    
    @classmethod
    def latest(cls) -> "LogVersion":
        """Get the latest supported version."""
        return cls.V2_1
    
    @classmethod
    def from_string(cls, version_str: str) -> "LogVersion":
        """Create LogVersion from string."""
        for version in cls:
            if version.value == version_str:
                return version
        raise ValueError(f"Unsupported log version: {version_str}")


@dataclass
class LogHeader:
    """Header structure for versioned .eaplog files."""
    magic: bytes = b"EAPLOG"  # Magic bytes to identify EAP log files
    version: str = LogVersion.latest().value
    created_at: float = 0.0
    sdk_version: str = "1.0.0"
    robot_id: Optional[str] = None
    session_id: Optional[str] = None
    compression: str = "none"  # none, gzip, lz4
    encryption: str = "none"   # none, aes256
    checksum_type: str = "crc32"  # crc32, sha256
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.metadata is None:
            self.metadata = {}
    
    def to_bytes(self) -> bytes:
        """Serialize header to bytes."""
        # Create header dictionary
        header_dict = asdict(self)
        header_dict['magic'] = self.magic.decode('utf-8')
        
        # Serialize to JSON
        header_json = json.dumps(header_dict, separators=(',', ':')).encode('utf-8')
        
        # Create header with length prefix
        header_length = len(header_json)
        header_bytes = struct.pack('<I', header_length) + header_json
        
        return header_bytes
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "LogHeader":
        """Deserialize header from bytes."""
        # Read header length
        if len(data) < 4:
            raise ValueError("Invalid header: too short")
        
        header_length = struct.unpack('<I', data[:4])[0]
        
        # Read header JSON
        if len(data) < 4 + header_length:
            raise ValueError("Invalid header: incomplete")
        
        header_json = data[4:4 + header_length]
        header_dict = json.loads(header_json.decode('utf-8'))
        
        # Convert magic back to bytes
        header_dict['magic'] = header_dict['magic'].encode('utf-8')
        
        return cls(**header_dict)
    
    def get_header_size(self) -> int:
        """Get the total size of the header in bytes."""
        return len(self.to_bytes())


class LogReader:
    """Reader for versioned .eaplog files with backward compatibility."""
    
    def __init__(self, file_path: str):
        """
        Initialize log reader.
        
        Args:
            file_path: Path to the .eaplog file
        """
        self.file_path = Path(file_path)
        self.header: Optional[LogHeader] = None
        self.version: LogVersion = LogVersion.V1_0  # Default to legacy
        self.file_handle: Optional[BinaryIO] = None
        self.data_start_offset: int = 0
    
    async def open(self):
        """Open and analyze the log file."""
        if not self.file_path.exists():
            raise FileNotFoundError(f"Log file not found: {self.file_path}")
        
        self.file_handle = open(self.file_path, 'rb')
        
        # Try to read header
        try:
            await self._detect_version()
        except Exception as e:
            logger.warning(f"Failed to detect log version, assuming legacy: {e}")
            self.version = LogVersion.V1_0
            self.data_start_offset = 0
            self.file_handle.seek(0)
    
    async def _detect_version(self):
        """Detect the log file version."""
        # Read potential magic bytes
        magic_bytes = self.file_handle.read(6)
        
        if magic_bytes == b"EAPLOG":
            # This is a versioned log file
            self.file_handle.seek(0)
            
            # Read header length
            header_length_bytes = self.file_handle.read(4)
            if len(header_length_bytes) < 4:
                raise ValueError("Invalid versioned log file")
            
            header_length = struct.unpack('<I', header_length_bytes)[0]
            
            # Read header
            header_data = header_length_bytes + self.file_handle.read(header_length)
            self.header = LogHeader.from_bytes(header_data)
            self.version = LogVersion.from_string(self.header.version)
            self.data_start_offset = len(header_data)
            
            logger.info(f"Detected versioned log file: {self.version.value}")
        else:
            # This is a legacy log file (no header)
            self.version = LogVersion.V1_0
            self.data_start_offset = 0
            self.file_handle.seek(0)
            
            logger.info("Detected legacy log file (no version header)")
    
    async def read_messages(self) -> List[bytes]:
        """Read all messages from the log file."""
        if not self.file_handle:
            raise RuntimeError("Log file not opened")
        
        messages = []
        self.file_handle.seek(self.data_start_offset)
        
        while True:
            # Read message length
            length_bytes = self.file_handle.read(4)
            if len(length_bytes) < 4:
                break  # End of file
            
            message_length = struct.unpack('<I', length_bytes)[0]
            
            # Read message data
            message_data = self.file_handle.read(message_length)
            if len(message_data) < message_length:
                logger.warning("Incomplete message at end of log file")
                break
            
            messages.append(message_data)
        
        return messages
    
    async def close(self):
        """Close the log file."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
    
    def get_info(self) -> Dict[str, Any]:
        """Get information about the log file."""
        info = {
            "file_path": str(self.file_path),
            "version": self.version.value,
            "file_size": self.file_path.stat().st_size,
            "data_start_offset": self.data_start_offset,
        }
        
        if self.header:
            info.update({
                "created_at": self.header.created_at,
                "sdk_version": self.header.sdk_version,
                "robot_id": self.header.robot_id,
                "session_id": self.header.session_id,
                "compression": self.header.compression,
                "encryption": self.header.encryption,
                "metadata": self.header.metadata,
            })
        
        return info


class LogWriter:
    """Writer for versioned .eaplog files."""
    
    def __init__(
        self,
        file_path: str,
        version: LogVersion = LogVersion.latest(),
        robot_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize log writer.
        
        Args:
            file_path: Path to the .eaplog file
            version: Log format version to use
            robot_id: Robot identifier
            session_id: Session identifier
            metadata: Additional metadata
        """
        self.file_path = Path(file_path)
        self.version = version
        self.header = LogHeader(
            version=version.value,
            robot_id=robot_id,
            session_id=session_id,
            metadata=metadata or {}
        )
        self.file_handle: Optional[BinaryIO] = None
        self.message_count = 0
    
    async def open(self):
        """Open the log file for writing."""
        # Ensure directory exists
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.file_handle = open(self.file_path, 'wb')
        
        # Write header for versioned formats
        if self.version != LogVersion.V1_0:
            header_bytes = self.header.to_bytes()
            self.file_handle.write(header_bytes)
            self.file_handle.flush()
            
            logger.info(f"Created versioned log file: {self.file_path} (v{self.version.value})")
        else:
            logger.info(f"Created legacy log file: {self.file_path}")
    
    async def write_message(self, message_data: bytes):
        """Write a message to the log file."""
        if not self.file_handle:
            raise RuntimeError("Log file not opened")
        
        # Write message length and data (same format as legacy)
        message_length = len(message_data)
        self.file_handle.write(struct.pack('<I', message_length))
        self.file_handle.write(message_data)
        self.file_handle.flush()
        
        self.message_count += 1
    
    async def close(self):
        """Close the log file."""
        if self.file_handle:
            self.file_handle.close()
            self.file_handle = None
            
            logger.info(f"Closed log file: {self.file_path} ({self.message_count} messages)")


class LogMigrator:
    """Utility for migrating log files between versions."""
    
    @staticmethod
    async def migrate_file(
        source_path: str,
        target_path: str,
        target_version: LogVersion = LogVersion.latest(),
        robot_id: Optional[str] = None,
        session_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Migrate a log file to a newer version.
        
        Args:
            source_path: Path to source log file
            target_path: Path to target log file
            target_version: Target version for migration
            robot_id: Robot identifier for new header
            session_id: Session identifier for new header
            metadata: Additional metadata for new header
            
        Returns:
            True if migration successful, False otherwise
        """
        try:
            # Read source file
            reader = LogReader(source_path)
            await reader.open()
            
            source_info = reader.get_info()
            logger.info(f"Migrating log file from v{reader.version.value} to v{target_version.value}")
            
            # Read all messages
            messages = await reader.read_messages()
            await reader.close()
            
            # Create migration metadata
            migration_metadata = metadata or {}
            migration_metadata.update({
                "migrated_from_version": reader.version.value,
                "migrated_at": time.time(),
                "original_file": source_path,
                "message_count": len(messages),
            })
            
            # If source had metadata, preserve it
            if source_info.get("metadata"):
                migration_metadata["original_metadata"] = source_info["metadata"]
            
            # Write target file
            writer = LogWriter(
                target_path,
                version=target_version,
                robot_id=robot_id or source_info.get("robot_id"),
                session_id=session_id or source_info.get("session_id"),
                metadata=migration_metadata
            )
            
            await writer.open()
            
            # Write all messages
            for message in messages:
                await writer.write_message(message)
            
            await writer.close()
            
            logger.info(f"Successfully migrated {len(messages)} messages to {target_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to migrate log file: {e}")
            return False
    
    @staticmethod
    async def batch_migrate(
        source_dir: str,
        target_dir: str,
        target_version: LogVersion = LogVersion.latest(),
        pattern: str = "*.eaplog"
    ) -> Dict[str, bool]:
        """
        Migrate all log files in a directory.
        
        Args:
            source_dir: Source directory
            target_dir: Target directory
            target_version: Target version for migration
            pattern: File pattern to match
            
        Returns:
            Dictionary mapping file paths to migration success status
        """
        source_path = Path(source_dir)
        target_path = Path(target_dir)
        
        # Ensure target directory exists
        target_path.mkdir(parents=True, exist_ok=True)
        
        results = {}
        
        for source_file in source_path.glob(pattern):
            target_file = target_path / source_file.name
            
            success = await LogMigrator.migrate_file(
                str(source_file),
                str(target_file),
                target_version
            )
            
            results[str(source_file)] = success
        
        return results


class LogValidator:
    """Utility for validating log file integrity."""
    
    @staticmethod
    async def validate_file(file_path: str) -> Dict[str, Any]:
        """
        Validate a log file and return validation results.
        
        Args:
            file_path: Path to log file
            
        Returns:
            Validation results dictionary
        """
        results = {
            "valid": False,
            "version": None,
            "message_count": 0,
            "errors": [],
            "warnings": [],
            "file_size": 0,
        }
        
        try:
            file_path_obj = Path(file_path)
            if not file_path_obj.exists():
                results["errors"].append("File does not exist")
                return results
            
            results["file_size"] = file_path_obj.stat().st_size
            
            # Try to read the file
            reader = LogReader(file_path)
            await reader.open()
            
            results["version"] = reader.version.value
            
            # Read and count messages
            messages = await reader.read_messages()
            results["message_count"] = len(messages)
            
            await reader.close()
            
            # Basic validation checks
            if results["message_count"] == 0:
                results["warnings"].append("Log file contains no messages")
            
            if results["file_size"] == 0:
                results["warnings"].append("Log file is empty")
            
            # Version-specific validation
            if reader.version == LogVersion.V1_0:
                results["warnings"].append("Legacy log format (no version header)")
            
            results["valid"] = len(results["errors"]) == 0
            
        except Exception as e:
            results["errors"].append(f"Validation failed: {e}")
        
        return results


# Utility functions for backward compatibility
async def detect_log_version(file_path: str) -> LogVersion:
    """Detect the version of a log file."""
    reader = LogReader(file_path)
    await reader.open()
    version = reader.version
    await reader.close()
    return version


async def get_log_info(file_path: str) -> Dict[str, Any]:
    """Get information about a log file."""
    reader = LogReader(file_path)
    await reader.open()
    info = reader.get_info()
    await reader.close()
    return info


async def convert_legacy_log(source_path: str, target_path: str) -> bool:
    """Convert a legacy log file to the latest version."""
    return await LogMigrator.migrate_file(source_path, target_path)