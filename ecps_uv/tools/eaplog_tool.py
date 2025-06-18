#!/usr/bin/env python3
"""
EAP Log Management Tool for ECPS-UV SDK.

This command-line utility provides tools for managing, migrating, and
analyzing .eaplog files with version support.
"""

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from actuation.log_versioning import (
    LogReader, LogWriter, LogMigrator, LogValidator, LogVersion,
    detect_log_version, get_log_info, convert_legacy_log
)


async def cmd_info(args):
    """Display information about a log file."""
    try:
        info = await get_log_info(args.file)
        
        print(f"Log File Information: {args.file}")
        print("=" * 50)
        print(f"Version: {info['version']}")
        print(f"File Size: {info['file_size']:,} bytes")
        print(f"Data Offset: {info['data_start_offset']} bytes")
        
        if info.get('created_at'):
            import datetime
            created = datetime.datetime.fromtimestamp(info['created_at'])
            print(f"Created: {created.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if info.get('sdk_version'):
            print(f"SDK Version: {info['sdk_version']}")
        
        if info.get('robot_id'):
            print(f"Robot ID: {info['robot_id']}")
        
        if info.get('session_id'):
            print(f"Session ID: {info['session_id']}")
        
        if info.get('compression') and info['compression'] != 'none':
            print(f"Compression: {info['compression']}")
        
        if info.get('encryption') and info['encryption'] != 'none':
            print(f"Encryption: {info['encryption']}")
        
        if info.get('metadata'):
            print(f"Metadata: {json.dumps(info['metadata'], indent=2)}")
        
    except Exception as e:
        print(f"Error reading log file: {e}", file=sys.stderr)
        return 1
    
    return 0


async def cmd_validate(args):
    """Validate a log file."""
    try:
        results = await LogValidator.validate_file(args.file)
        
        print(f"Validation Results: {args.file}")
        print("=" * 50)
        print(f"Valid: {'✅ Yes' if results['valid'] else '❌ No'}")
        print(f"Version: {results['version'] or 'Unknown'}")
        print(f"Messages: {results['message_count']:,}")
        print(f"File Size: {results['file_size']:,} bytes")
        
        if results['errors']:
            print("\nErrors:")
            for error in results['errors']:
                print(f"  ❌ {error}")
        
        if results['warnings']:
            print("\nWarnings:")
            for warning in results['warnings']:
                print(f"  ⚠️  {warning}")
        
        return 0 if results['valid'] else 1
        
    except Exception as e:
        print(f"Error validating log file: {e}", file=sys.stderr)
        return 1


async def cmd_migrate(args):
    """Migrate a log file to a newer version."""
    try:
        target_version = LogVersion.from_string(args.target_version)
        
        print(f"Migrating {args.source} to {args.target} (v{target_version.value})")
        
        success = await LogMigrator.migrate_file(
            args.source,
            args.target,
            target_version=target_version,
            robot_id=args.robot_id,
            session_id=args.session_id
        )
        
        if success:
            print("✅ Migration completed successfully")
            return 0
        else:
            print("❌ Migration failed", file=sys.stderr)
            return 1
            
    except ValueError as e:
        print(f"Invalid target version: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during migration: {e}", file=sys.stderr)
        return 1


async def cmd_batch_migrate(args):
    """Migrate all log files in a directory."""
    try:
        target_version = LogVersion.from_string(args.target_version)
        
        print(f"Batch migrating from {args.source_dir} to {args.target_dir} (v{target_version.value})")
        
        results = await LogMigrator.batch_migrate(
            args.source_dir,
            args.target_dir,
            target_version=target_version,
            pattern=args.pattern
        )
        
        successful = sum(1 for success in results.values() if success)
        total = len(results)
        
        print(f"\nMigration Results: {successful}/{total} files successful")
        
        for file_path, success in results.items():
            status = "✅" if success else "❌"
            print(f"  {status} {Path(file_path).name}")
        
        return 0 if successful == total else 1
        
    except ValueError as e:
        print(f"Invalid target version: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during batch migration: {e}", file=sys.stderr)
        return 1


async def cmd_convert(args):
    """Convert a legacy log file to the latest version."""
    try:
        print(f"Converting legacy log {args.source} to {args.target}")
        
        success = await convert_legacy_log(args.source, args.target)
        
        if success:
            print("✅ Conversion completed successfully")
            return 0
        else:
            print("❌ Conversion failed", file=sys.stderr)
            return 1
            
    except Exception as e:
        print(f"Error during conversion: {e}", file=sys.stderr)
        return 1


async def cmd_extract(args):
    """Extract messages from a log file."""
    try:
        reader = LogReader(args.file)
        await reader.open()
        
        messages = await reader.read_messages()
        await reader.close()
        
        print(f"Extracted {len(messages)} messages from {args.file}")
        
        if args.output:
            # Save messages to file
            output_path = Path(args.output)
            
            if args.format == 'json':
                # Convert to JSON (simplified representation)
                json_messages = []
                for i, msg in enumerate(messages):
                    json_messages.append({
                        "index": i,
                        "size": len(msg),
                        "data": msg.hex()  # Hex representation
                    })
                
                with open(output_path, 'w') as f:
                    json.dump(json_messages, f, indent=2)
                
                print(f"Saved messages as JSON to {output_path}")
            
            elif args.format == 'binary':
                # Save raw binary data
                with open(output_path, 'wb') as f:
                    for msg in messages:
                        # Write message length and data
                        f.write(len(msg).to_bytes(4, byteorder='little'))
                        f.write(msg)
                
                print(f"Saved raw messages to {output_path}")
        
        else:
            # Print summary to console
            for i, msg in enumerate(messages):
                print(f"Message {i}: {len(msg)} bytes")
        
        return 0
        
    except Exception as e:
        print(f"Error extracting messages: {e}", file=sys.stderr)
        return 1


async def cmd_list_versions(args):
    """List supported log versions."""
    print("Supported Log Versions:")
    print("=" * 30)
    
    for version in LogVersion:
        is_latest = " (latest)" if version == LogVersion.latest() else ""
        print(f"  {version.value}{is_latest}")
    
    return 0


def create_parser():
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="EAP Log Management Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get information about a log file
  python eaplog_tool.py info robot_actions.eaplog
  
  # Validate a log file
  python eaplog_tool.py validate robot_actions.eaplog
  
  # Migrate a log file to version 2.1
  python eaplog_tool.py migrate old.eaplog new.eaplog --target-version 2.1
  
  # Convert legacy log to latest version
  python eaplog_tool.py convert legacy.eaplog modern.eaplog
  
  # Batch migrate all logs in a directory
  python eaplog_tool.py batch-migrate ./old_logs ./new_logs --target-version 2.1
  
  # Extract messages from a log file
  python eaplog_tool.py extract robot_actions.eaplog --output messages.json --format json
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Display log file information')
    info_parser.add_argument('file', help='Path to log file')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate log file')
    validate_parser.add_argument('file', help='Path to log file')
    
    # Migrate command
    migrate_parser = subparsers.add_parser('migrate', help='Migrate log file to newer version')
    migrate_parser.add_argument('source', help='Source log file')
    migrate_parser.add_argument('target', help='Target log file')
    migrate_parser.add_argument('--target-version', default=LogVersion.latest().value,
                               help='Target version (default: latest)')
    migrate_parser.add_argument('--robot-id', help='Robot ID for new header')
    migrate_parser.add_argument('--session-id', help='Session ID for new header')
    
    # Batch migrate command
    batch_parser = subparsers.add_parser('batch-migrate', help='Batch migrate log files')
    batch_parser.add_argument('source_dir', help='Source directory')
    batch_parser.add_argument('target_dir', help='Target directory')
    batch_parser.add_argument('--target-version', default=LogVersion.latest().value,
                             help='Target version (default: latest)')
    batch_parser.add_argument('--pattern', default='*.eaplog',
                             help='File pattern to match (default: *.eaplog)')
    
    # Convert command
    convert_parser = subparsers.add_parser('convert', help='Convert legacy log to latest version')
    convert_parser.add_argument('source', help='Source legacy log file')
    convert_parser.add_argument('target', help='Target modern log file')
    
    # Extract command
    extract_parser = subparsers.add_parser('extract', help='Extract messages from log file')
    extract_parser.add_argument('file', help='Path to log file')
    extract_parser.add_argument('--output', help='Output file path')
    extract_parser.add_argument('--format', choices=['json', 'binary'], default='json',
                               help='Output format (default: json)')
    
    # List versions command
    versions_parser = subparsers.add_parser('list-versions', help='List supported log versions')
    
    return parser


async def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    # Command dispatch
    commands = {
        'info': cmd_info,
        'validate': cmd_validate,
        'migrate': cmd_migrate,
        'batch-migrate': cmd_batch_migrate,
        'convert': cmd_convert,
        'extract': cmd_extract,
        'list-versions': cmd_list_versions,
    }
    
    if args.command in commands:
        return await commands[args.command](args)
    else:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)