#!/usr/bin/env python3
"""
ECPS v1.0 Conformance Test Runner

This script runs conformance tests against ECPS implementations to validate
protocol compliance across different languages and transport layers.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from enum import Enum

class TestResult(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    SKIP = "SKIP"
    ERROR = "ERROR"

@dataclass
class TestCase:
    name: str
    category: str
    description: str
    test_type: str
    input_file: Optional[str] = None
    expected_output: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    timeout: int = 30

@dataclass
class TestExecution:
    test_case: TestCase
    result: TestResult
    duration_ms: int
    stdout: str = ""
    stderr: str = ""
    error_message: str = ""

class ConformanceTestRunner:
    def __init__(self, implementation_path: str, test_vectors_dir: str):
        self.implementation_path = implementation_path
        self.test_vectors_dir = Path(test_vectors_dir)
        self.results: List[TestExecution] = []
        
    def load_test_cases(self, category: Optional[str] = None) -> List[TestCase]:
        """Load test cases from YAML configuration files."""
        test_cases = []
        test_config_file = self.test_vectors_dir / "test-cases.yaml"
        
        if not test_config_file.exists():
            raise FileNotFoundError(f"Test configuration not found: {test_config_file}")
            
        with open(test_config_file, 'r') as f:
            config = yaml.safe_load(f)
            
        for test_data in config.get('test_cases', []):
            if category and test_data.get('category') != category:
                continue
                
            test_case = TestCase(**test_data)
            test_cases.append(test_case)
            
        return test_cases
    
    def run_test_case(self, test_case: TestCase) -> TestExecution:
        """Execute a single test case."""
        print(f"Running test: {test_case.name}")
        
        start_time = time.time()
        
        try:
            # Build command based on test type
            cmd = self._build_test_command(test_case)
            
            # Execute test
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=test_case.timeout,
                cwd=self.test_vectors_dir
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            
            # Determine test result
            if result.returncode == 0:
                test_result = TestResult.PASS
                error_message = ""
            else:
                test_result = TestResult.FAIL
                error_message = f"Exit code: {result.returncode}"
                
            return TestExecution(
                test_case=test_case,
                result=test_result,
                duration_ms=duration_ms,
                stdout=result.stdout,
                stderr=result.stderr,
                error_message=error_message
            )
            
        except subprocess.TimeoutExpired:
            duration_ms = int((time.time() - start_time) * 1000)
            return TestExecution(
                test_case=test_case,
                result=TestResult.ERROR,
                duration_ms=duration_ms,
                error_message=f"Test timed out after {test_case.timeout}s"
            )
            
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return TestExecution(
                test_case=test_case,
                result=TestResult.ERROR,
                duration_ms=duration_ms,
                error_message=str(e)
            )
    
    def _build_test_command(self, test_case: TestCase) -> List[str]:
        """Build the command to execute for a test case."""
        cmd = [self.implementation_path]
        
        if test_case.test_type == "validate-message":
            cmd.extend([
                "validate-message",
                "--type", test_case.config.get("message_type", ""),
                "--input", str(self.test_vectors_dir / test_case.input_file)
            ])
            
        elif test_case.test_type == "transport-test":
            cmd.extend([
                "transport-test",
                "--transport", test_case.config.get("transport", ""),
                "--config", str(self.test_vectors_dir / test_case.config.get("config_file", ""))
            ])
            
        elif test_case.test_type == "mep-query":
            cmd.extend([
                "mep-query",
                "--query", str(self.test_vectors_dir / test_case.input_file),
                "--expected", str(self.test_vectors_dir / test_case.expected_output)
            ])
            
        elif test_case.test_type == "eap-replay":
            cmd.extend([
                "eap-replay",
                "--actions", str(self.test_vectors_dir / test_case.input_file),
                "--state-hashes", str(self.test_vectors_dir / test_case.config.get("state_hashes", ""))
            ])
            
        elif test_case.test_type == "ltp-compression":
            cmd.extend([
                "ltp-compression",
                "--input", str(self.test_vectors_dir / test_case.input_file),
                "--verify-integrity"
            ])
            
        else:
            raise ValueError(f"Unknown test type: {test_case.test_type}")
            
        return cmd
    
    def run_all_tests(self, category: Optional[str] = None) -> List[TestExecution]:
        """Run all test cases in the specified category."""
        test_cases = self.load_test_cases(category)
        
        print(f"Running {len(test_cases)} test cases...")
        
        for test_case in test_cases:
            execution = self.run_test_case(test_case)
            self.results.append(execution)
            
            # Print immediate result
            status_symbol = {
                TestResult.PASS: "✓",
                TestResult.FAIL: "✗", 
                TestResult.SKIP: "⊝",
                TestResult.ERROR: "⚠"
            }[execution.result]
            
            print(f"  {status_symbol} {test_case.name} ({execution.duration_ms}ms)")
            
            if execution.result in [TestResult.FAIL, TestResult.ERROR]:
                print(f"    Error: {execution.error_message}")
                if execution.stderr:
                    print(f"    Stderr: {execution.stderr}")
        
        return self.results
    
    def generate_report(self, format: str = "text") -> str:
        """Generate a test report in the specified format."""
        if format == "json":
            return self._generate_json_report()
        elif format == "junit":
            return self._generate_junit_report()
        else:
            return self._generate_text_report()
    
    def _generate_text_report(self) -> str:
        """Generate a human-readable text report."""
        total_tests = len(self.results)
        passed = sum(1 for r in self.results if r.result == TestResult.PASS)
        failed = sum(1 for r in self.results if r.result == TestResult.FAIL)
        errors = sum(1 for r in self.results if r.result == TestResult.ERROR)
        skipped = sum(1 for r in self.results if r.result == TestResult.SKIP)
        
        total_duration = sum(r.duration_ms for r in self.results)
        
        report = []
        report.append("ECPS v1.0 Conformance Test Report")
        report.append("=" * 40)
        report.append(f"Total Tests: {total_tests}")
        report.append(f"Passed: {passed}")
        report.append(f"Failed: {failed}")
        report.append(f"Errors: {errors}")
        report.append(f"Skipped: {skipped}")
        report.append(f"Total Duration: {total_duration}ms")
        report.append("")
        
        # Group results by category
        categories = {}
        for result in self.results:
            category = result.test_case.category
            if category not in categories:
                categories[category] = []
            categories[category].append(result)
        
        for category, results in categories.items():
            report.append(f"Category: {category}")
            report.append("-" * 20)
            
            for result in results:
                status = result.result.value
                report.append(f"  {status}: {result.test_case.name} ({result.duration_ms}ms)")
                
                if result.result in [TestResult.FAIL, TestResult.ERROR]:
                    report.append(f"    Error: {result.error_message}")
            
            report.append("")
        
        return "\n".join(report)
    
    def _generate_json_report(self) -> str:
        """Generate a JSON report."""
        report_data = {
            "ecps_version": "1.0",
            "test_run_timestamp": time.time(),
            "implementation_path": self.implementation_path,
            "summary": {
                "total_tests": len(self.results),
                "passed": sum(1 for r in self.results if r.result == TestResult.PASS),
                "failed": sum(1 for r in self.results if r.result == TestResult.FAIL),
                "errors": sum(1 for r in self.results if r.result == TestResult.ERROR),
                "skipped": sum(1 for r in self.results if r.result == TestResult.SKIP),
                "total_duration_ms": sum(r.duration_ms for r in self.results)
            },
            "test_results": [
                {
                    "name": r.test_case.name,
                    "category": r.test_case.category,
                    "result": r.result.value,
                    "duration_ms": r.duration_ms,
                    "error_message": r.error_message,
                    "stdout": r.stdout,
                    "stderr": r.stderr
                }
                for r in self.results
            ]
        }
        
        return json.dumps(report_data, indent=2)

def main():
    parser = argparse.ArgumentParser(description="ECPS v1.0 Conformance Test Runner")
    parser.add_argument("--implementation", required=True,
                       help="Path to ECPS implementation conformance test binary")
    parser.add_argument("--test-vectors", default="test-vectors",
                       help="Path to test vectors directory")
    parser.add_argument("--category", 
                       help="Run only tests in specified category")
    parser.add_argument("--report-format", choices=["text", "json", "junit"], 
                       default="text", help="Report output format")
    parser.add_argument("--output", help="Output file for report")
    
    args = parser.parse_args()
    
    # Validate implementation path
    if not os.path.exists(args.implementation):
        print(f"Error: Implementation not found: {args.implementation}")
        sys.exit(1)
    
    # Validate test vectors directory
    test_vectors_dir = Path(__file__).parent.parent / args.test_vectors
    if not test_vectors_dir.exists():
        print(f"Error: Test vectors directory not found: {test_vectors_dir}")
        sys.exit(1)
    
    # Run tests
    runner = ConformanceTestRunner(args.implementation, str(test_vectors_dir))
    results = runner.run_all_tests(args.category)
    
    # Generate report
    report = runner.generate_report(args.report_format)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report written to: {args.output}")
    else:
        print("\n" + report)
    
    # Exit with appropriate code
    failed_tests = sum(1 for r in results if r.result in [TestResult.FAIL, TestResult.ERROR])
    sys.exit(1 if failed_tests > 0 else 0)

if __name__ == "__main__":
    main()