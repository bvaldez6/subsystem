"""
Grype Vulnerability Scanner Interface
Docker Exploit Mapper (DEM) - Subsystem 2
Team 16 - Date: 2025-10-27

This module implements the GrypeInterfacer class that integrates Anchore Grype
vulnerability scanner into the DEM system. It extends VulnerabilityToolsHandler
and provides concrete implementation for scanning container images and parsing results.

Setup Instructions:
    1. Create and activate virtual environment:
       python3.11 -m venv venv
       source venv/bin/activate  # On Windows: venv\\Scripts\\activate

    2. Install dependencies:
       pip install -r requirements.txt

    3. Install Grype (choose one method):
       - Using Go: go install github.com/anchore/grype@latest
       - Using Homebrew: brew install grype
       - Download binary: https://github.com/anchore/grype/releases

    4. Verify Grype installation:
       grype version

    5. Ensure Docker is running if scanning container images

Usage Example:
    from grype_interfacer import GrypeInterfacer
    
    # Initialize scanner
    scanner = GrypeInterfacer(config={"timeout": 300})
    
    # Scan a container image
    results = scanner.executeGrypeScan(
        container_image="nginx:latest",
        additional_flags=["--scope", "all-layers"]
    )
    
    # Access parsed vulnerabilities
    vulnerabilities = results["vulnerabilities"]
    print(f"Found {len(vulnerabilities)} vulnerabilities")

Requirements:
    - Python 3.11.4+
    - Grype installed and available in system PATH
    - Docker running (for container image scans)
    - Internet connection for initial vulnerability database download
    - System operates offline after Grype database is cached
"""

import subprocess
import json
import logging
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
import shlex
import sys

from vulnerability_tools_handler import VulnerabilityToolsHandler
from vulnerability import Vulnerability
from vulnerability_assessment_holder import VulnerabilityAssessmentHolder


class GrypeInterfacer(VulnerabilityToolsHandler):
    """
    Concrete implementation of VulnerabilityToolsHandler for Anchore Grype.
    
    This class provides integration with Grype vulnerability scanner, handling
    command execution, output parsing, error management, and result storage.
    
    Attributes:
        grype_path (str): Path to Grype executable
        default_output_format (str): Default output format (json)
        vulnerability_holder (VulnerabilityAssessmentHolder): Repository for storing results
        logger (logging.Logger): Logger inherited from parent class
        config (Dict[str, Any]): Configuration inherited from parent class
    
    Error Codes:
        1: Grype executable not found
        2: Invalid container image path or name
        3: Grype scan execution failed
        4: JSON parsing error
        5: General runtime error
    """
    
    # Class-level constants
    DEFAULT_TIMEOUT = 300  # 5 minutes
    DEFAULT_OUTPUT_FORMAT = "json"
    SUPPORTED_OUTPUT_FORMATS = ["json", "table", "cyclonedx", "sarif"]
    
    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        grype_path: str = "grype",
        vulnerability_holder: Optional[VulnerabilityAssessmentHolder] = None
    ) -> None:
        """
        Initialize the Grype interfacer.
        
        Args:
            config: Optional configuration dictionary with settings like:
                   - timeout: Command execution timeout in seconds (default: 300)
                   - output_format: Output format for Grype (default: "json")
                   - fail_on_severity: Exit with error if severity threshold met
                   - quiet: Suppress Grype output (default: False)
            grype_path: Path to Grype executable (default: "grype" from PATH)
            vulnerability_holder: Repository for storing vulnerabilities (creates new if None)
        
        Raises:
            RuntimeError: If Grype is not installed or not accessible
        
        Postconditions:
            - Grype executable is verified
            - Configuration is initialized with defaults
            - Vulnerability holder is ready
            - Logger is configured
        """
        super().__init__(config)
        
        self.grype_path = grype_path
        self.default_output_format = self.config.get(
            "output_format", self.DEFAULT_OUTPUT_FORMAT
        )
        
        # Initialize vulnerability storage
        self.vulnerability_holder = (
            vulnerability_holder if vulnerability_holder
            else VulnerabilityAssessmentHolder()
        )
        
        # Set default configuration values if not provided
        if "timeout" not in self.config:
            self.config["timeout"] = self.DEFAULT_TIMEOUT
        
        # Verify Grype installation
        if not self._verify_grype_installation():
            error_msg = (
                f"Grype executable not found at '{self.grype_path}'. "
                f"Please install Grype: https://github.com/anchore/grype"
            )
            self.logger.error(error_msg)
            raise RuntimeError(error_msg)
        
        self.logger.info(
            f"Initialized GrypeInterfacer with path: {self.grype_path}, "
            f"timeout: {self.config['timeout']}s"
        )
    
    def _verify_grype_installation(self) -> bool:
        """
        Verify that Grype is installed and accessible.
        
        Returns:
            True if Grype is available, False otherwise
        
        Postcondition:
            - Logs Grype version if found
            - Logs error if not found
        """
        try:
            # Run 'grype version' to verify installation
            result = subprocess.run(
                [self.grype_path, "version"],
                capture_output=True,
                text=True,
                timeout=10,
                check=False
            )
            
            if result.returncode == 0:
                version_info = result.stdout.strip()
                self.logger.info(f"Grype found: {version_info}")
                return True
            else:
                self.logger.error(f"Grype version check failed: {result.stderr}")
                return False
                
        except FileNotFoundError:
            self.logger.error(f"Grype executable not found: {self.grype_path}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.error("Grype version check timed out")
            return False
        except Exception as e:
            self.logger.error(f"Error verifying Grype installation: {e}")
            return False
    
    def execute_scan(
        self,
        target: str,
        additional_flags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute a vulnerability scan on the specified target.
        
        This method implements the abstract method from VulnerabilityToolsHandler.
        It delegates to executeGrypeScan for Grype-specific logic.
        
        Args:
            target: Container image name or path (e.g., "nginx:latest")
            additional_flags: Optional list of Grype command-line flags
        
        Returns:
            Dictionary containing scan results with keys:
                - status: "success" or "error"
                - vulnerabilities: List of Vulnerability objects
                - summary: Scan summary statistics
                - raw_output: Raw Grype output (if available)
                - error: Error message (if status is "error")
        
        Raises:
            ValueError: If target is invalid
            RuntimeError: If scan execution fails
        
        Preconditions:
            - target must be non-empty string
            - Grype must be installed and accessible
        
        Postconditions:
            - Scan results are parsed and stored
            - Vulnerabilities are available in vulnerability_holder
        """
        return self.executeGrypeScan(target, additional_flags)
    
    def executeGrypeScan(
        self,
        container_image: str,
        additional_flags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Execute Grype scan on a container image.
        
        This is the main method for performing vulnerability scans. It constructs
        the Grype command, executes it, parses the output, and stores results.
        
        Args:
            container_image: Docker image name/tag (e.g., "nginx:latest", "ubuntu:20.04")
                           Can also be image digest or local image ID
            additional_flags: Optional Grype flags like:
                            - ["--scope", "all-layers"]: Scan all image layers
                            - ["--fail-on", "critical"]: Exit on critical vulnerabilities
                            - ["--only-fixed"]: Show only fixed vulnerabilities
        
        Returns:
            Dictionary with scan results:
                {
                    "status": "success",
                    "target": "nginx:latest",
                    "vulnerabilities": [Vulnerability, ...],
                    "summary": {
                        "total": 42,
                        "critical": 2,
                        "high": 10,
                        "medium": 20,
                        "low": 10
                    },
                    "scan_timestamp": "2025-10-27T12:00:00Z",
                    "raw_output": {...}
                }
        
        Raises:
            ValueError: If container_image is invalid
            RuntimeError: If scan execution fails
        
        Example:
            scanner = GrypeInterfacer()
            results = scanner.executeGrypeScan(
                "nginx:latest",
                ["--scope", "all-layers", "--only-fixed"]
            )
            print(f"Found {results['summary']['total']} vulnerabilities")
        
        Preconditions:
            - container_image must be valid Docker image reference
            - Docker must be running (for remote images)
            - Grype database must be updated
        
        Postconditions:
            - Vulnerabilities are parsed and stored in vulnerability_holder
            - Scan results are logged
            - Returns structured result dictionary
        """
        # Input validation
        if not self.validate_target(container_image):
            error_msg = f"Invalid container image: {container_image}"
            self.logger.error(error_msg)
            return self._create_error_result(container_image, error_msg, error_code=2)
        
        self.logger.info(f"Starting Grype scan for: {container_image}")
        
        try:
            # Build Grype command
            command = self._build_grype_command(container_image, additional_flags)
            self.logger.debug(f"Executing command: {' '.join(command)}")
            
            # Execute Grype scan
            scan_start_time = datetime.utcnow()
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.config.get("timeout", self.DEFAULT_TIMEOUT),
                check=False  # Don't raise exception on non-zero exit
            )
            scan_end_time = datetime.utcnow()
            scan_duration = (scan_end_time - scan_start_time).total_seconds()
            
            self.logger.debug(
                f"Grype scan completed in {scan_duration:.2f}s "
                f"(exit code: {result.returncode})"
            )
            
            # Check for execution errors
            # Note: Grype may return non-zero exit code if vulnerabilities found
            # Only treat it as error if stderr contains error messages
            if result.returncode != 0 and result.stderr:
                # Check if this is a real error or just vulnerability findings
                if "error" in result.stderr.lower() or "fatal" in result.stderr.lower():
                    error_msg = f"Grype scan failed: {result.stderr}"
                    self.logger.error(error_msg)
                    return self.handleError(
                        error_msg,
                        error_code=3,
                        context={"container_image": container_image}
                    )
            
            # Parse JSON output
            parsed_results = self.parseOutput(result.stdout, container_image)
            
            # Store vulnerabilities
            if parsed_results["status"] == "success":
                vulnerabilities = parsed_results["vulnerabilities"]
                added_count = self.vulnerability_holder.add_vulnerabilities(vulnerabilities)
                self.logger.info(
                    f"Scan completed: {added_count} vulnerabilities stored "
                    f"for {container_image}"
                )
            
            return parsed_results
            
        except subprocess.TimeoutExpired:
            error_msg = (
                f"Grype scan timed out after {self.config['timeout']}s "
                f"for {container_image}"
            )
            self.logger.error(error_msg)
            return self.handleError(
                error_msg,
                error_code=3,
                context={"container_image": container_image, "timeout": self.config["timeout"]}
            )
            
        except Exception as e:
            error_msg = f"Unexpected error during Grype scan: {str(e)}"
            self.logger.error(error_msg, exc_info=True)
            return self.handleError(
                error_msg,
                error_code=5,
                context={"container_image": container_image, "exception": str(e)}
            )
    
    def _build_grype_command(
        self,
        container_image: str,
        additional_flags: Optional[List[str]] = None
    ) -> List[str]:
        """
        Build the Grype command with appropriate flags.
        
        Args:
            container_image: Docker image to scan
            additional_flags: Additional command-line flags
        
        Returns:
            List of command arguments for subprocess
        
        Postcondition:
            - Returns valid command list with all required flags
        """
        command = [
            self.grype_path,
            container_image,
            "--output", self.default_output_format,
        ]
        
        # Add quiet flag if configured
        if self.config.get("quiet", False):
            command.append("--quiet")
        
        # Add additional flags if provided
        if additional_flags:
            # Validate and sanitize flags
            for flag in additional_flags:
                if not isinstance(flag, str):
                    self.logger.warning(f"Skipping non-string flag: {flag}")
                    continue
                # Basic sanitization: remove potentially dangerous characters
                sanitized_flag = shlex.quote(flag) if flag.startswith("-") else flag
                command.append(sanitized_flag)
        
        return command
    
    def parseOutput(
        self,
        grype_output: str,
        container_image: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Parse Grype JSON output into Vulnerability objects.
        
        This method transforms raw Grype JSON output into structured Vulnerability
        objects that can be stored and queried.
        
        Args:
            grype_output: Raw JSON output from Grype command
            container_image: Name of scanned image (for logging/tracking)
        
        Returns:
            Dictionary containing:
                - status: "success" or "error"
                - vulnerabilities: List of Vulnerability objects
                - summary: Statistics about findings
                - scan_timestamp: When scan was performed
                - raw_output: Original JSON output
        
        Raises:
            json.JSONDecodeError: If output is not valid JSON
            KeyError: If expected fields are missing from JSON
        
        Example:
            json_output = '{"matches": [...], "source": {...}}'
            results = scanner.parseOutput(json_output, "nginx:latest")
        
        Preconditions:
            - grype_output must be valid JSON string
            - grype_output must follow Grype output schema
        
        Postconditions:
            - Returns structured result dictionary
            - Vulnerabilities are validated Vulnerability objects
        """
        self.logger.debug(f"Parsing Grype output for {container_image}")
        
        try:
            # Parse JSON output
            if not grype_output or not grype_output.strip():
                self.logger.warning("Empty Grype output received")
                return {
                    "status": "success",
                    "target": container_image,
                    "vulnerabilities": [],
                    "summary": self._create_summary([]),
                    "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                    "raw_output": None
                }
            
            parsed_json = json.loads(grype_output)
            
            # Extract vulnerability matches from Grype output
            # Grype JSON schema: {"matches": [...], "source": {...}, ...}
            matches = parsed_json.get("matches", [])
            
            if not matches:
                self.logger.info(f"No vulnerabilities found for {container_image}")
                return {
                    "status": "success",
                    "target": container_image,
                    "vulnerabilities": [],
                    "summary": self._create_summary([]),
                    "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                    "raw_output": parsed_json
                }
            
            # Convert Grype matches to Vulnerability objects
            vulnerabilities = []
            for match in matches:
                try:
                    vuln = self._parse_grype_match(match)
                    vulnerabilities.append(vuln)
                except Exception as e:
                    # Log parsing error but continue with other matches
                    self.logger.warning(
                        f"Failed to parse vulnerability match: {e}",
                        exc_info=True
                    )
                    continue
            
            # Sort vulnerabilities by severity
            vulnerabilities.sort()
            
            self.logger.info(
                f"Parsed {len(vulnerabilities)} vulnerabilities from Grype output"
            )
            
            return {
                "status": "success",
                "target": container_image,
                "vulnerabilities": vulnerabilities,
                "summary": self._create_summary(vulnerabilities),
                "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                "raw_output": parsed_json
            }
            
        except json.JSONDecodeError as e:
            error_msg = f"Failed to parse Grype JSON output: {e}"
            self.logger.error(error_msg)
            return self.handleError(
                error_msg,
                error_code=4,
                context={"container_image": container_image, "parse_error": str(e)}
            )
            
        except Exception as e:
            error_msg = f"Error parsing Grype output: {e}"
            self.logger.error(error_msg, exc_info=True)
            return self.handleError(
                error_msg,
                error_code=5,
                context={"container_image": container_image, "exception": str(e)}
            )
    
    def _parse_grype_match(self, match: Dict[str, Any]) -> Vulnerability:
        """
        Parse a single Grype vulnerability match into a Vulnerability object.
        
        Args:
            match: Dictionary from Grype JSON "matches" array
        
        Returns:
            Vulnerability object with parsed data
        
        Grype Match Schema (simplified):
            {
                "vulnerability": {
                    "id": "CVE-2024-1234",
                    "severity": "High",
                    "description": "...",
                    "cvss": [{"metrics": {"baseScore": 7.5}}]
                },
                "artifact": {
                    "name": "openssl",
                    "version": "1.1.1"
                },
                "relatedVulnerabilities": [...],
                "matchDetails": [{"found": {...}, "searchedBy": {...}}]
            }
        
        Raises:
            KeyError: If required fields are missing
            ValueError: If data is invalid
        """
        vuln_data = match.get("vulnerability", {})
        artifact_data = match.get("artifact", {})
        
        # Extract CVE ID
        cve_id = vuln_data.get("id", "UNKNOWN")
        
        # Extract severity and normalize
        severity = vuln_data.get("severity", "Unknown")
        severity = severity.capitalize()  # Normalize: "HIGH" -> "High"
        
        # Extract description
        description = vuln_data.get("description", "No description available")
        
        # Extract package information
        package = artifact_data.get("name", "unknown-package")
        package_version = artifact_data.get("version")
        
        # Extract fix information
        fixed_version = None
        match_details = match.get("matchDetails", [])
        if match_details:
            for detail in match_details:
                found = detail.get("found", {})
                fixed_in_versions = found.get("versionConstraint", "")
                if fixed_in_versions:
                    fixed_version = fixed_in_versions
                    break
        
        # Extract CVSS score
        cvss_score = None
        cvss_data = vuln_data.get("cvss", [])
        if cvss_data and isinstance(cvss_data, list) and len(cvss_data) > 0:
            metrics = cvss_data[0].get("metrics", {})
            cvss_score = metrics.get("baseScore")
        
        # Build remediation message
        if fixed_version:
            remediation = f"Upgrade {package} to version {fixed_version} or later"
        else:
            remediation = f"No fix available yet for {package}. Monitor vendor advisories."
        
        # Create Vulnerability object
        vulnerability = Vulnerability(
            cve_id=cve_id,
            severity=severity,
            description=description,
            package=package,
            remediation=remediation,
            package_version=package_version,
            fixed_version=fixed_version,
            cvss_score=cvss_score,
            discovered_at=datetime.utcnow(),
            metadata={
                "source": "grype",
                "match_details": match_details,
                "related_vulnerabilities": match.get("relatedVulnerabilities", [])
            }
        )
        
        return vulnerability
    
    def _create_summary(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """
        Create summary statistics from vulnerability list.
        
        Args:
            vulnerabilities: List of Vulnerability objects
        
        Returns:
            Dictionary with severity counts
        """
        summary = {
            "total": len(vulnerabilities),
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Negligible": 0,
            "Unknown": 0
        }
        
        for vuln in vulnerabilities:
            if vuln.severity in summary:
                summary[vuln.severity] += 1
        
        return summary
    
    def handleError(
        self,
        error_message: str,
        error_code: int = 5,
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Handle and log scan failures with appropriate error codes.
        
        This method provides centralized error handling and logging for all
        scan-related failures. It creates a standardized error response.
        
        Args:
            error_message: Description of the error
            error_code: Numeric error code:
                       1 = Grype not found
                       2 = Invalid input
                       3 = Execution failure
                       4 = Parse error
                       5 = General error
            context: Additional context information for debugging
        
        Returns:
            Dictionary with error information:
                {
                    "status": "error",
                    "error": "...",
                    "error_code": 3,
                    "timestamp": "2025-10-27T12:00:00Z",
                    "context": {...}
                }
        
        Postcondition:
            - Error is logged with appropriate level
            - Returns structured error dictionary
        """
        # Map error codes to descriptions
        error_codes = {
            1: "GRYPE_NOT_FOUND",
            2: "INVALID_INPUT",
            3: "EXECUTION_FAILURE",
            4: "PARSE_ERROR",
            5: "GENERAL_ERROR"
        }
        
        error_type = error_codes.get(error_code, "UNKNOWN_ERROR")
        
        # Log with appropriate level based on severity
        if error_code in {1, 3}:
            # Critical errors
            self.logger.error(
                f"[{error_type}] {error_message}",
                extra={"error_code": error_code, "context": context}
            )
        else:
            # Non-critical errors
            self.logger.warning(
                f"[{error_type}] {error_message}",
                extra={"error_code": error_code, "context": context}
            )
        
        return {
            "status": "error",
            "error": error_message,
            "error_code": error_code,
            "error_type": error_type,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "context": context or {}
        }
    
    def _create_error_result(
        self,
        target: str,
        error_message: str,
        error_code: int = 5
    ) -> Dict[str, Any]:
        """
        Create a standardized error result dictionary.
        
        Args:
            target: Scan target that failed
            error_message: Error description
            error_code: Numeric error code
        
        Returns:
            Error result dictionary
        """
        return self.handleError(
            error_message,
            error_code=error_code,
            context={"target": target}
        )
    
    def get_vulnerability_holder(self) -> VulnerabilityAssessmentHolder:
        """
        Get reference to the vulnerability storage repository.
        
        Returns:
            VulnerabilityAssessmentHolder instance
        
        Example:
            holder = scanner.get_vulnerability_holder()
            critical_vulns = holder.get_vulnerabilities_by_severity("Critical")
        """
        return self.vulnerability_holder
    
    def scan_multiple_images(
        self,
        images: List[str],
        additional_flags: Optional[List[str]] = None,
        continue_on_error: bool = True
    ) -> Dict[str, Dict[str, Any]]:
        """
        Scan multiple container images in sequence.
        
        This is a convenience method for batch scanning multiple images.
        
        Args:
            images: List of container image names to scan
            additional_flags: Flags to apply to all scans
            continue_on_error: Continue scanning if one image fails
        
        Returns:
            Dictionary mapping image names to scan results
        
        Example:
            results = scanner.scan_multiple_images([
                "nginx:latest",
                "ubuntu:20.04",
                "python:3.11"
            ])
        
        Postcondition:
            - All images are scanned (if continue_on_error=True)
            - Results are aggregated in vulnerability_holder
        """
        results = {}
        
        self.logger.info(f"Starting batch scan of {len(images)} images")
        
        for image in images:
            try:
                result = self.executeGrypeScan(image, additional_flags)
                results[image] = result
                
                if result["status"] == "error" and not continue_on_error:
                    self.logger.error(f"Stopping batch scan due to error with {image}")
                    break
                    
            except Exception as e:
                self.logger.error(f"Failed to scan {image}: {e}", exc_info=True)
                results[image] = self.handleError(
                    f"Exception during scan: {e}",
                    error_code=5,
                    context={"image": image}
                )
                
                if not continue_on_error:
                    break
        
        self.logger.info(
            f"Batch scan completed: {len(results)}/{len(images)} images scanned"
        )
        
        return results
    
    def __repr__(self) -> str:
        """String representation for debugging."""
        return (
            f"GrypeInterfacer(grype_path={self.grype_path}, "
            f"timeout={self.config.get('timeout')}, "
            f"vulnerabilities_stored={len(self.vulnerability_holder)})"
        )


# Contract enforcement utilities (optional - uncomment if using pycontracts)
# from contracts import contract
# 
# @contract(container_image='str,len>0', returns='dict')
# def executeGrypeScan_with_contract(self, container_image: str, ...) -> Dict[str, Any]:
#     """Version with design-by-contract enforcement"""
#     pass

