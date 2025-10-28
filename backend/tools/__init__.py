"""
Docker Exploit Mapper (DEM) - Subsystem 2 Backend
Team 16 - Date: 2025-10-27

This package contains the vulnerability scanning components for the DEM system.

Main Components:
    - VulnerabilityToolsHandler: Abstract base class for scanner integrations
    - GrypeInterfacer: Concrete implementation for Anchore Grype scanner
    - Vulnerability: Data model for vulnerability information
    - VulnerabilityAssessmentHolder: Repository for storing scan results

Usage:
    from backend.grype_interfacer import GrypeInterfacer
    from backend.vulnerability import Vulnerability
    from backend.vulnerability_assessment_holder import VulnerabilityAssessmentHolder
"""

__version__ = "1.0.0"
__author__ = "Team 16"
__date__ = "2025-10-27"

# Import main classes for easy access
from .vulnerability import Vulnerability, Severity
from .vulnerability_tools_handler import VulnerabilityToolsHandler
from .grype_interfacer import GrypeInterfacer
from .vulnerability_assessment_holder import VulnerabilityAssessmentHolder

__all__ = [
    "Vulnerability",
    "Severity",
    "VulnerabilityToolsHandler",
    "GrypeInterfacer",
    "VulnerabilityAssessmentHolder",
]

