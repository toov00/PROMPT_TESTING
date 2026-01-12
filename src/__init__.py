"""
Prompt Injection Testing Suite
A comprehensive framework for testing LLM applications against prompt injection attacks.
"""

from .prompt_injection_tester import (
    PromptInjectionTester,
    VulnerabilityDetector,
    AttackVectorLibrary,
    AttackCategory,
    Severity,
    AttackVector,
    TestResult,
)

__version__ = "1.0.0"
__author__ = "Your Name"

__all__ = [
    "PromptInjectionTester",
    "VulnerabilityDetector", 
    "AttackVectorLibrary",
    "AttackCategory",
    "Severity",
    "AttackVector",
    "TestResult",
]
