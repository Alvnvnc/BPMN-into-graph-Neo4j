"""
XPDL to Neo4j Converter Package

This package provides tools for converting XPDL files (BPMN diagrams) to Neo4j graphs,
enabling deep analysis of business processes, including deadlock detection.
"""

# Change relative imports to absolute
from converter import XPDLToNeo4jConverter
from deadlock_detector import DeadlockDetector
from config import load_config, save_config
from utils import generate_cypher_query_examples, save_query_examples

__all__ = [
    'XPDLToNeo4jConverter',
    'DeadlockDetector',
    'load_config',
    'save_config',
    'generate_cypher_query_examples',
    'save_query_examples'
]