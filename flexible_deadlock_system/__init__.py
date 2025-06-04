"""
Flexible SQL Deadlock Detection System

A modular and extensible system for detecting various types of deadlocks
in SQL execution workflows with configurable strategies.
"""

from .core.base_detector import BaseDeadlockStrategy, DeadlockResult, DeadlockSeverity
from .core.sql_parser import SQLResourceExtractor
from .core.graph_analyzer import GraphAnalyzer
from .config.detection_config import DetectionConfig, StrategyRegistry
from .strategies.parallel_strategy import ParallelExecutionStrategy
from .strategies.resource_strategy import ResourceContentionStrategy
from .strategies.gateway_strategy import GatewaySpecificStrategy

__version__ = "1.0.0"
__author__ = "SQL Deadlock Detection Team"

__all__ = [
    # Core classes
    'BaseDeadlockStrategy',
    'DeadlockResult', 
    'DeadlockSeverity',
    'SQLResourceExtractor',
    'GraphAnalyzer',
    
    # Configuration
    'DetectionConfig',
    'StrategyRegistry',
    
    # Strategies
    'ParallelExecutionStrategy',
    'ResourceContentionStrategy', 
    'GatewaySpecificStrategy'
]
