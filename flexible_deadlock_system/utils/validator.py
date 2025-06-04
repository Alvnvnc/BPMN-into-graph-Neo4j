"""
Validation utilities for the flexible deadlock detection system.
"""

from typing import List, Dict, Any, Optional, Set, Union
import re
from pathlib import Path
import json
import sys

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.base_detector import DeadlockResult, DeadlockSeverity


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


class InputValidator:
    """
    Validates inputs for the deadlock detection system.
    """
    
    @staticmethod
    def validate_sql_query(sql: str) -> bool:
        """
        Validate SQL query format and structure.
        
        Args:
            sql: SQL query string
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If SQL is invalid
        """
        if not sql or not isinstance(sql, str):
            raise ValidationError("SQL query must be a non-empty string")
        
        sql_clean = sql.strip().upper()
        
        # Check for basic SQL keywords
        sql_keywords = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER']
        if not any(keyword in sql_clean for keyword in sql_keywords):
            raise ValidationError("SQL query must contain at least one valid SQL keyword")
        
        # Check for potential injection attempts (basic check)
        dangerous_patterns = [
            r';\s*(DROP|DELETE|UPDATE|INSERT)',
            r'UNION\s+SELECT',
            r'--\s*',
            r'/\*.*\*/'
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, sql_clean, re.IGNORECASE):
                raise ValidationError(f"Potentially dangerous SQL pattern detected: {pattern}")
        
        return True
    
    @staticmethod
    def validate_node_data(node_data: Dict[str, Any]) -> bool:
        """
        Validate node data structure.
        
        Args:
            node_data: Dictionary containing node information
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If node data is invalid
        """
        if not isinstance(node_data, dict):
            raise ValidationError("Node data must be a dictionary")
        
        # Check for required fields (allow both 'type' and 'element_type')
        if 'id' not in node_data:
            raise ValidationError("Node data must contain 'id' field")
        if 'type' not in node_data and 'element_type' not in node_data:
            raise ValidationError("Node data must contain 'type' or 'element_type' field")
        
        # Validate node ID
        if not isinstance(node_data['id'], str) or not node_data['id'].strip():
            raise ValidationError("Node ID must be a non-empty string")
        
        # Validate node type
        node_type = node_data.get('type') or node_data.get('element_type')
        valid_types = ['task', 'gateway', 'event', 'subprocess', 'call_activity', 
                      'start_event', 'end_event', 'parallel_gateway', 'exclusive_gateway']
        if node_type not in valid_types:
            raise ValidationError(f"Node type '{node_type}' must be one of: {valid_types}")
        
        return True
    
    @staticmethod
    def validate_graph_structure(nodes: List[Dict], edges: List[Dict]) -> bool:
        """
        Validate graph structure for consistency.
        
        Args:
            nodes: List of node dictionaries
            edges: List of edge dictionaries
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If graph structure is invalid
        """
        if not isinstance(nodes, list) or not isinstance(edges, list):
            raise ValidationError("Nodes and edges must be lists")
        
        if not nodes:
            raise ValidationError("Graph must contain at least one node")
        
        # Collect node IDs
        node_ids = set()
        for node in nodes:
            InputValidator.validate_node_data(node)
            node_ids.add(node['id'])
        
        # Validate edges reference existing nodes
        for edge in edges:
            if not isinstance(edge, dict):
                raise ValidationError("Each edge must be a dictionary")
            
            if 'source' not in edge or 'target' not in edge:
                raise ValidationError("Each edge must have 'source' and 'target' fields")
            
            if edge['source'] not in node_ids:
                raise ValidationError(f"Edge source '{edge['source']}' not found in nodes")
            
            if edge['target'] not in node_ids:
                raise ValidationError(f"Edge target '{edge['target']}' not found in nodes")
        
        return True
    
    @staticmethod
    def validate_detection_config(config: Dict[str, Any]) -> bool:
        """
        Validate detection configuration.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If configuration is invalid
        """
        if not isinstance(config, dict):
            raise ValidationError("Configuration must be a dictionary")
        
        # Check for required configuration fields
        if 'enabled_strategies' not in config:
            raise ValidationError("Configuration must contain 'enabled_strategies' field")
        
        strategies = config['enabled_strategies']
        if not isinstance(strategies, list) or not strategies:
            raise ValidationError("Enabled strategies must be a non-empty list")
        
        # Validate thresholds if present
        if 'thresholds' in config:
            thresholds = config['thresholds']
            if not isinstance(thresholds, dict):
                raise ValidationError("Thresholds must be a dictionary")
            
            for key, value in thresholds.items():
                if not isinstance(value, (int, float)) or value < 0:
                    raise ValidationError(f"Threshold '{key}' must be a non-negative number")
        
        return True


class ResultValidator:
    """
    Validates detection results and output.
    """
    
    @staticmethod
    def validate_deadlock_result(result: DeadlockResult) -> bool:
        """
        Validate deadlock detection result.
        
        Args:
            result: DeadlockResult instance
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If result is invalid
        """
        if not isinstance(result, DeadlockResult):
            raise ValidationError("Result must be a DeadlockResult instance")
        
        # Validate required fields
        if not result.conflict_type or not isinstance(result.conflict_type, str):
            raise ValidationError("Result must have a non-empty conflict_type")
        
        if not isinstance(result.severity, DeadlockSeverity):
            raise ValidationError("Result must have a valid DeadlockSeverity")
        
        # Validate confidence score if present
        if result.confidence is not None:
            if not isinstance(result.confidence, (int, float)):
                raise ValidationError("Confidence must be numeric")
            
            if not 0 <= result.confidence <= 1:
                raise ValidationError("Confidence must be between 0 and 1")
        
        # Validate shared resources if present
        if result.shared_resources:
            if not isinstance(result.shared_resources, list):
                raise ValidationError("Shared resources must be a list")
            
            for resource in result.shared_resources:
                if not isinstance(resource, str) or not resource.strip():
                    raise ValidationError("Each shared resource must be a non-empty string")
        
        return True
    
    @staticmethod
    def validate_results_batch(results: List[DeadlockResult]) -> bool:
        """
        Validate a batch of detection results.
        
        Args:
            results: List of DeadlockResult instances
            
        Returns:
            True if all valid
            
        Raises:
            ValidationError: If any result is invalid
        """
        if not isinstance(results, list):
            raise ValidationError("Results must be a list")
        
        for i, result in enumerate(results):
            try:
                ResultValidator.validate_deadlock_result(result)
            except ValidationError as e:
                raise ValidationError(f"Result at index {i} is invalid: {str(e)}")
        
        return True


class FileValidator:
    """
    Validates file inputs and outputs.
    """
    
    @staticmethod
    def validate_input_file(file_path: Union[str, Path]) -> bool:
        """
        Validate input file exists and is readable.
        
        Args:
            file_path: Path to input file
            
        Returns:
            True if valid
            
        Raises:
            ValidationError: If file is invalid
        """
        path = Path(file_path)
        
        if not path.exists():
            raise ValidationError(f"Input file does not exist: {file_path}")
        
        if not path.is_file():
            raise ValidationError(f"Path is not a file: {file_path}")
        
        if not path.stat().st_size > 0:
            raise ValidationError(f"Input file is empty: {file_path}")
        
        # Try to read the file
        try:
            with open(path, 'r', encoding='utf-8') as f:
                f.read(1)  # Try to read at least one character
        except Exception as e:
            raise ValidationError(f"Cannot read input file {file_path}: {str(e)}")
        
        return True
    
    @staticmethod
    def validate_json_file(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Validate and parse JSON file.
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Parsed JSON data
            
        Raises:
            ValidationError: If JSON file is invalid
        """
        FileValidator.validate_input_file(file_path)
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return data
        except json.JSONDecodeError as e:
            raise ValidationError(f"Invalid JSON in file {file_path}: {str(e)}")
        except Exception as e:
            raise ValidationError(f"Error reading JSON file {file_path}: {str(e)}")


def validate_all_inputs(
    sql_queries: Optional[List[str]] = None,
    nodes: Optional[List[Dict]] = None,
    edges: Optional[List[Dict]] = None,
    config: Optional[Dict[str, Any]] = None
) -> bool:
    """
    Validate all inputs for deadlock detection.
    
    Args:
        sql_queries: Optional list of SQL queries to validate
        nodes: Optional list of nodes to validate
        edges: Optional list of edges to validate  
        config: Optional configuration to validate
        
    Returns:
        True if all inputs are valid
        
    Raises:
        ValidationError: If any input is invalid
    """
    if sql_queries:
        for i, sql in enumerate(sql_queries):
            try:
                InputValidator.validate_sql_query(sql)
            except ValidationError as e:
                raise ValidationError(f"SQL query at index {i} is invalid: {str(e)}")
    
    if nodes and edges:
        InputValidator.validate_graph_structure(nodes, edges)
    
    if config:
        InputValidator.validate_detection_config(config)
    
    return True
