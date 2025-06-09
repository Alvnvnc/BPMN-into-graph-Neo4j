# Configuration file for SQL Deadlock Detector
# Copy this file and rename to config.py, then update with your settings

# Neo4j Database Configuration
NEO4J_CONFIG = {
    'uri': 'bolt://localhost:7687',
    'user': 'neo4j',
    'password': 'ETS12345678',  # Update with your Neo4j password
    'database': 'neo4j'     # Default database name (changed from 'Graph DBMS')
}

# Logging Configuration
LOGGING_CONFIG = {
    'level': 'INFO',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'deadlock_detection.log'  # Set to None to disable file logging
}

# Analysis Configuration
ANALYSIS_CONFIG = {
    # Maximum depth for path traversal
    'max_path_depth': 15,
    
    # Timeout for Neo4j queries (seconds)
    'query_timeout': 30,
    
    # Enable/disable specific analysis types
    'enable_structural_analysis': True,
    'enable_sql_analysis': True,
    
    # Severity thresholds for deadlock scoring
    'severity_thresholds': {
        'critical': 80,
        'high': 50,
        'medium': 25,
        'low': 0
    },
    
    # SQL parsing configuration
    'sql_parsing': {
        'case_sensitive': False,
        'extract_stored_procedures': True,
        'extract_functions': True
    }
}

# Gateway combination rules (can be customized)
GATEWAY_RULES = {
    'problematic_combinations': {
        ('AND_SPLIT', 'OR_JOIN'): {
            'severity': 'CRITICAL',
            'description': 'AND-split activates all paths, but OR-join continues after first arrival',
            'recommendation': 'Replace OR-join with AND-join to wait for all parallel paths'
        },
        ('AND_SPLIT', 'XOR_JOIN'): {
            'severity': 'CRITICAL', 
            'description': 'AND-split activates all paths, but XOR-join only accepts one token',
            'recommendation': 'Replace XOR-join with AND-join to accept all parallel tokens'
        },
        ('OR_SPLIT', 'AND_JOIN'): {
            'severity': 'CRITICAL',
            'description': 'OR-split may not activate all paths, but AND-join requires all paths',
            'recommendation': 'Replace AND-join with OR-join or ensure all paths are always activated'
        },
        ('XOR_SPLIT', 'AND_JOIN'): {
            'severity': 'CRITICAL',
            'description': 'XOR-split activates only one path, but AND-join waits for all paths',
            'recommendation': 'Replace AND-join with XOR-join to match single path activation'
        }
    },
    
    'warning_combinations': {
        ('OR_SPLIT', 'XOR_JOIN'): {
            'severity': 'MEDIUM',
            'description': 'OR-split may activate multiple paths but XOR-join only accepts first arrival',
            'recommendation': 'Consider using OR-join instead of XOR-join or ensure only one path is activated'
        }
    },
    
    'safe_combinations': {
        ('AND_SPLIT', 'AND_JOIN'): 'AND-split activates all paths and AND-join waits for all paths',
        ('XOR_SPLIT', 'XOR_JOIN'): 'XOR-split activates one path and XOR-join continues after one path',
        ('OR_SPLIT', 'OR_JOIN'): 'OR-split activates paths and OR-join continues when active paths complete',
        ('XOR_SPLIT', 'OR_JOIN'): 'XOR-split activates one path and OR-join continues after completion'
    }
}

# Report Configuration
REPORT_CONFIG = {
    'output_format': 'console',  # console, json, html, csv
    'save_to_file': False,
    'output_directory': './reports',
    'include_graph_visualization': False,
    'detailed_sql_analysis': True,
    'show_safe_combinations': False
}

# Performance Configuration
PERFORMANCE_CONFIG = {
    'batch_size': 1000,  # For large graph processing
    'memory_limit_mb': 512,  # Memory limit for graph operations
    'parallel_processing': False,  # Enable parallel analysis (experimental)
    'cache_graph_data': True  # Cache graph data for multiple runs
}

# Custom SQL patterns for resource extraction
SQL_PATTERNS = {
    'table_patterns': [
        r'FROM\s+([\w\.]+)',
        r'UPDATE\s+([\w\.]+)',
        r'INSERT\s+INTO\s+([\w\.]+)',
        r'DELETE\s+FROM\s+([\w\.]+)',
        r'JOIN\s+([\w\.]+)',
        r'MERGE\s+([\w\.]+)'
    ],
    
    'column_patterns': [
        r'WHERE\s+([\w\.]+)\s*[=<>!]',
        r'SET\s+([\w\.]+)\s*=',
        r'ORDER\s+BY\s+([\w\.]+)',
        r'GROUP\s+BY\s+([\w\.]+)'
    ],
    
    'operation_patterns': {
        'read_operations': ['SELECT', 'WITH'],
        'write_operations': ['UPDATE', 'INSERT', 'DELETE', 'MERGE'],
        'transaction_keywords': ['BEGIN', 'COMMIT', 'ROLLBACK', 'TRANSACTION']
    }
}

# Validation rules
VALIDATION_RULES = {
    'min_nodes_for_analysis': 2,
    'max_graph_size': 10000,  # Maximum number of nodes
    'required_node_properties': ['name'],
    'required_relationship_types': ['SEQUENCE'],
    'validate_sql_syntax': False  # Enable SQL syntax validation
}