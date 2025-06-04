"""
Template for creating custom deadlock detection strategies.

This template provides a starting point for implementing your own
deadlock detection strategies tailored to specific business requirements.
"""

from typing import List, Dict, Any
from abc import ABC, abstractmethod
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.base_detector import (
    BaseDeadlockStrategy, 
    DeadlockResult, 
    DeadlockSeverity
)
from core.sql_parser import SQLResourceExtractor
from core.graph_analyzer import GraphAnalyzer


class CustomStrategyTemplate(BaseDeadlockStrategy):
    """
    Template for custom deadlock detection strategy.
    
    Copy this class and implement your own detection logic.
    """
    
    def __init__(self, **kwargs):
        """
        Initialize your custom strategy.
        
        Args:
            **kwargs: Strategy-specific configuration parameters
        """
        # Initialize parent class with strategy info
        super().__init__("custom_template", "Template for custom deadlock detection")
        
        # Store configuration parameters
        self.config = kwargs
        
        # Initialize helper utilities
        self.sql_extractor = SQLResourceExtractor()
        # Initialize graph_analyzer when needed (in detect methods)
        self.graph_analyzer = None
    
    def detect(self, graph_data: Dict, config: Dict = None) -> List[DeadlockResult]:
        """
        Main detection method required by BaseDeadlockStrategy.
        
        Args:
            graph_data: Graph data containing nodes and relationships
            config: Strategy-specific configuration
            
        Returns:
            List of DeadlockResult objects
        """
        nodes = graph_data.get('nodes', [])
        edges = graph_data.get('edges', [])
        sql_queries = graph_data.get('sql_queries')
        return self.detect_deadlocks(nodes, edges, sql_queries)
    
    def validate_conflict(self, node1: Dict, node2: Dict, context: Dict = None) -> bool:
        """
        Validate if a conflict exists between two nodes.
        
        Args:
            node1: First node to check
            node2: Second node to check
            context: Additional context for validation
            
        Returns:
            True if conflict exists, False otherwise
        """
        # Template implementation - customize as needed
        return True
    
    def detect_deadlocks(
        self, 
        nodes: List[Dict[str, Any]], 
        edges: List[Dict[str, Any]],
        sql_queries: List[str] = None
    ) -> List[DeadlockResult]:
        """
        Main detection method - implement your detection logic here.
        
        Args:
            nodes: List of workflow nodes with their properties
            edges: List of workflow edges defining the flow
            sql_queries: Optional list of SQL queries to analyze
            
        Returns:
            List of detected deadlock results
        """
        results = []
        
        # Step 1: Analyze the workflow structure
        workflow_analysis = self._analyze_workflow_structure(nodes, edges)
        
        # Step 2: Analyze SQL queries if provided
        sql_analysis = None
        if sql_queries or self._has_sql_in_nodes(nodes):
            sql_analysis = self._analyze_sql_patterns(nodes, sql_queries)
        
        # Step 3: Apply your custom detection logic
        deadlock_patterns = self._detect_custom_patterns(
            nodes, edges, workflow_analysis, sql_analysis
        )
        
        # Step 4: Convert patterns to DeadlockResult objects
        for pattern in deadlock_patterns:
            result = self._create_deadlock_result(pattern)
            if result:
                results.append(result)
        
        return results
    
    def _analyze_workflow_structure(
        self, 
        nodes: List[Dict[str, Any]], 
        edges: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Analyze the workflow structure for patterns relevant to your strategy.
        
        Args:
            nodes: Workflow nodes
            edges: Workflow edges
            
        Returns:
            Analysis results dictionary
        """
        analysis = {
            'node_count': len(nodes),
            'edge_count': len(edges),
            'parallel_gateways': [],
            'task_nodes': [],
            'decision_points': []
        }
        
        # Categorize nodes by type
        for node in nodes:
            node_type = node.get('type', '')
            
            if node_type == 'gateway':
                gateway_type = node.get('gateway_type', 'unknown')
                if gateway_type == 'parallel':
                    analysis['parallel_gateways'].append(node)
                elif gateway_type in ['exclusive', 'inclusive']:
                    analysis['decision_points'].append(node)
            elif node_type == 'task':
                analysis['task_nodes'].append(node)
        
        # Use graph analyzer for advanced analysis
        try:
            graph = self.graph_analyzer.build_networkx_graph(nodes, edges)
            analysis['has_cycles'] = not self.graph_analyzer.is_dag(graph)
            analysis['parallel_paths'] = self.graph_analyzer.find_parallel_paths(graph)
        except Exception:
            # Handle analysis errors gracefully
            analysis['has_cycles'] = False
            analysis['parallel_paths'] = []
        
        return analysis
    
    def _analyze_sql_patterns(
        self, 
        nodes: List[Dict[str, Any]], 
        sql_queries: List[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze SQL patterns for deadlock indicators.
        
        Args:
            nodes: Workflow nodes (may contain SQL queries)
            sql_queries: Additional SQL queries to analyze
            
        Returns:
            SQL analysis results
        """
        analysis = {
            'total_queries': 0,
            'locking_queries': [],
            'resource_conflicts': [],
            'tables_accessed': set()
        }
        
        # Collect all SQL queries
        all_queries = []
        
        # From nodes
        for node in nodes:
            if 'sql_query' in node:
                all_queries.append({
                    'sql': node['sql_query'],
                    'node_id': node['id'],
                    'source': 'node'
                })
        
        # From additional queries
        if sql_queries:
            for i, sql in enumerate(sql_queries):
                all_queries.append({
                    'sql': sql,
                    'node_id': f'query_{i}',
                    'source': 'external'
                })
        
        analysis['total_queries'] = len(all_queries)
        
        # Analyze each query
        for query_info in all_queries:
            sql = query_info['sql']
            
            try:
                # Extract resources using the SQL parser
                resources = self.sql_extractor.extract_resources(sql)
                analysis['tables_accessed'].update(resources.get('tables', []))
                
                # Check for locking patterns
                if self._is_locking_query(sql):
                    analysis['locking_queries'].append(query_info)
                
                # Check for potential conflicts
                conflicts = self._detect_sql_conflicts(sql, resources)
                if conflicts:
                    analysis['resource_conflicts'].extend(conflicts)
                    
            except Exception:
                # Handle SQL parsing errors gracefully
                continue
        
        return analysis
    
    def _detect_custom_patterns(
        self,
        nodes: List[Dict[str, Any]], 
        edges: List[Dict[str, Any]],
        workflow_analysis: Dict[str, Any],
        sql_analysis: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        Implement your custom deadlock detection patterns here.
        
        This is where you implement the core logic of your strategy.
        
        Args:
            nodes: Workflow nodes
            edges: Workflow edges  
            workflow_analysis: Results from workflow structure analysis
            sql_analysis: Results from SQL analysis (if available)
            
        Returns:
            List of detected patterns, each as a dictionary
        """
        patterns = []
        
        # Example Pattern 1: Detect circular dependencies in parallel flows
        if workflow_analysis.get('has_cycles') and workflow_analysis.get('parallel_gateways'):
            patterns.append({
                'type': 'circular_parallel_dependency',
                'severity': DeadlockSeverity.HIGH,
                'description': 'Circular dependency detected in parallel execution flow',
                'affected_nodes': [gw['id'] for gw in workflow_analysis['parallel_gateways']],
                'confidence': 0.8,
                'details': 'Parallel gateways with circular dependencies can cause deadlocks'
            })
        
        # Example Pattern 2: Resource contention in concurrent tasks
        if sql_analysis and len(sql_analysis.get('locking_queries', [])) > 1:
            locking_nodes = [q['node_id'] for q in sql_analysis['locking_queries']]
            
            # Check if locking nodes are in parallel paths
            parallel_paths = workflow_analysis.get('parallel_paths', [])
            for path_group in parallel_paths:
                conflicting_nodes = [node for node in locking_nodes if node in path_group]
                if len(conflicting_nodes) > 1:
                    patterns.append({
                        'type': 'concurrent_resource_lock',
                        'severity': DeadlockSeverity.MEDIUM,
                        'description': f'Concurrent resource locking detected',
                        'affected_nodes': conflicting_nodes,
                        'confidence': 0.7,
                        'details': f'Nodes {conflicting_nodes} execute locking queries in parallel'
                    })
        
        # Example Pattern 3: Long-running tasks in critical path
        # (Add your own patterns here)
        
        # Template for additional patterns:
        # if self._check_your_condition(workflow_analysis, sql_analysis):
        #     patterns.append({
        #         'type': 'your_pattern_type',
        #         'severity': DeadlockSeverity.MEDIUM,  # or LOW, HIGH, CRITICAL
        #         'description': 'Description of the deadlock pattern',
        #         'affected_nodes': ['node1', 'node2'],  # List of affected node IDs
        #         'confidence': 0.75,  # Confidence score (0.0 to 1.0)
        #         'details': 'Additional details about the pattern'
        #     })
        
        return patterns
    
    def _create_deadlock_result(self, pattern: Dict[str, Any]) -> DeadlockResult:
        """
        Convert a detected pattern to a DeadlockResult object.
        
        Args:
            pattern: Pattern dictionary from _detect_custom_patterns
            
        Returns:
            DeadlockResult object or None if pattern is invalid
        """
        try:
            # Get node information from pattern
            nodes = pattern.get('affected_nodes', [])
            node1_id = nodes[0] if len(nodes) > 0 else 'unknown'
            node2_id = nodes[1] if len(nodes) > 1 else node1_id
            
            return DeadlockResult(
                node1_id=node1_id,
                node2_id=node2_id,
                node1_name=pattern.get('node1_name', node1_id),
                node2_name=pattern.get('node2_name', node2_id),
                severity=pattern['severity'],
                confidence=pattern.get('confidence', 0.5),
                conflict_type=pattern.get('conflict_type', 'custom_pattern'),
                shared_resources=pattern.get('shared_resources', []),
                strategy_name=self.name,
                details=pattern.get('details', {}),
                recommendations=pattern.get('recommendations', [
                    "Review the detected pattern",
                    "Consider workflow optimization"
                ])
            )
        except KeyError as e:
            # Handle missing required fields
            print(f"Warning: Pattern missing required field {e}")
            return None
    
    def _has_sql_in_nodes(self, nodes: List[Dict[str, Any]]) -> bool:
        """Check if any nodes contain SQL queries."""
        return any('sql_query' in node for node in nodes)
    
    def _is_locking_query(self, sql: str) -> bool:
        """Check if SQL query uses locking mechanisms."""
        sql_upper = sql.upper()
        locking_keywords = [
            'FOR UPDATE',
            'LOCK IN SHARE MODE', 
            'WITH (UPDLOCK)',
            'WITH (XLOCK)',
            'HOLDLOCK'
        ]
        return any(keyword in sql_upper for keyword in locking_keywords)
    
    def _detect_sql_conflicts(self, sql: str, resources: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect potential SQL resource conflicts.
        
        Args:
            sql: SQL query string
            resources: Extracted resources from the query
            
        Returns:
            List of detected conflicts
        """
        conflicts = []
        
        # Example: Detect UPDATE operations on frequently accessed tables
        if 'UPDATE' in sql.upper():
            for table in resources.get('tables', []):
                if table.upper() in ['ORDERS', 'INVENTORY', 'CUSTOMERS']:  # High-contention tables
                    conflicts.append({
                        'type': 'high_contention_update',
                        'table': table,
                        'query': sql[:100]  # First 100 chars
                    })
        
        return conflicts


# Example implementation of a specific custom strategy
class DatabaseLockingStrategy(CustomStrategyTemplate):
    """
    Example custom strategy focused on database locking patterns.
    """
    
    def __init__(self, lock_timeout: int = 30):
        super().__init__(lock_timeout=lock_timeout)
        self.strategy_name = "database_locking"
        self.description = "Detects database locking deadlock patterns"
        self.lock_timeout = lock_timeout
    
    def _detect_custom_patterns(
        self,
        nodes: List[Dict[str, Any]], 
        edges: List[Dict[str, Any]],
        workflow_analysis: Dict[str, Any],
        sql_analysis: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """Detect database locking specific patterns."""
        patterns = []
        
        if not sql_analysis:
            return patterns
        
        # Pattern: Multiple FOR UPDATE queries on same table
        table_locks = {}
        for query_info in sql_analysis.get('locking_queries', []):
            try:
                resources = self.sql_extractor.extract_resources(query_info['sql'])
                for table in resources.get('tables', []):
                    if table not in table_locks:
                        table_locks[table] = []
                    table_locks[table].append(query_info['node_id'])
            except:
                continue
        
        # Find tables with multiple locking queries
        for table, node_ids in table_locks.items():
            if len(node_ids) > 1:
                patterns.append({
                    'type': 'table_lock_contention',
                    'severity': DeadlockSeverity.HIGH,
                    'description': f'Multiple nodes attempting to lock table {table}',
                    'affected_nodes': node_ids,
                    'confidence': 0.9,
                    'details': f'Table {table} is locked by {len(node_ids)} concurrent operations'
                })
        
        return patterns


def create_custom_strategy_example():
    """
    Example of how to create and use a custom strategy.
    """
    print("Creating custom database locking strategy...")
    
    # Create the strategy
    custom_strategy = DatabaseLockingStrategy(lock_timeout=25)
    
    # Sample data for testing
    nodes = [
        {
            "id": "task1", 
            "type": "task",
            "sql_query": "SELECT * FROM orders WHERE id = 1 FOR UPDATE"
        },
        {
            "id": "task2",
            "type": "task", 
            "sql_query": "UPDATE orders SET status = 'processed' WHERE id = 1"
        }
    ]
    edges = [{"source": "task1", "target": "task2"}]
    
    # Test the strategy
    results = custom_strategy.detect_deadlocks(nodes, edges)
    
    print(f"Found {len(results)} potential deadlocks:")
    for result in results:
        print(f"- {result.description} (Severity: {result.severity.name})")
    
    return custom_strategy


if __name__ == "__main__":
    """Test the custom strategy template."""
    
    print("🔧 Custom Strategy Template Example")
    print("=" * 50)
    
    try:
        strategy = create_custom_strategy_example()
        print(f"\n✅ Custom strategy '{strategy.strategy_name}' created successfully!")
        print("\nTo create your own strategy:")
        print("1. Copy the CustomStrategyTemplate class")
        print("2. Implement the _detect_custom_patterns method")
        print("3. Add your specific detection logic")
        print("4. Register it with the DeadlockDetectionSystem")
        
    except Exception as e:
        print(f"❌ Error testing custom strategy: {e}")
        import traceback
        traceback.print_exc()
