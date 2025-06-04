from typing import Dict, List, Any
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.base_detector import BaseDeadlockStrategy, DeadlockResult, DeadlockSeverity
from core.graph_analyzer import GraphAnalyzer
from core.sql_parser import SQLResourceExtractor

class ParallelExecutionStrategy(BaseDeadlockStrategy):
    """Strategy for detecting deadlocks in parallel execution paths"""
    
    def __init__(self):
        super().__init__(
            name="parallel_execution",
            description="Detects deadlocks in guaranteed parallel execution paths (AND splits)"
        )
        self.sql_extractor = SQLResourceExtractor()
    
    def detect(self, graph_data: Dict, config: Dict = None) -> List[DeadlockResult]:
        """Detect deadlocks in parallel execution scenarios"""
        analyzer = GraphAnalyzer(graph_data)
        deadlocks = []
        
        # Find parallel paths
        parallel_scenarios = analyzer.find_parallel_paths()
        
        for scenario in parallel_scenarios:
            # Focus on guaranteed parallel execution (AND_SPLIT)
            if scenario['gateway_type'] != 'AND_SPLIT':
                continue
                
            # Check conflicts between all path pairs
            paths = scenario['paths']
            for i, path1 in enumerate(paths):
                for j, path2 in enumerate(paths[i+1:], i+1):
                    conflicts = self._check_path_conflicts(path1, path2, analyzer)
                    deadlocks.extend(conflicts)
        
        return deadlocks
    
    def _check_path_conflicts(self, path1: List[str], path2: List[str], 
                            analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Check for conflicts between two parallel paths"""
        conflicts = []
        
        # Get SQL nodes from both paths
        sql_nodes1 = self._get_sql_nodes_from_path(path1, analyzer)
        sql_nodes2 = self._get_sql_nodes_from_path(path2, analyzer)
        
        # Check each pair of SQL nodes
        for node1 in sql_nodes1:
            for node2 in sql_nodes2:
                conflict = self._analyze_node_pair(node1, node2, analyzer)
                if conflict:
                    conflicts.append(conflict)
                    
        return conflicts
    
    def _get_sql_nodes_from_path(self, path: List[str], analyzer: GraphAnalyzer) -> List[str]:
        """Get nodes with SQL resources from a path"""
        sql_nodes = []
        
        for node_id in path:
            sql_resource = analyzer.get_node_sql_resources(node_id)
            if sql_resource and sql_resource['sql_text'].strip():
                sql_nodes.append(node_id)
                
        return sql_nodes
    
    def _analyze_node_pair(self, node1_id: str, node2_id: str, 
                          analyzer: GraphAnalyzer) -> DeadlockResult:
        """Analyze a pair of nodes for deadlock potential"""
        # Get SQL resources for both nodes
        node1_sql = analyzer.get_node_sql_resources(node1_id)
        node2_sql = analyzer.get_node_sql_resources(node2_id)
        
        if not node1_sql or not node2_sql:
            return None
            
        # Extract SQL resources
        resource1 = self.sql_extractor.extract_resources(node1_sql['sql_text'])
        resource2 = self.sql_extractor.extract_resources(node2_sql['sql_text'])
        
        # Check for resource conflicts
        conflict_info = self.sql_extractor.check_resource_conflict(resource1, resource2)
        
        # Validate conflict for parallel execution
        if not self.validate_conflict(
            {'resources': resource1, 'sql_info': node1_sql},
            {'resources': resource2, 'sql_info': node2_sql},
            {'execution_type': 'parallel', 'gateway_type': 'AND_SPLIT'}
        ):
            return None
        
        # Calculate severity and confidence
        severity = self.get_severity(conflict_info)
        confidence = self.get_confidence(conflict_info)
        
        # Build shared resources list
        shared_resources = list(conflict_info['table_conflicts'])
        if conflict_info['column_conflicts']:
            shared_resources.extend(f"column:{col}" for col in conflict_info['column_conflicts'])
        
        return DeadlockResult(
            node1_id=node1_id,
            node2_id=node2_id,
            node1_name=node1_sql['node_name'],
            node2_name=node2_sql['node_name'],
            severity=severity,
            confidence=confidence,
            conflict_type="parallel_execution",
            shared_resources=shared_resources,
            strategy_name=self.name,
            details={
                'gateway_type': 'AND_SPLIT',
                'execution_type': 'guaranteed_parallel',
                'table_conflicts': list(conflict_info['table_conflicts']),
                'column_conflicts': list(conflict_info['column_conflicts']),
                'write_write_conflict': conflict_info['write_write_conflict'],
                'write_read_conflict': conflict_info['write_read_conflict'],
                'conflict_score': conflict_info['conflict_score'],
                'operations': {
                    'node1': list(resource1.operations),
                    'node2': list(resource2.operations)
                }
            },
            recommendations=self._generate_recommendations(conflict_info, resource1, resource2)
        )
    
    def validate_conflict(self, node1: Dict, node2: Dict, context: Dict = None) -> bool:
        """Validate if a conflict is realistic for parallel execution"""
        resource1 = node1['resources']
        resource2 = node2['resources']
        
        # Must have resource overlap
        if not resource1.tables.intersection(resource2.tables):
            return False
        
        # Must have write operations
        write_ops = {'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'UPSERT'}
        has_writes = (resource1.operations.intersection(write_ops) or 
                     resource2.operations.intersection(write_ops))
        
        if not has_writes:
            return False
        
        # Check for mutual exclusion (should not be mutually exclusive for parallel)
        conflict_info = SQLResourceExtractor().check_resource_conflict(resource1, resource2)
        if conflict_info['mutually_exclusive']:
            return False
            
        return True
    
    def _generate_recommendations(self, conflict_info: Dict, resource1, resource2) -> List[str]:
        """Generate recommendations for resolving parallel execution deadlocks"""
        recommendations = []
        
        shared_tables = conflict_info['table_conflicts']
        if shared_tables:
            sorted_tables = sorted(list(shared_tables))
            recommendations.append(
                f"Implement consistent table access ordering: {' → '.join(sorted_tables)}"
            )
        
        if conflict_info['write_write_conflict']:
            recommendations.append("Use optimistic locking or row-level locking to reduce contention")
            recommendations.append("Consider implementing retry logic with exponential backoff")
        
        if conflict_info['write_read_conflict']:
            recommendations.append("Use READ_COMMITTED isolation level or NOLOCK hints for read operations")
        
        recommendations.append("Monitor for deadlock events and implement automatic retry mechanisms")
        
        return recommendations
