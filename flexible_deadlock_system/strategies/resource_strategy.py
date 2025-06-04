from typing import Dict, List, Any
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.base_detector import BaseDeadlockStrategy, DeadlockResult, DeadlockSeverity
from core.graph_analyzer import GraphAnalyzer
from core.sql_parser import SQLResourceExtractor

class ResourceContentionStrategy(BaseDeadlockStrategy):
    """Strategy for detecting resource-based deadlocks"""
    
    def __init__(self):
        super().__init__(
            name="resource_contention",
            description="Detects deadlocks based on SQL resource contention patterns"
        )
        self.sql_extractor = SQLResourceExtractor()
    
    def detect(self, graph_data: Dict, config: Dict = None) -> List[DeadlockResult]:
        """Detect resource contention deadlocks"""
        analyzer = GraphAnalyzer(graph_data)
        deadlocks = []
        
        # Find all SQL-enabled nodes
        sql_nodes = self._find_sql_nodes(analyzer)
        
        # Build resource dependency graph
        resource_graph = self._build_resource_graph(sql_nodes, analyzer)
        
        # Detect resource conflicts
        conflicts = self._detect_resource_conflicts(resource_graph, analyzer)
        
        return conflicts
    
    def _find_sql_nodes(self, analyzer: GraphAnalyzer) -> List[str]:
        """Find all nodes with SQL resources"""
        sql_nodes = []
        
        if isinstance(analyzer.nodes, dict):
            node_items = analyzer.nodes.items()
        else:
            node_items = [(node.get('id'), node) for node in analyzer.nodes if node.get('id')]
        
        for node_id, node_data in node_items:
            properties = node_data.get('properties', {})
            sql_text = properties.get('SQL', '') or properties.get('sql', '')
            
            if sql_text and sql_text.strip():
                sql_nodes.append(node_id)
                
        return sql_nodes
    
    def _build_resource_graph(self, sql_nodes: List[str], analyzer: GraphAnalyzer) -> Dict:
        """Build resource dependency graph"""
        resource_graph = {
            'nodes': {},
            'edges': [],
            'resources': {}
        }
        
        # Process each SQL node
        for node_id in sql_nodes:
            sql_info = analyzer.get_node_sql_resources(node_id)
            if not sql_info:
                continue
                
            resources = self.sql_extractor.extract_resources(sql_info['sql_text'])
            
            resource_graph['nodes'][node_id] = {
                'name': sql_info['node_name'],
                'type': sql_info['node_type'],
                'sql_text': sql_info['sql_text']
            }
            
            resource_graph['resources'][node_id] = resources
        
        # Build edges based on resource dependencies
        node_list = list(resource_graph['nodes'].keys())
        for i, node1 in enumerate(node_list):
            for node2 in node_list[i+1:]:
                edge = self._analyze_resource_dependency(
                    node1, node2, resource_graph['resources'], analyzer
                )
                if edge:
                    resource_graph['edges'].append(edge)
        
        return resource_graph
    
    def _analyze_resource_dependency(self, node1: str, node2: str, resources: Dict, 
                                   analyzer: GraphAnalyzer) -> Dict:
        """Analyze resource dependency between two nodes"""
        resource1 = resources[node1]
        resource2 = resources[node2]
        
        # Check resource conflicts
        conflict_info = self.sql_extractor.check_resource_conflict(resource1, resource2)
        
        if not conflict_info['has_resource_overlap'] or not conflict_info['has_operation_conflict']:
            return None
        
        # Determine dependency type
        dependency_type = self._determine_dependency_type(conflict_info, resource1, resource2)
        
        return {
            'source': node1,
            'target': node2,
            'dependency_type': dependency_type,
            'conflict_info': conflict_info,
            'weight': conflict_info['conflict_score']
        }
    
    def _determine_dependency_type(self, conflict_info: Dict, resource1, resource2) -> str:
        """Determine the type of resource dependency"""
        if conflict_info['write_write_conflict']:
            return 'write_write'
        elif conflict_info['write_read_conflict']:
            return 'write_read'
        elif conflict_info['table_conflicts']:
            return 'table_contention'
        else:
            return 'resource_overlap'
    
    def _detect_resource_conflicts(self, resource_graph: Dict, analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Detect conflicts in the resource graph"""
        conflicts = []
        
        for edge in resource_graph['edges']:
            conflict = self._create_deadlock_result(edge, resource_graph, analyzer)
            if conflict:
                conflicts.append(conflict)
        
        return conflicts
    
    def _create_deadlock_result(self, edge: Dict, resource_graph: Dict, 
                              analyzer: GraphAnalyzer) -> DeadlockResult:
        """Create deadlock result from resource edge"""
        node1_id = edge['source']
        node2_id = edge['target']
        
        node1_info = resource_graph['nodes'][node1_id]
        node2_info = resource_graph['nodes'][node2_id]
        
        resource1 = resource_graph['resources'][node1_id]
        resource2 = resource_graph['resources'][node2_id]
        
        conflict_info = edge['conflict_info']
        
        # Validate conflict
        if not self.validate_conflict(
            {'resources': resource1, 'info': node1_info},
            {'resources': resource2, 'info': node2_info},
            {'dependency_type': edge['dependency_type']}
        ):
            return None
        
        # Calculate severity and confidence
        severity = self.get_severity(conflict_info)
        confidence = self.get_confidence(conflict_info)
        
        # Build shared resources
        shared_resources = []
        if conflict_info['table_conflicts']:
            shared_resources.extend(list(conflict_info['table_conflicts']))
        if conflict_info['column_conflicts']:
            shared_resources.extend(f"column:{col}" for col in conflict_info['column_conflicts'])
        
        return DeadlockResult(
            node1_id=node1_id,
            node2_id=node2_id,
            node1_name=node1_info['name'],
            node2_name=node2_info['name'],
            severity=severity,
            confidence=confidence,
            conflict_type=f"resource_contention_{edge['dependency_type']}",
            shared_resources=shared_resources,
            strategy_name=self.name,
            details={
                'dependency_type': edge['dependency_type'],
                'table_conflicts': list(conflict_info['table_conflicts']),
                'column_conflicts': list(conflict_info['column_conflicts']),
                'write_write_conflict': conflict_info['write_write_conflict'],
                'write_read_conflict': conflict_info['write_read_conflict'],
                'conflict_score': conflict_info['conflict_score'],
                'mutually_exclusive': conflict_info['mutually_exclusive'],
                'operations': {
                    'node1': list(resource1.operations),
                    'node2': list(resource2.operations)
                }
            },
            recommendations=self._generate_recommendations(edge, conflict_info, resource1, resource2)
        )
    
    def validate_conflict(self, node1: Dict, node2: Dict, context: Dict = None) -> bool:
        """Validate if a resource conflict is realistic"""
        resource1 = node1['resources']
        resource2 = node2['resources']
        
        # Must have actual resource overlap
        has_table_overlap = bool(resource1.tables.intersection(resource2.tables))
        has_column_overlap = bool(resource1.columns.intersection(resource2.columns))
        
        if not has_table_overlap and not has_column_overlap:
            return False
        
        # Must have conflicting operations
        write_ops = {'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'UPSERT'}
        ops1 = resource1.operations
        ops2 = resource2.operations
        
        has_write_write = bool(ops1.intersection(write_ops) and ops2.intersection(write_ops))
        has_write_read = bool(
            (ops1.intersection(write_ops) and 'SELECT' in ops2) or
            ('SELECT' in ops1 and ops2.intersection(write_ops))
        )
        
        if not has_write_write and not has_write_read:
            return False
        
        # For write-read conflicts, must have table overlap
        if has_write_read and not has_write_write and not has_table_overlap:
            return False
        
        return True
    
    def _generate_recommendations(self, edge: Dict, conflict_info: Dict, 
                                resource1, resource2) -> List[str]:
        """Generate recommendations for resource contention deadlocks"""
        recommendations = []
        dependency_type = edge['dependency_type']
        
        if dependency_type == 'write_write':
            recommendations.extend([
                "Implement optimistic concurrency control",
                "Use row-level locking instead of table locks",
                "Consider partitioning data to reduce contention"
            ])
        
        elif dependency_type == 'write_read':
            recommendations.extend([
                "Use READ_COMMITTED or READ_UNCOMMITTED isolation levels",
                "Implement NOLOCK hints for read operations where appropriate",
                "Consider using snapshot isolation"
            ])
        
        elif dependency_type == 'table_contention':
            shared_tables = list(conflict_info['table_conflicts'])
            sorted_tables = sorted(shared_tables)
            recommendations.extend([
                f"Implement consistent table access ordering: {' → '.join(sorted_tables)}",
                "Use fine-grained locking strategies",
                "Consider database-level deadlock detection and automatic retry"
            ])
        
        recommendations.append("Monitor deadlock frequency and adjust timeout values")
        
        return recommendations
    
    def get_severity(self, conflict_data: Dict) -> DeadlockSeverity:
        """Calculate severity for resource contention conflicts"""
        score = 0
        
        # Table conflicts are most severe
        if conflict_data.get('table_conflicts'):
            score += 40
        
        # Column conflicts
        if conflict_data.get('column_conflicts'):
            score += 20
        
        # Operation type conflicts
        if conflict_data.get('write_write_conflict'):
            score += 35
        elif conflict_data.get('write_read_conflict'):
            score += 15
        
        # Conflict score
        score += conflict_data.get('conflict_score', 0) * 20
        
        if score >= 70:
            return DeadlockSeverity.CRITICAL
        elif score >= 50:
            return DeadlockSeverity.HIGH
        elif score >= 30:
            return DeadlockSeverity.MEDIUM
        else:
            return DeadlockSeverity.LOW
    
    def get_confidence(self, conflict_data: Dict) -> float:
        """Calculate confidence for resource contention conflicts"""
        confidence = 0.3  # Base confidence
        
        if conflict_data.get('table_conflicts'):
            confidence += 0.4
        
        if conflict_data.get('write_write_conflict'):
            confidence += 0.3
        elif conflict_data.get('write_read_conflict'):
            confidence += 0.2
        
        if not conflict_data.get('mutually_exclusive'):
            confidence += 0.1
        
        return min(1.0, confidence)
