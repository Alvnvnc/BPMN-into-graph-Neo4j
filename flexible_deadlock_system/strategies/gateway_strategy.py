from typing import Dict, List, Any
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.base_detector import BaseDeadlockStrategy, DeadlockResult, DeadlockSeverity
from core.graph_analyzer import GraphAnalyzer
from core.sql_parser import SQLResourceExtractor

class GatewaySpecificStrategy(BaseDeadlockStrategy):
    """Strategy for detecting gateway-specific deadlock patterns"""
    
    def __init__(self):
        super().__init__(
            name="gateway_specific",
            description="Detects deadlocks specific to BPMN gateway patterns"
        )
        self.sql_extractor = SQLResourceExtractor()
    
    def detect(self, graph_data: Dict, config: Dict = None) -> List[DeadlockResult]:
        """Detect gateway-specific deadlocks"""
        analyzer = GraphAnalyzer(graph_data)
        deadlocks = []
        
        # Detect different gateway patterns
        deadlocks.extend(self._detect_convergent_join_deadlocks(analyzer))
        deadlocks.extend(self._detect_conditional_parallel_deadlocks(analyzer))
        deadlocks.extend(self._detect_gateway_transition_deadlocks(analyzer))
        
        return deadlocks
    
    def _detect_convergent_join_deadlocks(self, analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Detect deadlocks at convergent join points"""
        deadlocks = []
        
        # Find convergent scenarios
        convergent_scenarios = analyzer.find_convergent_paths()
        
        for scenario in convergent_scenarios:
            join_type = scenario['join_type']
            convergent_paths = scenario['convergent_paths']
            
            # Skip XOR joins (mutually exclusive)
            if 'XOR' in join_type:
                continue
            
            # Check conflicts between convergent paths
            for i, path1 in enumerate(convergent_paths):
                for j, path2 in enumerate(convergent_paths[i+1:], i+1):
                    conflicts = self._check_convergent_path_conflicts(
                        path1, path2, join_type, analyzer
                    )
                    deadlocks.extend(conflicts)
        
        return deadlocks
    
    def _detect_conditional_parallel_deadlocks(self, analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Detect deadlocks in conditional parallel execution (OR splits)"""
        deadlocks = []
        
        # Find OR split scenarios
        parallel_scenarios = analyzer.find_parallel_paths()
        
        for scenario in parallel_scenarios:
            if scenario['gateway_type'] != 'OR_SPLIT':
                continue
            
            # OR splits can be parallel if conditions are not mutually exclusive
            paths = scenario['paths']
            for i, path1 in enumerate(paths):
                for j, path2 in enumerate(paths[i+1:], i+1):
                    conflicts = self._check_conditional_parallel_conflicts(
                        path1, path2, analyzer
                    )
                    deadlocks.extend(conflicts)
        
        return deadlocks
    
    def _detect_gateway_transition_deadlocks(self, analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Detect deadlocks at gateway transitions"""
        deadlocks = []
        
        # Find gateway transition patterns
        gateway_transitions = self._find_gateway_transitions(analyzer)
        
        for transition in gateway_transitions:
            conflicts = self._analyze_gateway_transition(transition, analyzer)
            deadlocks.extend(conflicts)
        
        return deadlocks
    
    def _check_convergent_path_conflicts(self, path1: List[str], path2: List[str], 
                                       join_type: str, analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Check conflicts between convergent paths"""
        conflicts = []
        
        # Get SQL nodes from both paths
        sql_nodes1 = self._get_sql_nodes_from_path(path1, analyzer)
        sql_nodes2 = self._get_sql_nodes_from_path(path2, analyzer)
        
        # Check conflicts between SQL nodes
        for node1_id in sql_nodes1:
            for node2_id in sql_nodes2:
                conflict = self._analyze_convergent_conflict(
                    node1_id, node2_id, join_type, analyzer
                )
                if conflict:
                    conflicts.append(conflict)
        
        return conflicts
    
    def _check_conditional_parallel_conflicts(self, path1: List[str], path2: List[str], 
                                            analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Check conflicts in conditional parallel paths"""
        conflicts = []
        
        # Get SQL nodes from both paths
        sql_nodes1 = self._get_sql_nodes_from_path(path1, analyzer)
        sql_nodes2 = self._get_sql_nodes_from_path(path2, analyzer)
        
        # Check conflicts if paths can execute in parallel
        for node1_id in sql_nodes1:
            for node2_id in sql_nodes2:
                conflict = self._analyze_conditional_parallel_conflict(
                    node1_id, node2_id, analyzer
                )
                if conflict:
                    conflicts.append(conflict)
        
        return conflicts
    
    def _find_gateway_transitions(self, analyzer: GraphAnalyzer) -> List[Dict]:
        """Find gateway transition patterns"""
        transitions = []
        
        # Look for split-to-join patterns
        for rel in analyzer.relationships:
            rel_type = rel.get('rel_type', '')
            if 'SPLIT' in rel_type:
                # Find corresponding join
                join_pattern = self._find_corresponding_join(rel, analyzer)
                if join_pattern:
                    transitions.append({
                        'split': rel,
                        'join': join_pattern,
                        'pattern_type': f"{rel_type}_to_{join_pattern['rel_type']}"
                    })
        
        return transitions
    
    def _find_corresponding_join(self, split_rel: Dict, analyzer: GraphAnalyzer) -> Dict:
        """Find the corresponding join for a split"""
        # This is a simplified implementation
        # In practice, you'd trace paths from split to find the matching join
        split_source = split_rel.get('source_id')
        
        # Look for joins that could correspond to this split
        for rel in analyzer.relationships:
            rel_type = rel.get('rel_type', '')
            if 'JOIN' in rel_type:
                # Simple heuristic: check if join is reachable from split
                return rel
        
        return None
    
    def _get_sql_nodes_from_path(self, path: List[str], analyzer: GraphAnalyzer) -> List[str]:
        """Get SQL-enabled nodes from a path"""
        sql_nodes = []
        
        for node_id in path:
            sql_info = analyzer.get_node_sql_resources(node_id)
            if sql_info and sql_info['sql_text'].strip():
                sql_nodes.append(node_id)
        
        return sql_nodes
    
    def _analyze_convergent_conflict(self, node1_id: str, node2_id: str, 
                                   join_type: str, analyzer: GraphAnalyzer) -> DeadlockResult:
        """Analyze conflict at convergent join"""
        # Get SQL resources
        node1_sql = analyzer.get_node_sql_resources(node1_id)
        node2_sql = analyzer.get_node_sql_resources(node2_id)
        
        if not node1_sql or not node2_sql:
            return None
        
        resource1 = self.sql_extractor.extract_resources(node1_sql['sql_text'])
        resource2 = self.sql_extractor.extract_resources(node2_sql['sql_text'])
        
        # Check resource conflicts
        conflict_info = self.sql_extractor.check_resource_conflict(resource1, resource2)
        
        # Validate for convergent joins
        if not self.validate_conflict(
            {'resources': resource1, 'sql_info': node1_sql},
            {'resources': resource2, 'sql_info': node2_sql},
            {'join_type': join_type, 'pattern': 'convergent'}
        ):
            return None
        
        return self._create_deadlock_result(
            node1_id, node2_id, node1_sql, node2_sql,
            resource1, resource2, conflict_info,
            f"convergent_{join_type.lower()}", 
            f"Convergent paths deadlock at {join_type}"
        )
    
    def _analyze_conditional_parallel_conflict(self, node1_id: str, node2_id: str, 
                                             analyzer: GraphAnalyzer) -> DeadlockResult:
        """Analyze conflict in conditional parallel execution"""
        # Get SQL resources
        node1_sql = analyzer.get_node_sql_resources(node1_id)
        node2_sql = analyzer.get_node_sql_resources(node2_id)
        
        if not node1_sql or not node2_sql:
            return None
        
        resource1 = self.sql_extractor.extract_resources(node1_sql['sql_text'])
        resource2 = self.sql_extractor.extract_resources(node2_sql['sql_text'])
        
        # Check resource conflicts
        conflict_info = self.sql_extractor.check_resource_conflict(resource1, resource2)
        
        # For OR splits, check if conditions can be parallel
        if conflict_info['mutually_exclusive']:
            return None  # Mutually exclusive conditions = no parallel execution
        
        # Validate for conditional parallel
        if not self.validate_conflict(
            {'resources': resource1, 'sql_info': node1_sql},
            {'resources': resource2, 'sql_info': node2_sql},
            {'gateway_type': 'OR_SPLIT', 'pattern': 'conditional_parallel'}
        ):
            return None
        
        return self._create_deadlock_result(
            node1_id, node2_id, node1_sql, node2_sql,
            resource1, resource2, conflict_info,
            "conditional_parallel", 
            "Conditional parallel execution deadlock (OR split)"
        )
    
    def _analyze_gateway_transition(self, transition: Dict, analyzer: GraphAnalyzer) -> List[DeadlockResult]:
        """Analyze gateway transition for deadlocks"""
        # This is a placeholder for more complex transition analysis
        # You can implement specific logic for different transition patterns
        return []
    
    def _create_deadlock_result(self, node1_id: str, node2_id: str, node1_sql: Dict, 
                              node2_sql: Dict, resource1, resource2, conflict_info: Dict,
                              conflict_type: str, description: str) -> DeadlockResult:
        """Create a deadlock result"""
        severity = self.get_severity(conflict_info)
        confidence = self.get_confidence(conflict_info)
        
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
            conflict_type=conflict_type,
            shared_resources=shared_resources,
            strategy_name=self.name,
            details={
                'description': description,
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
            recommendations=self._generate_gateway_recommendations(conflict_type, conflict_info)
        )
    
    def validate_conflict(self, node1: Dict, node2: Dict, context: Dict = None) -> bool:
        """Validate gateway-specific conflicts"""
        resource1 = node1['resources']
        resource2 = node2['resources']
        
        # Must have resource overlap
        if not (resource1.tables.intersection(resource2.tables) or 
                resource1.columns.intersection(resource2.columns)):
            return False
        
        # Must have operation conflicts
        write_ops = {'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'UPSERT'}
        ops1 = resource1.operations
        ops2 = resource2.operations
        
        has_conflicts = (
            (ops1.intersection(write_ops) and ops2.intersection(write_ops)) or
            ((ops1.intersection(write_ops) and 'SELECT' in ops2) or 
             ('SELECT' in ops1 and ops2.intersection(write_ops)))
        )
        
        if not has_conflicts:
            return False
        
        # Context-specific validation
        if context:
            pattern = context.get('pattern')
            if pattern == 'convergent':
                # Convergent patterns are always potentially problematic
                return True
            elif pattern == 'conditional_parallel':
                # Must not be mutually exclusive for conditional parallel
                conflict_info = self.sql_extractor.check_resource_conflict(resource1, resource2)
                return not conflict_info['mutually_exclusive']
        
        return True
    
    def _generate_gateway_recommendations(self, conflict_type: str, conflict_info: Dict) -> List[str]:
        """Generate gateway-specific recommendations"""
        recommendations = []
        
        if 'convergent' in conflict_type:
            recommendations.extend([
                "Implement proper synchronization at join points",
                "Use compensation patterns for failed transactions",
                "Consider using saga patterns for long-running transactions"
            ])
        
        elif 'conditional_parallel' in conflict_type:
            recommendations.extend([
                "Ensure OR split conditions are properly evaluated",
                "Implement proper condition checking to avoid unexpected parallelism",
                "Use exclusive conditions where parallel execution is not intended"
            ])
        
        # General recommendations
        if conflict_info['table_conflicts']:
            tables = list(conflict_info['table_conflicts'])
            recommendations.append(f"Implement consistent access order for tables: {sorted(tables)}")
        
        recommendations.extend([
            "Monitor gateway execution patterns for unexpected parallel behavior",
            "Implement proper error handling and retry mechanisms",
            "Use process-level locks for critical sections"
        ])
        
        return recommendations
