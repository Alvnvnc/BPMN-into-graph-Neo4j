"""
Additional Detection Strategies for Flexible Deadlock Detector
- Custom strategies for specific deadlock patterns
- Extensible strategy implementations
"""

import re
from typing import Dict, List, Set, Any
from flexible_deadlock_detector import DeadlockDetectionStrategy, DeadlockPattern, ConflictResult

class SQLTableLockStrategy(DeadlockDetectionStrategy):
    """Strategy for detecting table-level lock conflicts"""
    
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        patterns = []
        sql_resources = context.get('sql_resources', {})
        graph_data = context.get('graph_data', {})
        
        # Group nodes by table access
        table_access_map = self._build_table_access_map(sql_resources)
        
        # Check for conflicting table access patterns
        for table, access_info in table_access_map.items():
            if len(access_info['write_nodes']) > 1:
                # Multiple writers to same table
                patterns.extend(self._detect_write_write_conflicts(table, access_info))
            
            if access_info['write_nodes'] and access_info['read_nodes']:
                # Read-write conflicts
                patterns.extend(self._detect_read_write_conflicts(table, access_info))
        
        return patterns
    
    def get_strategy_name(self) -> str:
        return "SQLTableLockStrategy"
    
    def _build_table_access_map(self, sql_resources: Dict) -> Dict:
        """Build map of table access patterns"""
        table_map = {}
        
        for node_id, resource_info in sql_resources.items():
            tables = resource_info['resources']['tables']
            operations = resource_info['resources']['operations']
            
            for table in tables:
                if table not in table_map:
                    table_map[table] = {
                        'read_nodes': [],
                        'write_nodes': [],
                        'all_nodes': []
                    }
                
                table_map[table]['all_nodes'].append(node_id)
                
                if operations.intersection({'SELECT'}):
                    table_map[table]['read_nodes'].append(node_id)
                
                if operations.intersection({'UPDATE', 'INSERT', 'DELETE'}):
                    table_map[table]['write_nodes'].append(node_id)
        
        return table_map
    
    def _detect_write_write_conflicts(self, table: str, access_info: Dict) -> List[DeadlockPattern]:
        """Detect write-write conflicts on same table"""
        patterns = []
        write_nodes = access_info['write_nodes']
        
        for i in range(len(write_nodes)):
            for j in range(i + 1, len(write_nodes)):
                pattern = DeadlockPattern(
                    pattern_id=f"write_write_{table}_{write_nodes[i]}_{write_nodes[j]}",
                    pattern_type="TABLE_WRITE_CONFLICT",
                    severity="HIGH",
                    nodes=[write_nodes[i], write_nodes[j]],
                    resources={table},
                    gateway_type="RESOURCE_CONTENTION",
                    execution_context="CONCURRENT_WRITES",
                    metadata={
                        'table': table,
                        'conflict_type': 'WRITE-WRITE',
                        'risk_level': 'HIGH'
                    }
                )
                patterns.append(pattern)
        
        return patterns
    
    def _detect_read_write_conflicts(self, table: str, access_info: Dict) -> List[DeadlockPattern]:
        """Detect read-write conflicts on same table"""
        patterns = []
        read_nodes = access_info['read_nodes']
        write_nodes = access_info['write_nodes']
        
        for read_node in read_nodes:
            for write_node in write_nodes:
                if read_node != write_node:
                    pattern = DeadlockPattern(
                        pattern_id=f"read_write_{table}_{read_node}_{write_node}",
                        pattern_type="TABLE_READ_WRITE_CONFLICT",
                        severity="MEDIUM",
                        nodes=[read_node, write_node],
                        resources={table},
                        gateway_type="RESOURCE_CONTENTION",
                        execution_context="READ_WRITE_CONFLICT",
                        metadata={
                            'table': table,
                            'conflict_type': 'READ-WRITE',
                            'risk_level': 'MEDIUM'
                        }
                    )
                    patterns.append(pattern)
        
        return patterns

class CircularDependencyStrategy(DeadlockDetectionStrategy):
    """Strategy for detecting circular dependencies in graph"""
    
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        patterns = []
        graph_data = context.get('graph_data', {})
        sql_resources = context.get('sql_resources', {})
        
        # Build directed graph
        import networkx as nx
        G = nx.DiGraph()
        
        for rel in graph_data.get('relationships', []):
            source = rel.get('source_id')
            target = rel.get('target_id')
            if source and target:
                G.add_edge(source, target)
        
        # Find strongly connected components (cycles)
        try:
            sccs = list(nx.strongly_connected_components(G))
            
            for scc in sccs:
                if len(scc) > 1:  # Cycle found
                    sql_nodes_in_cycle = [node for node in scc if node in sql_resources]
                    
                    if len(sql_nodes_in_cycle) >= 2:
                        # Check if cycle involves SQL operations with shared resources
                        shared_resources = self._find_shared_resources_in_cycle(sql_nodes_in_cycle, sql_resources)
                        
                        if shared_resources:
                            pattern = DeadlockPattern(
                                pattern_id=f"circular_dependency_{'_'.join(sorted(sql_nodes_in_cycle)[:3])}",
                                pattern_type="CIRCULAR_DEPENDENCY",
                                severity="CRITICAL",
                                nodes=sql_nodes_in_cycle,
                                resources=shared_resources,
                                gateway_type="CYCLE",
                                execution_context="CIRCULAR_WAIT",
                                metadata={
                                    'cycle_size': len(scc),
                                    'sql_nodes_count': len(sql_nodes_in_cycle),
                                    'cycle_nodes': list(scc)
                                }
                            )
                            patterns.append(pattern)
        
        except Exception as e:
            print(f"Error in circular dependency detection: {e}")
        
        return patterns
    
    def get_strategy_name(self) -> str:
        return "CircularDependencyStrategy"
    
    def _find_shared_resources_in_cycle(self, nodes: List[str], sql_resources: Dict) -> Set[str]:
        """Find shared resources among nodes in cycle"""
        if not nodes:
            return set()
        
        # Start with resources from first node
        shared = sql_resources[nodes[0]]['resources']['tables'].copy()
        
        # Intersect with resources from other nodes
        for node in nodes[1:]:
            node_tables = sql_resources[node]['resources']['tables']
            shared = shared.intersection(node_tables)
        
        return shared

class TransactionBoundaryStrategy(DeadlockDetectionStrategy):
    """Strategy for detecting deadlocks across transaction boundaries"""
    
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        patterns = []
        sql_resources = context.get('sql_resources', {})
        
        # Look for explicit transaction patterns in SQL
        transaction_groups = self._identify_transaction_groups(sql_resources)
        
        # Check for cross-transaction conflicts
        for group_id, group_info in transaction_groups.items():
            conflicts = self._check_transaction_conflicts(group_info, sql_resources)
            patterns.extend(conflicts)
        
        return patterns
    
    def get_strategy_name(self) -> str:
        return "TransactionBoundaryStrategy"
    
    def _identify_transaction_groups(self, sql_resources: Dict) -> Dict:
        """Identify nodes that likely belong to same transaction"""
        transaction_groups = {}
        
        for node_id, resource_info in sql_resources.items():
            sql = resource_info.get('sql', '').upper()
            
            # Simple heuristic: look for transaction keywords
            if any(keyword in sql for keyword in ['BEGIN', 'COMMIT', 'ROLLBACK', 'TRANSACTION']):
                group_id = f"explicit_txn_{node_id}"
                transaction_groups[group_id] = {
                    'nodes': [node_id],
                    'type': 'EXPLICIT',
                    'has_txn_control': True
                }
            else:
                # Group by operation type and proximity
                operations = resource_info['resources']['operations']
                if operations.intersection({'UPDATE', 'INSERT', 'DELETE'}):
                    group_id = f"implicit_write_{len(transaction_groups)}"
                    transaction_groups[group_id] = {
                        'nodes': [node_id],
                        'type': 'IMPLICIT_WRITE',
                        'has_txn_control': False
                    }
        
        return transaction_groups
    
    def _check_transaction_conflicts(self, group_info: Dict, sql_resources: Dict) -> List[DeadlockPattern]:
        """Check for conflicts within transaction group"""
        patterns = []
        # Implementation would check for specific transaction-level conflicts
        return patterns

# Example of how to extend the flexible detector with custom strategies
def register_custom_strategies(detector):
    """Register custom strategies with the detector"""
    detector.register_strategy(SQLTableLockStrategy())
    detector.register_strategy(CircularDependencyStrategy())
    detector.register_strategy(TransactionBoundaryStrategy())
    
    print("Custom strategies registered:")
    print("- SQLTableLockStrategy: Table-level lock conflicts")
    print("- CircularDependencyStrategy: Circular dependencies in execution graph")
    print("- TransactionBoundaryStrategy: Cross-transaction deadlocks")
