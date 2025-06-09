#!/usr/bin/env python3
"""
Deadlock Detector Module
Handles the core deadlock detection logic using graph theory and resource analysis.
Refactored from backup_sql.py for modular architecture.
"""

import logging
import networkx as nx
from typing import Dict, List, Set, Tuple, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)

class DeadlockDetector:
    """
    Detects SQL deadlocks using graph theory and resource conflict analysis
    """
    
    def __init__(self, graph_data: Dict, sql_resources: Dict, neo4j_connector=None):
        """
        Initialize the deadlock detector
        
        Args:
            graph_data: Graph data containing nodes and relationships
            sql_resources: SQL resources extracted from nodes
        """
        self.neo4j_connector = neo4j_connector
        self.graph_data = graph_data
        self.sql_resources = sql_resources
        self.resource_graph = nx.DiGraph()
        self.wait_for_graph = nx.DiGraph()
        self.deadlock_risks = []
        self.detected_conflicts = []
        
        logger.debug("Initializing DeadlockDetector")
    
    def analyze_deadlocks(self, parallel_scenarios: List[Dict]) -> Dict:
        """
        Analyze deadlocks across all parallel scenarios
        
        Args:
            parallel_scenarios: List of parallel execution scenarios
            
        Returns:
            Dict: Deadlock analysis results
        """
        logger.info(f"Analyzing deadlocks across {len(parallel_scenarios)} parallel scenarios...")
        
        # Build resource dependency graph
        self._build_resource_dependency_graph()
        
        # Build wait-for graph with enhanced logic
        self._build_wait_for_graph(parallel_scenarios)
        
        # Detect cycles (potential deadlocks)
        deadlock_cycles = self._detect_deadlock_cycles()
        
        # Analyze conflict severity
        conflict_analysis = self._analyze_conflict_severity()
        
        results = {
            'total_scenarios_analyzed': len(parallel_scenarios),
            'deadlock_cycles': deadlock_cycles,
            'conflict_analysis': conflict_analysis,
            'detected_conflicts': self.detected_conflicts,
            'deadlock_risks': self.deadlock_risks,
            'resource_graph_stats': self._get_resource_graph_stats(),
            'wait_for_graph_stats': self._get_wait_for_graph_stats()
        }
        
        logger.info(f"Deadlock analysis completed. Found {len(deadlock_cycles)} potential deadlock cycles")
        return results
    
    def _build_resource_dependency_graph(self):
        """
        Build resource dependency graph from BPMN nodes
        """
        logger.debug("Building resource dependency graph...")
        
        # Add SQL-enabled nodes to resource graph
        for node_id, node_data in self.sql_resources.items():
            logger.debug(f"Processing node {node_id}, data type: {type(node_data)}, data: {node_data}")
            
            # Ensure node_data is a dictionary
            if not isinstance(node_data, dict):
                logger.warning(f"Node {node_id} has invalid data type: {type(node_data)}. Skipping.")
                continue
            
            # Convert sets to lists for JSON serialization and networkx compatibility
            resources = node_data.get('resources', {})
            node_attrs = {
                'name': node_data.get('name', node_id),
                'sql': node_data.get('sql', ''),
                'labels': node_data.get('labels', []),
                'tables': list(resources.get('tables', set())),
                'operations': list(resources.get('operations', set())),
                'columns': list(resources.get('columns', set()))
            }
            self.resource_graph.add_node(node_id, **node_attrs)
        
        logger.debug(f"Added {len(self.sql_resources)} SQL nodes to resource graph")
    
    def _build_wait_for_graph(self, parallel_scenarios: List[Dict]):
        """
        Build wait-for graph with enhanced logic for convergent JOIN deadlocks
        
        Args:
            parallel_scenarios: List of parallel execution scenarios
        """
        logger.info(f"Building wait-for graph from {len(parallel_scenarios)} scenarios...")
        
        # Debug: Log all scenario types being processed
        scenario_types = [scenario.get('gateway_type', 'UNKNOWN') for scenario in parallel_scenarios]
        logger.info(f"Scenario types to process: {scenario_types}")
        
        for i, scenario in enumerate(parallel_scenarios):
            logger.info(f"Processing scenario {i+1}/{len(parallel_scenarios)}: {scenario.get('gateway_type', 'UNKNOWN')}")
            self._analyze_scenario_for_conflicts(scenario)
        
        logger.info(f"Wait-for graph built with {self.wait_for_graph.number_of_nodes()} nodes and {self.wait_for_graph.number_of_edges()} edges")
    
    def _analyze_scenario_for_conflicts(self, scenario: Dict):
        """
        Analyze a single parallel scenario for potential conflicts
        
        Args:
            scenario: Parallel scenario dictionary
        """
        logger.info(f"Analyzing scenario: {scenario['gateway_type']} with {len(scenario['paths'])} paths")
        
        # Enhanced logging for AND_JOIN scenarios
        if scenario['gateway_type'] == 'AND_JOIN':
            logger.info(f"Processing AND_JOIN scenario - Gateway: {scenario.get('gateway_node_id', 'unknown')}")
            for i, path in enumerate(scenario['paths']):
                logger.info(f"  AND_JOIN Path {i+1}: {len(path)} SQL nodes - {path}")
        
        paths = scenario['paths']
        
        # Compare each pair of paths for conflicts
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                path1 = paths[i]
                path2 = paths[j]
                
                logger.debug(f"Comparing path {i+1} vs path {j+1} in {scenario['gateway_type']}")
                conflicts = self._detect_path_conflicts(path1, path2, scenario)
                
                if conflicts:
                    logger.info(f"Found {len(conflicts)} conflicts between paths in {scenario['gateway_type']}")
                    self._add_conflicts_to_wait_for_graph(conflicts, scenario)
                else:
                    logger.debug(f"No conflicts found between paths {i+1} and {j+1}")
    
    def _detect_path_conflicts(self, path1: List[str], path2: List[str], scenario: Dict) -> List[Dict]:
        """
        Detect resource conflicts between two parallel paths
        
        Args:
            path1: First execution path
            path2: Second execution path
            scenario: Parallel scenario context
            
        Returns:
            List[Dict]: List of detected conflicts
        """
        conflicts = []
        logger.debug(f"    Analyzing conflicts between Path 1: {path1} and Path 2: {path2}")
        
        # Check each node in path1 against each node in path2
        for node1_id in path1:
            for node2_id in path2:
                logger.debug(f"      Checking nodes: {node1_id} vs {node2_id}")
                
                # Check if both nodes have SQL resources
                if node1_id not in self.sql_resources:
                    logger.debug(f"        [SKIP] Node {node1_id} not found in SQL resources")
                    continue
                if node2_id not in self.sql_resources:
                    logger.debug(f"        [SKIP] Node {node2_id} not found in SQL resources")
                    continue
                    
                logger.debug(f"        Both nodes have SQL resources - analyzing conflict")
                conflict = self._check_resource_conflict(node1_id, node2_id, scenario)
                if conflict:
                    logger.debug(f"        [FOUND] Conflict detected: {conflict['conflict_type']}")
                    conflicts.append(conflict)
                else:
                    logger.debug(f"        [NONE] No conflict found")
        
        logger.debug(f"    Total conflicts found: {len(conflicts)}")
        return conflicts
    
    def _check_resource_conflict(self, node1_id: str, node2_id: str, scenario: Dict) -> Optional[Dict]:
        """
        Check for resource conflict between two SQL nodes with enhanced validation
        Now includes cross-table conflicts via shared columns and foreign key relationships
        
        Args:
            node1_id: First node ID
            node2_id: Second node ID
            scenario: Parallel scenario context
            
        Returns:
            Optional[Dict]: Conflict details if found, None otherwise
        """
        # Skip self-comparison
        if node1_id == node2_id:
            return None
            
        res1 = self.sql_resources[node1_id]['resources']
        res2 = self.sql_resources[node2_id]['resources']
        
        node1_name = self.sql_resources[node1_id].get('name', node1_id)
        node2_name = self.sql_resources[node2_id].get('name', node2_id)
        
        logger.debug(f"  ANALYZING CONFLICT: {node1_name} ({node1_id}) <-> {node2_name} ({node2_id})")
        logger.debug(f"    Node1 - Tables: {res1['tables']}, Operations: {res1['operations']}, Columns: {res1['columns']}")
        logger.debug(f"    Node2 - Tables: {res2['tables']}, Operations: {res2['operations']}, Columns: {res2['columns']}")
        
        # ENHANCED FILTER 1: Check for mutual exclusion - if conditions are mutually exclusive, no conflict possible
        if self._check_mutual_exclusion(res1, res2):
            logger.debug(f"  [X] FILTERED: {node1_name} <-> {node2_name} - mutually exclusive WHERE conditions")
            return None
        
        # ENHANCED FILTER 2: Check for shared resources (both tables AND columns for cross-table conflicts)
        table_overlap = res1['tables'].intersection(res2['tables'])
        column_overlap = res1['columns'].intersection(res2['columns'])
        
        logger.debug(f"    Table overlap: {table_overlap}")
        logger.debug(f"    Column overlap: {column_overlap}")
        
        # NEW: Allow cross-table conflicts via shared columns (foreign key relationships)
        has_shared_resources = bool(table_overlap or column_overlap)
        
        if not has_shared_resources:
            logger.debug(f"  [X] FILTERED: {node1_name} <-> {node2_name} - no shared tables or columns")
            return None
        
        # ENHANCED FILTER 3: Check operations - must have conflicting operations
        ops1 = res1['operations']
        ops2 = res2['operations']
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # Only these scenarios create real deadlock potential:
        has_write_write = (ops1.intersection(write_ops) and ops2.intersection(write_ops))
        has_write_read = ((ops1.intersection(write_ops) and 'SELECT' in ops2) or 
                         ('SELECT' in ops1 and ops2.intersection(write_ops)))
        
        logger.debug(f"    Has write-write: {has_write_write}, Has write-read: {has_write_read}")
        
        if not has_write_write and not has_write_read:
            logger.debug(f"  [X] FILTERED: {node1_name} <-> {node2_name} - no conflicting operations")
            return None
        
        # ENHANCED FILTER 4: For OR gateways, require Write-Write conflicts only (higher confidence)
        if scenario['gateway_type'] == 'OR_SPLIT' and not has_write_write:
            logger.debug(f"  [X] FILTERED: {node1_name} <-> {node2_name} - OR gateway requires Write-Write conflict")
            return None
        
        # ENHANCED FILTER 5: Gateway-specific validation with enhanced criteria for cross-table conflicts
        gateway_valid = self._validate_enhanced_gateway_conflict(scenario['gateway_type'], ops1, ops2, table_overlap, column_overlap)
        logger.debug(f"    Gateway validation ({scenario['gateway_type']}): {gateway_valid}")
        
        if not gateway_valid:
            logger.debug(f"  [X] FILTERED: {node1_name} <-> {node2_name} - enhanced gateway validation failed")
            return None
        
        # Determine conflict type and severity (enhanced for cross-table conflicts)
        conflict_type = self._determine_enhanced_conflict_type(ops1, ops2, table_overlap, column_overlap)
        logger.debug(f"    Conflict type: {conflict_type}")
        
        if not conflict_type:
            logger.debug(f"  [X] FILTERED: {node1_name} <-> {node2_name} - no conflict type determined")
            return None
        
        # Check for mutual exclusion (reduces conflict severity)
        is_mutually_exclusive = self._check_mutual_exclusion(res1, res2)
        
        # Calculate conflict severity (enhanced for cross-table conflicts)
        severity = self._calculate_enhanced_conflict_severity(conflict_type, table_overlap, column_overlap, is_mutually_exclusive, scenario)
        
        logger.info(f"  [OK] CONFLICT VALIDATED: {node1_name} <-> {node2_name} - {conflict_type}")
        
        # Build enhanced conflict data with cross-table information
        all_involved_tables = list(res1['tables'].union(res2['tables']))
        
        conflict = {
            'node1_id': node1_id,
            'node2_id': node2_id,
            'node1_name': node1_name,
            'node2_name': self.sql_resources[node2_id]['name'],
            'conflict_type': conflict_type,
            'shared_tables': list(table_overlap),
            'shared_columns': list(column_overlap),
            'all_involved_tables': all_involved_tables,
            'operations1': list(res1['operations']),
            'operations2': list(res2['operations']),
            'is_mutually_exclusive': is_mutually_exclusive,
            'is_cross_table': len(table_overlap) == 0 and len(column_overlap) > 0,  # NEW: Flag for cross-table conflicts
            'severity': severity,
            'scenario_type': scenario['gateway_type'],
            'scenario_id': scenario.get('gateway_node_id', scenario.get('gateway_id', 'unknown'))
        }
        
        logger.debug(f"Found {conflict_type} conflict: {conflict['node1_name']} vs {conflict['node2_name']} (Severity: {severity})")
        return conflict
    
    def _determine_conflict_type(self, ops1: Set[str], ops2: Set[str]) -> Optional[str]:
        """
        Determine the type of conflict between two sets of operations
        
        Args:
            ops1: First set of operations
            ops2: Second set of operations
            
        Returns:
            Optional[str]: Conflict type or None if no conflict
        """
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        read_ops = {'SELECT'}
        
        # Write-Write conflict (most severe)
        if ops1.intersection(write_ops) and ops2.intersection(write_ops):
            return 'WRITE_WRITE'
        
        # Read-Write conflict
        if (ops1.intersection(read_ops) and ops2.intersection(write_ops)) or \
           (ops2.intersection(read_ops) and ops1.intersection(write_ops)):
            return 'READ_WRITE'
        
        return None
    
    def _determine_strict_conflict_type(self, ops1: Set[str], ops2: Set[str], table_overlap: Set[str]) -> Optional[str]:
        """
        Determine strict conflict type based on operations and table overlap
        
        Args:
            ops1: Operations from first node
            ops2: Operations from second node
            table_overlap: Set of overlapping tables
            
        Returns:
            Optional[str]: Conflict type or None if no conflict
        """
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # Write-Write conflict (most severe) - only on same tables
        if ops1.intersection(write_ops) and ops2.intersection(write_ops):
            if table_overlap:
                return 'WRITE_WRITE'
        
        # Read-Write conflict (only on same tables)
        if table_overlap:
            if (ops1.intersection({'SELECT'}) and ops2.intersection(write_ops)) or \
               (ops2.intersection({'SELECT'}) and ops1.intersection(write_ops)):
                return 'READ_WRITE'
        
        return None
    
    def _validate_enhanced_gateway_conflict(self, gateway_type: str, ops1: Set[str], ops2: Set[str], 
                                          table_overlap: Set[str], column_overlap: Set[str]) -> bool:
        """
        Enhanced gateway-specific conflict validation including cross-table conflicts
        
        Args:
            gateway_type: Type of gateway
            ops1: Operations from first node
            ops2: Operations from second node
            table_overlap: Set of overlapping tables
            column_overlap: Set of overlapping columns
            
        Returns:
            bool: True if conflict is valid for this gateway type
        """
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # AND_JOIN: Allow both same-table and cross-table conflicts
        if gateway_type == 'AND_JOIN':
            # Same table conflicts: allow write-write and write-read
            if table_overlap:
                return True
            # Cross-table conflicts: require write-write operations (higher confidence)
            if column_overlap and ops1.intersection(write_ops) and ops2.intersection(write_ops):
                return True
            return False
        
        # OR_JOIN: Be more conservative - require write-write conflicts only
        if gateway_type == 'OR_JOIN':
            # Same table: allow write-write only
            if table_overlap and ops1.intersection(write_ops) and ops2.intersection(write_ops):
                return True
            # Cross-table: require write-write with higher confidence
            if column_overlap and ops1.intersection(write_ops) and ops2.intersection(write_ops):
                return True
            return False
        
        # Default: Conservative approach
        has_table_overlap = bool(table_overlap)
        has_write_write = bool(ops1.intersection(write_ops) and ops2.intersection(write_ops))
        return has_table_overlap and has_write_write
        has_write_write = bool(ops1.intersection(write_ops) and ops2.intersection(write_ops))
        has_write_read = bool((ops1.intersection(write_ops) and 'SELECT' in ops2) or 
                         ('SELECT' in ops1 and ops2.intersection(write_ops)))
        
        # AND_SPLIT/AND_JOIN: Guaranteed parallel execution - allow both same-table and cross-table conflicts
        if 'AND_' in gateway_type:
            # For same-table conflicts: allow both write-write and write-read
            if table_overlap:
                return has_write_write or has_write_read
            # For cross-table conflicts: require write-write (higher confidence for foreign key conflicts)
            elif column_overlap:
                return has_write_write
        
        # OR_SPLIT/OR_JOIN: Conditional parallel - only Write-Write conflicts (higher confidence)
        elif 'OR_' in gateway_type:
            # For same-table conflicts: write-write only
            if table_overlap:
                return has_write_write
            # For cross-table conflicts: write-write only with high confidence
            elif column_overlap:
                return has_write_write
        
        # XOR_SPLIT/XOR_JOIN: Mutually exclusive execution - no parallel conflicts possible
        elif 'XOR' in gateway_type:
            return False
        
        return False
    
    def _determine_enhanced_conflict_type(self, ops1: Set[str], ops2: Set[str], table_overlap: Set[str], column_overlap: Set[str]) -> Optional[str]:
        """
        Determine enhanced conflict type including cross-table conflicts
        
        Args:
            ops1: Operations from first node
            ops2: Operations from second node
            table_overlap: Set of overlapping tables
            column_overlap: Set of overlapping columns
            
        Returns:
            Optional[str]: Conflict type or None if no conflict
        """
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # Write-Write conflicts
        if ops1.intersection(write_ops) and ops2.intersection(write_ops):
            if table_overlap:
                return 'WRITE_WRITE_SAME_TABLE'
            elif column_overlap:
                return 'WRITE_WRITE_CROSS_TABLE'
        
        # Read-Write conflicts (only for same table)
        if table_overlap:
            if (ops1.intersection(write_ops) and 'SELECT' in ops2) or \
               ('SELECT' in ops1 and ops2.intersection(write_ops)):
                return 'READ_WRITE_SAME_TABLE'
        
        return None
        """
        Determine enhanced conflict type based on operations and resource overlap
        
        Args:
            ops1: Operations from first node
            ops2: Operations from second node
            table_overlap: Set of overlapping tables
            column_overlap: Set of overlapping columns
            
        Returns:
            Optional[str]: Conflict type or None if no conflict
        """
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # Write-Write conflict (most severe)
        if ops1.intersection(write_ops) and ops2.intersection(write_ops):
            if table_overlap:
                return 'WRITE_WRITE_SAME_TABLE'
            elif column_overlap:
                return 'WRITE_WRITE_CROSS_TABLE'  # NEW: Cross-table write-write via shared columns
        
        # Read-Write conflict (only on same tables for now)
        if table_overlap:
            if (ops1.intersection({'SELECT'}) and ops2.intersection(write_ops)) or \
               (ops2.intersection({'SELECT'}) and ops1.intersection(write_ops)):
                return 'READ_WRITE_SAME_TABLE'
        
        return None
    
    def _calculate_enhanced_conflict_severity(self, conflict_type: str, table_overlap: Set[str], column_overlap: Set[str],
                                           is_mutually_exclusive: bool, scenario: Dict) -> str:
        """
        Calculate enhanced conflict severity for cross-table conflicts
        
        Args:
            conflict_type: Type of conflict
            table_overlap: Set of overlapping tables
            column_overlap: Set of overlapping columns
            is_mutually_exclusive: Whether operations are mutually exclusive
            scenario: Scenario context
            
        Returns:
            str: Severity level (LOW, MEDIUM, HIGH, CRITICAL)
        """
        base_severity = 'MEDIUM'
        
        # Base severity by conflict type
        if conflict_type == 'WRITE_WRITE_SAME_TABLE':
            base_severity = 'HIGH'
        elif conflict_type == 'WRITE_WRITE_CROSS_TABLE':
            base_severity = 'HIGH'  # Cross-table write conflicts are also high risk
        elif conflict_type == 'READ_WRITE_SAME_TABLE':
            base_severity = 'MEDIUM'
        
        # Adjust for mutual exclusion
        if is_mutually_exclusive:
            severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            current_index = severity_levels.index(base_severity)
            if current_index > 0:
                base_severity = severity_levels[current_index - 1]
        
        # Adjust for scenario type
        if scenario['gateway_type'] == 'AND_JOIN':
            # AND_JOIN scenarios are more likely to cause deadlocks
            severity_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            current_index = severity_levels.index(base_severity)
            if current_index < len(severity_levels) - 1:
                base_severity = severity_levels[current_index + 1]
        
        return base_severity
        """
        Calculate enhanced conflict severity including cross-table conflicts
        
        Args:
            conflict_type: Type of conflict
            table_overlap: Set of overlapping tables
            column_overlap: Set of overlapping columns
            is_mutually_exclusive: Whether operations are mutually exclusive
            scenario: Parallel scenario context
            
        Returns:
            str: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        # Base severity from conflict type
        base_severity = {
            'WRITE_WRITE_SAME_TABLE': 'HIGH',
            'WRITE_WRITE_CROSS_TABLE': 'MEDIUM',  # NEW: Lower than same-table but still significant
            'READ_WRITE_SAME_TABLE': 'MEDIUM'
        }.get(conflict_type, 'LOW')
        
        # Reduce severity if mutually exclusive
        if is_mutually_exclusive:
            severity_reduction = {
                'HIGH': 'MEDIUM',
                'MEDIUM': 'LOW',
                'LOW': 'LOW'
            }
            base_severity = severity_reduction.get(base_severity, 'LOW')
        
        # Increase severity for AND gateways (guaranteed parallel execution)
        if 'AND' in scenario['gateway_type']:
            severity_increase = {
                'HIGH': 'CRITICAL',
                'MEDIUM': 'HIGH',
                'LOW': 'MEDIUM'
            }
            base_severity = severity_increase.get(base_severity, base_severity)
        
        return base_severity
    
    def _check_mutual_exclusion(self, res1: Dict, res2: Dict) -> bool:
        """
        Check if two resources have mutually exclusive WHERE conditions
        
        Args:
            res1: First resource dictionary
            res2: Second resource dictionary
            
        Returns:
            bool: True if conditions are mutually exclusive
        """
        # Simple heuristic: Check for conflicting WHERE conditions
        # This is a simplified implementation - could be enhanced with SQL parsing
        
        conditions1 = res1.get('conditions', set())
        conditions2 = res2.get('conditions', set())
        
        # For now, assume they're not mutually exclusive
        # TODO: Implement proper SQL WHERE clause analysis
        return False
        """
        Check if two SQL resources have mutually exclusive WHERE conditions
        
        Args:
            res1: First SQL resource
            res2: Second SQL resource
            
        Returns:
            bool: True if resources are mutually exclusive
        """
        try:
            conditions1 = res1.get('where_conditions', [])
            conditions2 = res2.get('where_conditions', [])
            
            # Check for mutual exclusion: same column with different values
            for cond1 in conditions1:
                for cond2 in conditions2:
                    if (cond1['column'] == cond2['column'] and 
                        cond1['operator'] == '=' and cond2['operator'] == '=' and
                        cond1['value'] != cond2['value']):
                        
                        logger.debug(f"Mutual exclusion detected: {cond1['raw_condition']} vs {cond2['raw_condition']}")
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking mutual exclusion: {e}")
            return False
    
    def _calculate_conflict_severity(self, conflict_type: str, table_overlap: Set[str], 
                                   is_mutually_exclusive: bool, scenario: Dict) -> str:
        """
        Calculate conflict severity (legacy method)
        
        Args:
            conflict_type: Type of conflict
            table_overlap: Set of overlapping tables
            is_mutually_exclusive: Whether operations are mutually exclusive
            scenario: Scenario context
            
        Returns:
            str: Severity level
        """
        # Use enhanced method
        return self._calculate_enhanced_conflict_severity(
            conflict_type, table_overlap, set(), is_mutually_exclusive, scenario
        )
        """
        Calculate the severity of a conflict
        
        Args:
            conflict_type: Type of conflict
            table_overlap: Set of overlapping tables
            is_mutually_exclusive: Whether operations are mutually exclusive
            scenario: Parallel scenario context
            
        Returns:
            str: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        # Base severity from conflict type
        base_severity = {
            'WRITE_WRITE': 'HIGH',
            'READ_WRITE': 'MEDIUM'
        }.get(conflict_type, 'LOW')
        
        # Reduce severity if mutually exclusive
        if is_mutually_exclusive:
            severity_reduction = {
                'HIGH': 'MEDIUM',
                'MEDIUM': 'LOW',
                'LOW': 'LOW'
            }
            base_severity = severity_reduction.get(base_severity, 'LOW')
        
        # Increase severity for AND gateways (guaranteed parallel execution)
        if 'AND' in scenario['gateway_type']:
            severity_increase = {
                'HIGH': 'CRITICAL',
                'MEDIUM': 'HIGH',
                'LOW': 'MEDIUM'
            }
            base_severity = severity_increase.get(base_severity, base_severity)
        
        return base_severity
    
    def _add_conflicts_to_wait_for_graph(self, conflicts: List[Dict], scenario: Dict):
        """
        Add detected conflicts to the wait-for graph
        
        Args:
            conflicts: List of conflicts to add
            scenario: Parallel scenario context
        """
        for conflict in conflicts:
            # Add nodes to wait-for graph
            node1_id = conflict['node1_id']
            node2_id = conflict['node2_id']
            
            # Add nodes with attributes
            self.wait_for_graph.add_node(node1_id, 
                                       name=conflict['node1_name'],
                                       type='sql_task')
            self.wait_for_graph.add_node(node2_id, 
                                       name=conflict['node2_name'],
                                       type='sql_task')
            
            # Add bidirectional edges (mutual wait)
            self.wait_for_graph.add_edge(node1_id, node2_id, 
                                       conflict_type=conflict['conflict_type'],
                                       severity=conflict['severity'],
                                       scenario_type=scenario['gateway_type'])
            self.wait_for_graph.add_edge(node2_id, node1_id, 
                                       conflict_type=conflict['conflict_type'],
                                       severity=conflict['severity'],
                                       scenario_type=scenario['gateway_type'])
            
            # Store conflict for reporting (avoid duplicates)
            if not self._is_duplicate_conflict(conflict):
                self.detected_conflicts.append(conflict)
    
    def _is_duplicate_conflict(self, new_conflict: Dict) -> bool:
        """
        Check if a conflict is already in the detected conflicts list
        
        Args:
            new_conflict: Conflict to check for duplicates
            
        Returns:
            bool: True if conflict is duplicate
        """
        for existing_conflict in self.detected_conflicts:
            # Check if it's the same conflict (either A->B or B->A)
            same_nodes = (
                (existing_conflict['node1_id'] == new_conflict['node1_id'] and 
                 existing_conflict['node2_id'] == new_conflict['node2_id']) or
                (existing_conflict['node1_id'] == new_conflict['node2_id'] and 
                 existing_conflict['node2_id'] == new_conflict['node1_id'])
            )
            
            if same_nodes and existing_conflict['conflict_type'] == new_conflict['conflict_type']:
                return True
        
        return False
    
    def _detect_deadlock_cycles(self) -> List[List[str]]:
        """
        Detect deadlock cycles using Tarjan's strongly connected components algorithm
        Returns:
            List[List[str]]: List of detected cycles
        """
        logger.info("Detecting deadlock cycles using Tarjan's algorithm...")

        deadlock_message = "data query if parallel relation"

        try:
            # Find strongly connected components
            sccs = list(nx.strongly_connected_components(self.wait_for_graph))

            # Filter out single-node components (not cycles)
            cycles = [list(scc) for scc in sccs if len(scc) > 1]

            logger.info(f"Found {len(cycles)} potential deadlock cycles")

            # Store cycles as deadlock risks, and tag nodes with deadlock message
            for cycle in cycles:
                risk = {
                    'type': 'DEADLOCK_CYCLE',
                    'nodes': cycle,
                    'node_names': [self.sql_resources.get(node_id, {}).get('name', node_id) for node_id in cycle],
                    'cycle_length': len(cycle)
                }
                self.deadlock_risks.append(risk)
                for node_id in cycle:
                    # Tag node in resource_graph if exists
                    if node_id in self.resource_graph.nodes:
                        self.resource_graph.nodes[node_id]['deadlock_message'] = deadlock_message
                    # Tag node in sql_resources if exists
                    if node_id in self.sql_resources:
                        self.sql_resources[node_id]['deadlock_message'] = deadlock_message
                    # OPTIONAL: Update to Neo4j if connector ada
                    if hasattr(self, "neo4j_connector") and self.neo4j_connector:
                        try:
                            self.neo4j_connector.update_node_deadlock_message(node_id, deadlock_message)
                        except Exception as e:
                            logger.warning(f"Failed to update deadlock_message for node {node_id} in Neo4j: {e}")

            return cycles

        except Exception as e:
            logger.error(f"Error detecting deadlock cycles: {e}")
            return []
    
    def _analyze_conflict_severity(self) -> Dict:
        """
        Analyze the severity distribution of detected conflicts
        
        Returns:
            Dict: Conflict severity analysis
        """
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        conflict_types = defaultdict(int)
        
        for conflict in self.detected_conflicts:
            severity = conflict.get('severity', 'MEDIUM')
            conflict_type = conflict.get('conflict_type', 'UNKNOWN')
            
            severity_counts[severity] += 1
            conflict_types[conflict_type] += 1
        
        return {
            'severity_distribution': severity_counts,
            'conflict_type_distribution': dict(conflict_types),
            'total_conflicts': len(self.detected_conflicts),
            'high_severity_conflicts': severity_counts['HIGH'] + severity_counts['CRITICAL'],
            'critical_conflicts': severity_counts['CRITICAL'],
            'high_conflicts': severity_counts['HIGH'],
            'medium_conflicts': severity_counts['MEDIUM'],
            'low_conflicts': severity_counts['LOW']
        }

    
    def _get_resource_graph_stats(self) -> Dict:
        """
        Get statistics about the resource graph
        
        Returns:
            Dict: Resource graph statistics
        """
        return {
            'nodes': self.resource_graph.number_of_nodes(),
            'edges': self.resource_graph.number_of_edges(),
            'density': nx.density(self.resource_graph) if self.resource_graph.number_of_nodes() > 0 else 0
        }
    
    def _get_wait_for_graph_stats(self) -> Dict:
        """
        Get statistics about the wait-for graph
        
        Returns:
            Dict: Wait-for graph statistics
        """
        num_nodes = self.wait_for_graph.number_of_nodes()
        num_edges = self.wait_for_graph.number_of_edges()
        
        return {
            'nodes': num_nodes,
            'edges': num_edges,
            'density': nx.density(self.wait_for_graph) if num_nodes > 0 else 0,
            'is_strongly_connected': nx.is_strongly_connected(self.wait_for_graph) if num_nodes > 1 else False
        }
    
    def run_conflict_detection_only(self) -> Dict:
        """
        Run only conflict detection without full deadlock analysis
        
        Returns:
            Dict: Conflict detection results
        """
        logger.info("Running conflict detection only...")
        
        # Build resource dependency graph
        self._build_resource_dependency_graph()
        
        # Find all pairs of SQL nodes and check for conflicts
        sql_node_ids = list(self.sql_resources.keys())
        all_conflicts = []
        
        for i, node1_id in enumerate(sql_node_ids):
            for j, node2_id in enumerate(sql_node_ids[i+1:], i+1):
                # Create dummy scenario for conflict checking
                dummy_scenario = {
                    'gateway_type': 'AND_JOIN',
                    'gateway_node_id': 'dummy'
                }
                
                conflict = self._check_resource_conflict(node1_id, node2_id, dummy_scenario)
                if conflict:
                    all_conflicts.append(conflict)
        
        # Analyze conflicts
        conflict_analysis = self._analyze_conflicts_list(all_conflicts)
        
        return {
            'total_sql_nodes': len(sql_node_ids),
            'detected_conflicts': all_conflicts,
            'conflict_analysis': conflict_analysis
        }

    
    def _analyze_conflicts_list(self, conflicts: List[Dict]) -> Dict:
        """
        Analyze a list of conflicts for statistics
        
        Args:
            conflicts: List of conflict dictionaries
            
        Returns:
            Dict: Conflict analysis results
        """
        severity_counts = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        conflict_types = defaultdict(int)
        cross_table_count = 0
        
        for conflict in conflicts:
            severity = conflict.get('severity', 'MEDIUM')
            conflict_type = conflict.get('conflict_type', 'UNKNOWN')
            is_cross_table = conflict.get('is_cross_table', False)
            
            severity_counts[severity] += 1
            conflict_types[conflict_type] += 1
            
            if is_cross_table:
                cross_table_count += 1
        
        return {
            'total_conflicts': len(conflicts),
            'severity_distribution': severity_counts,
            'conflict_type_distribution': dict(conflict_types),
            'cross_table_conflicts': cross_table_count,
            'same_table_conflicts': len(conflicts) - cross_table_count,
            'high_severity_conflicts': severity_counts['HIGH'] + severity_counts['CRITICAL']
        }