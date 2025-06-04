import logging
import re
import sqlparse
import json
import os
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from neo4j import GraphDatabase
from collections import defaultdict, deque
import networkx as nx
import sys

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

class SQLDeadlockDetector:
    """
    SQL Deadlock Detector using Graph Theory:
    - Tarjan's Algorithm for Strongly Connected Components
    - Automated SQL resource extraction
    - Resource conflict detection across all gateway types
    - Dynamic analysis without hardcoded patterns
    """
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, database: str = "neo4j"):
        logger.debug(f"Initializing SQLDeadlockDetector with URI: {neo4j_uri}")
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            logger.debug("Neo4j driver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j driver: {e}")
            raise
        self.database = database
        self.graph_data = None
        self.resource_graph = nx.DiGraph()
        self.wait_for_graph = nx.DiGraph()
        self.sql_resources = {}
        self.deadlock_risks = []
        
        # Add conflict tracking for JSON export
        self.detected_conflicts = []
        self.conflict_output_file = "sql_conflicts.json"
        
        logger.debug("SQLDeadlockDetector initialization completed")
        
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            
    def fetch_graph_data(self) -> Dict:
        """Fetch complete graph data from Neo4j"""
        with self.driver.session(database=self.database) as session:
            # Get all nodes with their properties
            nodes_query = """
            MATCH (n)
            RETURN elementId(n) as id, labels(n) as labels, properties(n) as props
            """
            
            # Get all relationships
            rels_query = """
            MATCH (a)-[r]->(b)
            RETURN elementId(a) as source_id, elementId(b) as target_id, 
                   type(r) as rel_type, properties(r) as props
            """
            
            nodes_result = session.run(nodes_query)
            rels_result = session.run(rels_query)
            
            nodes = {record['id']: {
                'labels': record['labels'],
                'properties': record['props']
            } for record in nodes_result}
            
            relationships = [{
                'source_id': record['source_id'],
                'target_id': record['target_id'],
                'rel_type': record['rel_type'],
                'properties': record['props']
            } for record in rels_result]
            
            self.graph_data = {
                'nodes': nodes,
                'relationships': relationships
            }
            
            return self.graph_data
    
    def extract_sql_resources(self, sql_query: str) -> Dict[str, Set[str]]:
        """Extract database resources from SQL query with WHERE clause analysis"""
        if not sql_query:
            return {'tables': set(), 'columns': set(), 'operations': set(), 'where_conditions': []}
            
        try:
            # Parse SQL using sqlparse
            parsed = sqlparse.parse(sql_query.upper())
            resources = {
                'tables': set(),
                'columns': set(), 
                'operations': set(),
                'where_conditions': []  # New: store WHERE clause conditions for mutual exclusion analysis
            }
            
            for statement in parsed:
                # Extract operation type
                first_token = str(statement.tokens[0]).strip()
                if first_token in ['SELECT', 'UPDATE', 'INSERT', 'DELETE']:
                    resources['operations'].add(first_token)
                
                # Extract table names using regex patterns
                sql_text = str(statement)
                
                # Table patterns for different operations
                table_patterns = [
                    r'FROM\s+([\w]+)',
                    r'UPDATE\s+([\w]+)',
                    r'INSERT\s+INTO\s+([\w]+)',
                    r'DELETE\s+FROM\s+([\w]+)',
                    r'JOIN\s+([\w]+)'
                ]
                
                for pattern in table_patterns:
                    matches = re.findall(pattern, sql_text, re.IGNORECASE)
                    resources['tables'].update(matches)
                
                # Extract column names from WHERE clauses - enhanced to capture ALL columns
                # First pattern: direct column references in conditions
                where_pattern = r'WHERE\s+(.+?)(?:ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|;|$)'
                where_match = re.search(where_pattern, sql_text, re.IGNORECASE | re.DOTALL)
                if where_match:
                    where_clause = where_match.group(1)
                    # Extract all column names from WHERE clause conditions
                    column_patterns = [
                        r'(\w+)\s*[=<>!]',  # column = value
                        r'(\w+)\s+(?:IN|LIKE|BETWEEN)',  # column IN/LIKE/BETWEEN
                        r'(\w+)\s+IS\s+(?:NULL|NOT\s+NULL)',  # column IS NULL
                    ]
                    for pattern in column_patterns:
                        column_matches = re.findall(pattern, where_clause, re.IGNORECASE)
                        resources['columns'].update(column_matches)
                        
                    logger.debug(f"WHERE clause: {where_clause}")
                    logger.debug(f"Extracted WHERE columns: {column_matches}")
                
                # NEW: Extract complete WHERE conditions for mutual exclusion analysis
                self._extract_where_conditions(sql_text, resources)
                
                # Extract SET clause columns (for UPDATE)
                set_pattern = r'SET\s+([\w]+)\s*='
                set_matches = re.findall(set_pattern, sql_text, re.IGNORECASE)
                resources['columns'].update(set_matches)
                
            return resources
            
        except Exception as e:
            logger.warning(f"Error parsing SQL: {e}")
            return {'tables': set(), 'columns': set(), 'operations': set(), 'where_conditions': []}

    def _extract_where_conditions(self, sql_text: str, resources: Dict):
        """Extract WHERE clause conditions for mutual exclusion analysis"""
        try:
            # Find WHERE clause using regex
            where_match = re.search(r'WHERE\s+(.+?)(?:ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|$)', sql_text, re.IGNORECASE | re.DOTALL)
            if where_match:
                where_clause = where_match.group(1).strip()
                
                # Parse equality conditions like "column = 'value'"
                equality_conditions = re.findall(r'(\w+)\s*=\s*[\'"]?([^\s\'"]+)[\'"]?', where_clause, re.IGNORECASE)
                
                # Store parsed conditions for mutual exclusion checking
                for column, value in equality_conditions:
                    condition = {
                        'column': column.upper(),
                        'operator': '=',
                        'value': value.strip('\'"').upper(),
                        'raw_condition': f"{column} = '{value}'"
                    }
                    resources['where_conditions'].append(condition)
                    
                logger.debug(f"Extracted WHERE conditions: {resources['where_conditions']}")
                
        except Exception as e:
            logger.warning(f"Error extracting WHERE conditions: {e}")

    def _check_mutual_exclusion(self, res1: Dict, res2: Dict) -> bool:
        """Check if two SQL resources have mutually exclusive WHERE conditions"""
        try:
            conditions1 = res1.get('where_conditions', [])
            conditions2 = res2.get('where_conditions', [])
            
            # Check for mutual exclusion: same column with different values
            for cond1 in conditions1:
                for cond2 in conditions2:
                    if (cond1['column'] == cond2['column'] and 
                        cond1['operator'] == '=' and cond2['operator'] == '=' and
                        cond1['value'] != cond2['value']):
                        
                        logger.info(f"Mutual exclusion detected: {cond1['raw_condition']} vs {cond2['raw_condition']}")
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking mutual exclusion: {e}")
            return False
    
    def build_resource_dependency_graph(self):
        """Build resource dependency graph from BPMN nodes"""
        if not self.graph_data:
            self.fetch_graph_data()
            
        # Extract SQL resources from each task
        for node_id, node_data in self.graph_data['nodes'].items():
            props = node_data['properties']
            
            # Check if node has SQL property
            if 'SQL' in props and props['SQL']:
                sql_query = props['SQL']
                resources = self.extract_sql_resources(sql_query)
                
                self.sql_resources[node_id] = {
                    'name': props.get('name', f'Node_{node_id}'),
                    'sql': sql_query,
                    'resources': resources,
                    'labels': node_data['labels']
                }
                
                # Add node to resource graph
                self.resource_graph.add_node(node_id, **self.sql_resources[node_id])
    
    def identify_all_parallel_paths(self) -> List[Dict]:
        """Identify all TRULY parallel execution paths by considering both SPLIT and JOIN"""
        parallel_scenarios = []
        
        # Focus on gateways that can cause real deadlocks - including JOIN gateways
        realistic_gateways = {
            'split': ['AND_SPLIT', 'OR_SPLIT'],
            'join': ['AND_JOIN', 'OR_JOIN']
        }
        
        # Method 1: Analyze from SPLIT gateways (forward analysis)
        for split_type in realistic_gateways['split']:
            for rel in self.graph_data['relationships']:
                if split_type in rel['rel_type']:
                    source_id = rel['source_id']
                    
                    # Find all paths from this split gateway
                    parallel_paths = self._find_truly_parallel_paths(source_id, split_type)
                    if len(parallel_paths) > 1:
                        scenario = {
                            'analysis_type': 'SPLIT_FORWARD',
                            'gateway_node_id': source_id,
                            'gateway_type': split_type,
                            'gateway_name': self.graph_data['nodes'][source_id]['properties'].get('name', f'Split_{source_id}'),
                            'paths': parallel_paths,
                            'path_count': len(parallel_paths),
                            'is_truly_parallel': self._validate_truly_parallel_execution(parallel_paths, split_type)
                        }
                        
                        # Only include scenarios that are truly parallel
                        if scenario['is_truly_parallel']:
                            parallel_scenarios.append(scenario)
                            logger.info(f"Found TRULY PARALLEL {split_type} with {len(parallel_paths)} paths (forward analysis)")
                        else:
                            logger.info(f"Skipping {split_type} - paths merge before potential conflicts (forward analysis)")
        
        # Method 2: Analyze from JOIN gateways (backward analysis)
        for join_type in realistic_gateways['join']:
            for rel in self.graph_data['relationships']:
                if join_type in rel['rel_type']:
                    target_id = rel['target_id']
                    
                    # Find all paths that lead to this join gateway
                    converging_paths = self._find_converging_parallel_paths(target_id, join_type)
                    if len(converging_paths) > 1:
                        scenario = {
                            'analysis_type': 'JOIN_BACKWARD',
                            'gateway_node_id': target_id,
                            'gateway_type': join_type,
                            'gateway_name': self.graph_data['nodes'][target_id]['properties'].get('name', f'Join_{target_id}'),
                            'paths': converging_paths,
                            'path_count': len(converging_paths),
                            'is_truly_parallel': self._validate_converging_parallel_execution(converging_paths, join_type)
                        }
                        
                        # Only include scenarios that are truly parallel
                        if scenario['is_truly_parallel']:
                            # Check if this scenario is not already covered by forward analysis
                            if not self._is_duplicate_scenario(scenario, parallel_scenarios):
                                parallel_scenarios.append(scenario)
                                logger.info(f"Found TRULY PARALLEL {join_type} with {len(converging_paths)} converging paths (backward analysis)")
                        else:
                            logger.info(f"Skipping {join_type} - paths not truly parallel (backward analysis)")
                        
        return parallel_scenarios
    
    def _find_converging_parallel_paths(self, join_node_id: str, join_type: str) -> List[List[str]]:
        """Find paths that converge at a JOIN gateway (backward analysis)"""
        paths = []
        
        # Get immediate predecessors to this join
        predecessors = []
        for rel in self.graph_data['relationships']:
            if rel['target_id'] == join_node_id and join_type in rel['rel_type']:
                predecessors.append(rel['source_id'])
        
        logger.info(f"Join {join_node_id} has {len(predecessors)} immediate predecessors")
        
        # For each predecessor, trace the path backward until corresponding split
        for predecessor in predecessors:
            path = self._trace_path_backward_from_join(predecessor, join_type)
            if path:  # Only include paths that have SQL nodes before join
                paths.append(path)
                logger.info(f"  Backward path found with {len(path)} SQL nodes: {[self.sql_resources.get(node, {}).get('name', node) for node in path]}")
                
        return paths
    
    def _trace_path_backward_from_join(self, start_node: str, join_type: str, max_depth: int = 20) -> List[str]:
        """Trace execution path backward from JOIN until it hits corresponding SPLIT gateway"""
        sql_path = []
        current = start_node
        visited = set()
        depth = 0
        
        # Determine corresponding SPLIT types
        split_types = {
            'AND_JOIN': ['AND_SPLIT'],
            'OR_JOIN': ['OR_SPLIT', 'AND_SPLIT']  # OR_JOIN can come from either OR_SPLIT or AND_SPLIT
        }
        corresponding_splits = split_types.get(join_type, [])
        
        while current and current not in visited and depth < max_depth:
            visited.add(current)
            depth += 1
            
            # Add SQL-enabled nodes to path (in reverse order)
            if current in self.sql_resources:
                sql_path.insert(0, current)  # Insert at beginning to maintain execution order
            
            # Check if we hit a SPLIT gateway
            incoming_rels = [rel for rel in self.graph_data['relationships'] if rel['target_id'] == current]
            
            for rel in incoming_rels:
                if any(split_type in rel['rel_type'] for split_type in corresponding_splits):
                    # We hit a corresponding split - stop tracing this path
                    logger.info(f"    Backward path stopped at {rel['rel_type']} gateway")
                    return sql_path
            
            # Find previous node (non-split)
            prev_nodes = [rel['source_id'] for rel in incoming_rels 
                         if not any(split_type in rel['rel_type'] for split_type in corresponding_splits)]
            
            # Continue with first previous node (simplified traversal)
            current = prev_nodes[0] if prev_nodes else None
            
        return sql_path
    
    def _validate_converging_parallel_execution(self, paths: List[List[str]], join_type: str) -> bool:
        """Validate if converging paths were truly executed in parallel"""
        
        # For AND_JOIN: Paths must have come from AND_SPLIT - always parallel
        if join_type == 'AND_JOIN':
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        # For OR_JOIN: Paths could have come from OR_SPLIT or AND_SPLIT
        elif join_type == 'OR_JOIN':
            # Similar validation as OR_SPLIT - can be parallel if multiple conditions triggered
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        return False
    
    def _is_duplicate_scenario(self, new_scenario: Dict, existing_scenarios: List[Dict]) -> bool:
        """Check if a scenario is already covered by existing scenarios"""
        new_paths_set = set()
        for path in new_scenario['paths']:
            new_paths_set.add(tuple(sorted(path)))
        
        for existing in existing_scenarios:
            existing_paths_set = set()
            for path in existing['paths']:
                existing_paths_set.add(tuple(sorted(path)))
            
            # If the paths are the same or very similar, consider it duplicate
            if len(new_paths_set.intersection(existing_paths_set)) > 0:
                logger.info(f"Duplicate scenario detected - skipping {new_scenario['gateway_type']}")
                return True
        
        return False
    
    def build_wait_for_graph(self):
        """Build wait-for graph with enhanced logic for convergent JOIN deadlocks"""
        parallel_scenarios = self.identify_all_parallel_paths()
        
        logger.info(f"Analyzing {len(parallel_scenarios)} scenarios (SPLIT + JOIN) for SQL conflicts")
        
        for scenario in parallel_scenarios:
            gateway_type = scenario['gateway_type']
            analysis_type = scenario['analysis_type']
            paths = scenario['paths']
            
            logger.info(f"\nAnalyzing {gateway_type} scenario ({analysis_type}) with {len(paths)} paths")
            
            # Handle different gateway types with appropriate logic
            if 'AND_' in gateway_type:
                # AND_SPLIT/AND_JOIN: All paths execute in parallel - high deadlock risk
                logger.info(f"{gateway_type}: Analyzing guaranteed parallel execution deadlock risks")
                self._analyze_parallel_conflicts(scenario, paths, 'PARALLEL')
                
            elif 'OR_' in gateway_type:
                # OR_SPLIT/OR_JOIN: Multiple paths can execute based on conditions - medium deadlock risk
                logger.info(f"{gateway_type}: Analyzing conditional parallel execution deadlock risks")
                self._analyze_parallel_conflicts(scenario, paths, 'CONDITIONAL_PARALLEL')
        
        # NEW: Add convergent JOIN deadlock detection for XOR->AND/OR scenarios
        self._detect_convergent_join_deadlocks()

    def _detect_convergent_join_deadlocks(self):
        """Detect deadlocks where different XOR paths converge at AND/OR JOINs"""
        logger.info("\n=== DETECTING CONVERGENT JOIN DEADLOCKS (XOR->AND/OR) ===")
        
        # Find all AND_JOIN and OR_JOIN targets
        convergent_joins = []
        for rel in self.graph_data['relationships']:
            if rel['rel_type'] in ['AND_JOIN', 'OR_JOIN']:
                join_target = rel['target_id']
                join_type = rel['rel_type']
                gateway_props = rel.get('properties', {})
                
                # Find all sources (predecessors) that lead to this JOIN
                join_sources = []
                for other_rel in self.graph_data['relationships']:
                    if (other_rel['target_id'] == join_target and 
                        other_rel['rel_type'] == join_type):
                        join_sources.append(other_rel['source_id'])
                
                if len(join_sources) > 1:  # Multiple paths converging
                    convergent_joins.append({
                        'join_target': join_target,
                        'join_type': join_type,
                        'join_sources': join_sources,
                        'gateway_id': gateway_props.get('gateway_id', 'Unknown'),
                        'gateway_props': gateway_props
                    })
        
        logger.info(f"Found {len(convergent_joins)} convergent JOINs to analyze")
        
        for join_info in convergent_joins:
            self._analyze_convergent_join_deadlock(join_info)

    def _analyze_convergent_join_deadlock(self, join_info: Dict):
        """Analyze specific convergent JOIN for potential SQL deadlocks"""
        join_target = join_info['join_target']
        join_type = join_info['join_type']
        join_sources = join_info['join_sources']
        gateway_id = join_info['gateway_id']
        
        target_name = self.graph_data['nodes'].get(join_target, {}).get('properties', {}).get('name', f'Join_{join_target}')
        
        logger.info(f"\nAnalyzing convergent {join_type} at '{target_name}' (Gateway: {gateway_id})")
        logger.info(f"  Convergent sources: {len(join_sources)} paths")
        
        # For each pair of convergent sources, check for SQL deadlock potential
        deadlock_pairs_found = 0
        
        for i, source1 in enumerate(join_sources):
            for j, source2 in enumerate(join_sources):
                if i >= j:  # Avoid duplicate analysis
                    continue
                
                # Trace back to find SQL nodes in each path
                path1_sql_nodes = self._trace_sql_nodes_from_convergent_source(source1, join_type)
                path2_sql_nodes = self._trace_sql_nodes_from_convergent_source(source2, join_type)
                
                if path1_sql_nodes and path2_sql_nodes:
                    source1_name = self.graph_data['nodes'].get(source1, {}).get('properties', {}).get('name', source1)
                    source2_name = self.graph_data['nodes'].get(source2, {}).get('properties', {}).get('name', source2)
                    
                    logger.info(f"    Checking convergent paths: '{source1_name}' vs '{source2_name}'")
                    logger.info(f"      Path 1 SQL nodes: {[self.sql_resources.get(n, {}).get('name', n) for n in path1_sql_nodes]}")
                    logger.info(f"      Path 2 SQL nodes: {[self.sql_resources.get(n, {}).get('name', n) for n in path2_sql_nodes]}")
                    
                    # Check for SQL conflicts between these convergent paths
                    conflicts_found = self._check_convergent_path_conflicts(
                        path1_sql_nodes, path2_sql_nodes, join_info
                    )
                    
                    if conflicts_found:
                        deadlock_pairs_found += conflicts_found
                        logger.info(f"      ✅ Found {conflicts_found} convergent deadlock pairs")
                    else:
                        logger.info(f"      ❌ No SQL conflicts between these convergent paths")
        
        if deadlock_pairs_found > 0:
            logger.info(f"  🔥 CONVERGENT {join_type} DEADLOCK: {deadlock_pairs_found} pairs at '{target_name}'")
        else:
            logger.info(f"  ✅ No convergent deadlocks found at '{target_name}'")

    def _trace_sql_nodes_from_convergent_source(self, source_node: str, join_type: str, max_depth: int = 15) -> List[str]:
        """Trace back from convergent source to find SQL nodes in the path"""
        sql_nodes = []
        current = source_node
        visited = set()
        depth = 0
        
        # First check if source itself has SQL
        if current in self.sql_resources:
            sql_nodes.append(current)
        
        # Trace backward to find more SQL nodes in this convergent path
        while current and current not in visited and depth < max_depth:
            visited.add(current)
            depth += 1
            
            # Find predecessors
            predecessors = []
            for rel in self.graph_data['relationships']:
                if rel['target_id'] == current:
                    # Stop at major gateways (SPLIT types) to avoid going too far back
                    if not any(gate_type in rel['rel_type'] for gate_type in ['XOR_SPLIT', 'AND_SPLIT', 'OR_SPLIT']):
                        predecessors.append(rel['source_id'])
                    elif 'XOR_SPLIT' in rel['rel_type']:
                        # For XOR_SPLIT, we can include it as it represents the divergent point
                        predecessors.append(rel['source_id'])
                        break  # Stop here as we found the divergent point
            
            # Continue with first predecessor
            if predecessors:
                current = predecessors[0]
                if current in self.sql_resources:
                    sql_nodes.insert(0, current)  # Insert at beginning for execution order
            else:
                break
        
        return sql_nodes

    def _check_convergent_path_conflicts(self, path1_sql_nodes: List[str], path2_sql_nodes: List[str], 
                                       join_info: Dict) -> int:
        """Check for SQL conflicts between convergent paths leading to same JOIN"""
        conflicts_found = 0
        join_type = join_info['join_type']
        join_target = join_info['join_target']
        gateway_id = join_info['gateway_id']
        
        # Check each SQL node in path1 against each SQL node in path2
        for node1 in path1_sql_nodes:
            for node2 in path2_sql_nodes:
                if node1 == node2:  # Skip same node
                    continue
                
                # NEW: Skip deadlock detection between parent-child nodes (same sequential path)
                if self._are_in_same_sequential_path(node1, node2):
                    node1_name = self.sql_resources[node1].get('name', node1)
                    node2_name = self.sql_resources[node2].get('name', node2)
                    logger.info(f"    ⚠️  SKIPPING: '{node1_name}' ↔ '{node2_name}' - Same sequential path (parent-child relationship)")
                    continue
                
                # Check for specific SQL resource conflicts
                conflict = self._check_specific_node_conflicts(node1, node2)
                if conflict:
                    node1_name = self.sql_resources[node1].get('name', node1)
                    node2_name = self.sql_resources[node2].get('name', node2)
                    target_name = self.graph_data['nodes'].get(join_target, {}).get('properties', {}).get('name', f'Join_{join_target}')
                    
                    logger.info(f"        🔥 CONVERGENT DEADLOCK: '{node1_name}' ↔ '{node2_name}'")
                    logger.info(f"           Shared tables: {list(conflict.get('table_conflicts', set()))}")
                    logger.info(f"           Operations: {conflict.get('operation_conflicts', [])}")
                    
                    # Add edges to wait-for graph for convergent deadlock
                    self.wait_for_graph.add_edge(node1, node2, 
                                               conflict=conflict,
                                               gateway_type=f'CONVERGENT_{join_type}',
                                               analysis_type='CONVERGENT_JOIN',
                                               scenario=target_name,
                                               execution_type='CONVERGENT_PARALLEL',
                                               gateway_id=gateway_id,
                                               convergent_join_target=join_target)
                    
                    self.wait_for_graph.add_edge(node2, node1, 
                                               conflict=conflict,
                                               gateway_type=f'CONVERGENT_{join_type}',
                                               analysis_type='CONVERGENT_JOIN',
                                               scenario=target_name,
                                               execution_type='CONVERGENT_PARALLEL',
                                               gateway_id=gateway_id,
                                               convergent_join_target=join_target)
                    
                    conflicts_found += 1
        
        return conflicts_found

    def _validate_realistic_deadlock(self, conflict: Dict, gateway_type: str, execution_type: str) -> bool:
        """Enhanced validation including convergent JOIN deadlocks and mutual exclusion checking"""
        
        # Original validations with enhanced OR_SPLIT logic
        if gateway_type == 'AND_SPLIT':
            return bool(conflict.get('table_conflicts') and conflict.get('operation_conflicts'))
        
        elif gateway_type == 'OR_SPLIT':
            # OR_SPLIT can be parallel IF conditions are not mutually exclusive
            # The mutual exclusion check is already done in _check_specific_node_conflicts
            # So if we reach here, the conditions allow concurrent execution
            return bool(conflict.get('table_conflicts') and conflict.get('operation_conflicts'))
        
        # NEW: Convergent JOIN deadlock validation
        elif gateway_type.startswith('CONVERGENT_'):
            # Convergent deadlocks are realistic if:
            # 1. Nodes have shared tables AND conflicting operations
            # 2. The JOIN type is AND or OR (both can cause actual waiting)
            if gateway_type in ['CONVERGENT_AND_JOIN', 'CONVERGENT_OR_JOIN']:
                has_table_conflicts = bool(conflict.get('table_conflicts'))
                has_operation_conflicts = bool(conflict.get('operation_conflicts'))
                
                logger.info(f"    Convergent deadlock validation: tables={has_table_conflicts}, ops={has_operation_conflicts}")
                return has_table_conflicts and has_operation_conflicts
        
        # XOR_SPLIT is excluded - should never reach here
        elif gateway_type == 'XOR_SPLIT':
            logger.warning(f"XOR_SPLIT detected in validation - this should be excluded. Returning False.")
            return False
        
        return False

    def _get_conflict_description(self, gateway_type: str, execution_type: str) -> str:
        """Enhanced descriptions including convergent JOIN conflicts"""
        descriptions = {
            'AND_SPLIT': {
                'PARALLEL': 'Guaranteed parallel execution deadlock risk'
            },
            'OR_SPLIT': {
                'CONDITIONAL_PARALLEL': 'Conditional parallel execution deadlock risk'
            },
            'CONVERGENT_AND_JOIN': {
                'CONVERGENT_PARALLEL': 'Convergent paths deadlock at AND_JOIN - both paths must complete'
            },
            'CONVERGENT_OR_JOIN': {
                'CONVERGENT_PARALLEL': 'Convergent paths deadlock at OR_JOIN - paths may execute conditionally'
            }
        }
        
        return descriptions.get(gateway_type, {}).get(execution_type, 'Unknown conflict pattern')

    def _generate_gateway_specific_recommendation(self, conflict: Dict, ops1: Set[str], ops2: Set[str], 
                                                gateway_type: str, execution_type: str) -> str:
        """Enhanced recommendations including convergent JOIN deadlocks"""
        recommendations = []
        
        # Table-specific recommendations
        shared_tables = conflict.get('table_conflicts', set())
        if shared_tables:
            sorted_tables = sorted(list(shared_tables))
            recommendations.append(f"Critical: Implement consistent table access order: {' -> '.join(sorted_tables)}")
        
        # Gateway-specific recommendations
        if gateway_type == 'AND_SPLIT':
            recommendations.append("AND-split: Use explicit BEGIN TRANSACTION with consistent table ordering")
            recommendations.append("Implement table-level locking with HOLDLOCK/XLOCK hints")
            recommendations.append("Consider using SERIALIZABLE isolation level for critical sections")
            
        elif gateway_type == 'OR_SPLIT':
            recommendations.append("OR-split: Use conditional locking based on runtime decision logic")
            recommendations.append("Implement path-specific resource reservation patterns")
            recommendations.append("Use application-level coordination mechanisms")
        
        # NEW: Convergent JOIN recommendations
        elif gateway_type.startswith('CONVERGENT_'):
            if 'AND_JOIN' in gateway_type:
                recommendations.append("Convergent AND_JOIN: All paths must complete - implement resource ordering")
                recommendations.append("Use distributed locking or semaphores to coordinate convergent access")
                recommendations.append("Consider path-specific timeouts with rollback mechanisms")
            elif 'OR_JOIN' in gateway_type:
                recommendations.append("Convergent OR_JOIN: Implement conditional resource locking")
                recommendations.append("Use path prioritization to reduce convergent conflicts")
                recommendations.append("Implement resource reservation patterns for high-priority paths")
        
        # Operation-specific recommendations
        operation_conflicts = conflict.get('operation_conflicts', [])
        for op_conflict in operation_conflicts:
            if 'WRITE-WRITE' in op_conflict[0]:
                recommendations.append(f"Write-Write conflict: Use MERGE or UPSERT patterns")
            elif 'WRITE-READ' in op_conflict[0]:
                recommendations.append(f"Write-Read conflict: Use READ_COMMITTED_SNAPSHOT isolation")
        
        recommendations.append("Implement retry logic with exponential backoff (max 3 attempts)")
        
        return "; ".join(recommendations)

    def _analyze_deadlock_pair(self, node1: str, node2: str, edge_data: Dict) -> Optional[Dict]:
        """Enhanced deadlock pair analysis including convergent JOINs"""
        if node1 not in self.sql_resources or node2 not in self.sql_resources:
            return None
        
        conflict = edge_data.get('conflict', {})
        gateway_type = edge_data.get('gateway_type', 'UNKNOWN')
        scenario = edge_data.get('scenario', 'Unknown')
        execution_type = edge_data.get('execution_type', 'UNKNOWN')
        analysis_type = edge_data.get('analysis_type', 'UNKNOWN')
        gateway_id = edge_data.get('gateway_id', 'Unknown')
        
        # Exclude XOR_SPLIT but allow convergent deadlocks
        if gateway_type == 'XOR_SPLIT':
            logger.info(f"Excluding XOR_SPLIT deadlock - not realistic for SQL deadlock analysis")
            return None
        
        node1_name = self.sql_resources[node1].get('name', node1)
        node2_name = self.sql_resources[node2].get('name', node2)
        
        # Enhanced validation for realistic deadlocks including convergent
        is_realistic_deadlock = self._validate_realistic_deadlock(conflict, gateway_type, execution_type)
        if not is_realistic_deadlock:
            logger.info(f"Dismissing unrealistic deadlock: {node1_name} ↔ {node2_name} via {gateway_type}")
            return None
        
        # Get SQL details
        node1_sql = self.sql_resources[node1].get('sql', '')
        node2_sql = self.sql_resources[node2].get('sql', '')
        
        # Get operations
        ops1 = self.sql_resources[node1]['resources']['operations']
        ops2 = self.sql_resources[node2]['resources']['operations']
        
        # Calculate severity for this pair
        severity = self._calculate_pair_severity(conflict, ops1, ops2)
        
        # Determine conflict type description
        conflict_description = self._get_conflict_description(gateway_type, execution_type)
        
        # Enhanced likelihood calculation
        likelihood = 'HIGH' if 'AND_' in gateway_type else 'MEDIUM'
        if gateway_type.startswith('CONVERGENT_'):
            likelihood = 'HIGH' if 'AND_JOIN' in gateway_type else 'MEDIUM'
        
        print(f"\n🔍 REALISTIC SQL DEADLOCK DETECTED ({gateway_type}):")
        print(f"   Node 1: {node1_name}")
        print(f"   Node 2: {node2_name}")
        print(f"   Gateway: {gateway_type} ({conflict_description})")
        print(f"   Scenario: {scenario}")
        print(f"   Gateway ID: {gateway_id}")
        print(f"   Analysis Type: {analysis_type}")
        print(f"   Shared Tables: {list(conflict.get('table_conflicts', set()))}")
        print(f"   Column Conflicts: {list(conflict.get('column_conflicts', set()))}")
        print(f"   Operation Conflicts: {conflict.get('operation_conflicts', [])}")
        print(f"   Severity: {severity}")
        print(f"   Likelihood: {likelihood}")
        
        return {
            'type': f'{gateway_type} Realistic SQL Deadlock',
            'node1': {
                'id': node1,
                'name': node1_name,
                'sql': node1_sql,
                'operations': list(ops1)
            },
            'node2': {
                'id': node2,
                'name': node2_name,
                'sql': node2_sql,
                'operations': list(ops2)
            },
            'conflict_details': {
                'shared_tables': list(conflict.get('table_conflicts', set())),
                'columns': list(conflict.get('column_conflicts', set())),
                'operation_types': conflict.get('operation_conflicts', [])
            },
            'gateway_context': {
                'type': gateway_type,
                'scenario': scenario,
                'execution_model': execution_type,
                'analysis_type': analysis_type,
                'gateway_id': gateway_id,
                'risk_description': conflict_description,
                'likelihood': likelihood
            },
            'severity': severity,
            'description': f"Realistic SQL deadlock between {node1_name} and {node2_name} via {gateway_type}",
            'recommendation': self._generate_gateway_specific_recommendation(conflict, ops1, ops2, gateway_type, execution_type)
        }
    
    def _analyze_parallel_conflicts(self, scenario: Dict, paths: List[List[str]], execution_type: str):
        """Analyze conflicts for realistic parallel execution scenarios (enhanced for JOIN support)"""
        gateway_type = scenario['gateway_type']
        analysis_type = scenario['analysis_type']
        
        # Check resource conflicts between all path combinations
        for i, path1 in enumerate(paths):
            for j, path2 in enumerate(paths):
                if i >= j:  # Avoid duplicate comparisons
                    continue
                    
                logger.info(f"  Checking {execution_type} conflicts between path {i+1} and path {j+1} ({analysis_type})")
                
                # Check for resource conflicts between paths
                conflicts = self._check_path_resource_conflicts(path1, path2, gateway_type)
                if conflicts:
                    logger.info(f"    Found conflicts: {len(conflicts['conflicts'])} conflict pairs")
                    
                    # Add edges to wait-for graph for conflicting nodes
                    for conflict in conflicts['conflicts']:
                        node1 = conflict['node1']
                        node2 = conflict['node2']
                        
                        self.wait_for_graph.add_edge(node1, node2, 
                                                   conflict=conflict['conflict'],
                                                   gateway_type=gateway_type,
                                                   analysis_type=analysis_type,
                                                   scenario=scenario['gateway_name'],
                                                   execution_type=execution_type)
                        self.wait_for_graph.add_edge(node2, node1, 
                                                   conflict=conflict['conflict'],
                                                   gateway_type=gateway_type,
                                                   analysis_type=analysis_type,
                                                   scenario=scenario['gateway_name'],
                                                   execution_type=execution_type)
                else:
                    logger.info(f"    No conflicts found between these paths ({analysis_type})")

    def _find_truly_parallel_paths(self, split_node_id: str, split_type: str) -> List[List[str]]:
        """Find paths that are truly executed in parallel (before they join)"""
        paths = []
        
        # Get immediate successors from this split
        successors = []
        for rel in self.graph_data['relationships']:
            if rel['source_id'] == split_node_id:
                successors.append(rel['target_id'])
        
        logger.info(f"Split {split_node_id} has {len(successors)} immediate successors")
        
        # For each successor, trace the path until join
        for successor in successors:
            path = self._trace_path_until_join(successor, split_type)
            if path:  # Only include paths that have SQL nodes before join
                paths.append(path)
                logger.info(f"  Path found with {len(path)} SQL nodes before join: {[self.sql_resources.get(node, {}).get('name', node) for node in path]}")
                
        return paths
    
    def _trace_path_until_join(self, start_node: str, split_type: str, max_depth: int = 20) -> List[str]:
        """Trace execution path until it hits a JOIN gateway"""
        sql_path = []
        current = start_node
        visited = set()
        depth = 0
        
        # Determine corresponding JOIN types
        join_types = {
            'AND_SPLIT': ['AND_JOIN'],
            'OR_SPLIT': ['OR_JOIN', 'AND_JOIN']  # OR_SPLIT can join at either OR_JOIN or AND_JOIN
        }
        corresponding_joins = join_types.get(split_type, [])
        
        while current and current not in visited and depth < max_depth:
            visited.add(current)
            depth += 1
            
            # Add SQL-enabled nodes to path
            if current in self.sql_resources:
                sql_path.append(current)
            
            # Check if we hit a JOIN gateway
            outgoing_rels = [rel for rel in self.graph_data['relationships'] if rel['source_id'] == current]
            
            for rel in outgoing_rels:
                if any(join_type in rel['rel_type'] for join_type in corresponding_joins):
                    # We hit a join - stop tracing this path
                    logger.info(f"    Path stopped at {rel['rel_type']} junction")
                    return sql_path
            
            # Find next node (non-join)
            next_nodes = [rel['target_id'] for rel in outgoing_rels 
                         if not any(join_type in rel['rel_type'] for join_type in corresponding_joins)]
            
            # Continue with first next node (simplified traversal)
            current = next_nodes[0] if next_nodes else None
            
        return sql_path
    
    def _validate_truly_parallel_execution(self, paths: List[List[str]], split_type: str) -> bool:
        """Validate if paths can truly execute in parallel before joining"""
        
        # For AND_SPLIT: Always parallel until AND_JOIN
        if split_type == 'AND_SPLIT':
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        # For OR_SPLIT: Only parallel if multiple conditions can be true simultaneously
        elif split_type == 'OR_SPLIT':
            # OR_SPLIT paths can be parallel if they don't immediately join
            # This is a simplified check - in practice, need to analyze conditions
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        return False
    
    def _check_path_resource_conflicts(self, path1: List[str], path2: List[str], gateway_type: str) -> Dict:
        """Check for resource conflicts between two paths from any gateway type"""
        conflicts = []
        
        # Check each node in path1 against each node in path2
        for node1 in path1:
            for node2 in path2:
                if node1 in self.sql_resources and node2 in self.sql_resources:
                    # NEW: Skip deadlock detection between parent-child nodes (same sequential path)
                    if self._are_in_same_sequential_path(node1, node2):
                        node1_name = self.sql_resources[node1].get('name', node1)
                        node2_name = self.sql_resources[node2].get('name', node2)
                        logger.info(f"    ⚠️  SKIPPING: '{node1_name}' ↔ '{node2_name}' - Same sequential path (parent-child relationship)")
                        continue
                    
                    conflict = self._check_specific_node_conflicts(node1, node2)
                    if conflict:
                        conflicts.append({
                            'node1': node1,
                            'node2': node2,
                            'node1_name': self.sql_resources[node1].get('name', node1),
                            'node2_name': self.sql_resources[node2].get('name', node2),
                            'conflict': conflict
                        })
        
        if conflicts:
            return {
                'gateway_type': gateway_type,
                'conflicts': conflicts,
                'conflict_count': len(conflicts)
            }
        
        return None
    
    def _check_specific_node_conflicts(self, node1: str, node2: str) -> Dict:
        """Check for resource conflicts between two specific nodes with enhanced validation"""
        if node1 not in self.sql_resources or node2 not in self.sql_resources:
            return None
            
        res1 = self.sql_resources[node1]['resources']
        res2 = self.sql_resources[node2]['resources']
        
        node1_name = self.sql_resources[node1].get('name', node1)
        node2_name = self.sql_resources[node2].get('name', node2)
        
        # ENHANCED FILTER 1: Check for mutual exclusion - if conditions are mutually exclusive, no conflict possible
        if self._check_mutual_exclusion(res1, res2):
            logger.info(f"No conflict between '{node1_name}' and '{node2_name}' - mutually exclusive WHERE conditions")
            return None
        
        # ENHANCED FILTER 2: Skip if no shared resources at all
        table_overlap = res1['tables'].intersection(res2['tables'])
        column_overlap = res1['columns'].intersection(res2['columns'])
        
        if not table_overlap and not column_overlap:
            logger.info(f"No conflict between '{node1_name}' and '{node2_name}' - no shared resources")
            return None
        
        # ENHANCED FILTER 3: Check operations - must have conflicting operations
        ops1 = res1['operations']
        ops2 = res2['operations']
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # Only these scenarios create real deadlock potential:
        # 1. Write-Write conflicts (high risk)
        # 2. Write-Read conflicts (medium risk, but only on same tables)
        has_write_write = (ops1.intersection(write_ops) and ops2.intersection(write_ops))
        has_write_read = ((ops1.intersection(write_ops) and 'SELECT' in ops2) or 
                         ('SELECT' in ops1 and ops2.intersection(write_ops)))
        
        if not has_write_write and not has_write_read:
            logger.info(f"No conflict between '{node1_name}' and '{node2_name}' - no conflicting operations")
            return None
        
        # ENHANCED FILTER 4: Write-Read conflicts only valid on same tables (not cross-table)
        if has_write_read and not has_write_write and not table_overlap:
            logger.info(f"No conflict between '{node1_name}' and '{node2_name}' - Write-Read requires same table")
            return None
        
        # Build conflict data
        conflicts = {
            'table_conflicts': table_overlap,
            'column_conflicts': column_overlap,
            'operation_conflicts': []
        }
        
        # Record specific conflict types
        shared_resources = list(table_overlap) if table_overlap else list(column_overlap)
        
        if has_write_write:
            if table_overlap:
                conflicts['operation_conflicts'].append(('WRITE-WRITE', list(table_overlap)))
                logger.info(f"  WRITE-WRITE conflict detected on tables: {list(table_overlap)}")
            elif column_overlap:
                # Cross-table write-write via shared columns (foreign keys)
                all_tables = list(res1['tables'].union(res2['tables']))
                conflicts['operation_conflicts'].append(('WRITE-WRITE-CROSS-TABLE', all_tables))
                conflicts['table_conflicts'] = res1['tables'].union(res2['tables'])  # Update to include all tables
                logger.info(f"  WRITE-WRITE cross-table conflict via columns: {list(column_overlap)}")
        
        if has_write_read and table_overlap:  # Only same-table write-read conflicts
            conflicts['operation_conflicts'].append(('WRITE-READ', list(table_overlap)))
            logger.info(f"  WRITE-READ conflict detected on tables: {list(table_overlap)}")
        
        # ENHANCED FILTER 5: Must have operation conflicts to be valid
        if not conflicts['operation_conflicts']:
            logger.info(f"No conflict between '{node1_name}' and '{node2_name}' - no valid operation conflicts")
            return None
        
        logger.info(f"  ✅ VALIDATED CONFLICT between '{node1_name}' and '{node2_name}'")
        
        # Save conflict to JSON tracking with enhanced data
        conflict_data = {
            'timestamp': datetime.now().isoformat(),
            'node1': {
                'id': node1,
                'name': node1_name,
                'tables': list(res1['tables']),
                'columns': list(res1['columns']),
                'operations': list(res1['operations'])
            },
            'node2': {
                'id': node2,
                'name': node2_name,
                'tables': list(res2['tables']),
                'columns': list(res2['columns']),
                'operations': list(res2['operations'])
            },
            'conflict_details': {
                'shared_tables': list(table_overlap) if table_overlap else [],
                'shared_columns': list(column_overlap) if column_overlap else [],
                'all_involved_tables': list(conflicts['table_conflicts']),
                'operation_conflicts': conflicts['operation_conflicts'],
                'conflict_type': 'SAME-TABLE' if table_overlap else 'CROSS-TABLE',
                'shared_resources': shared_resources,
                'risk_level': 'HIGH' if has_write_write else 'MEDIUM'
            }
        }
        
        self.detected_conflicts.append(conflict_data)
        self._save_conflicts_to_json()
        
        return conflicts
    
    def _save_conflicts_to_json(self):
        """Save detected conflicts to JSON file"""
        try:
            output_data = {
                'analysis_info': {
                    'timestamp': datetime.now().isoformat(),
                    'total_conflicts_detected': len(self.detected_conflicts),
                    'analyzer_version': '1.0'
                },
                'conflicts': self.detected_conflicts
            }
            
            with open(self.conflict_output_file, 'w') as f:
                json.dump(output_data, f, indent=2, ensure_ascii=False)
            
            logger.info(f"💾 Saved {len(self.detected_conflicts)} conflicts to {self.conflict_output_file}")
            
        except Exception as e:
            logger.error(f"Error saving conflicts to JSON: {e}")
    
    def run_conflict_detection_only(self):
        """Run only conflict detection with PROPER filtering - fixed version"""
        logger.info("🔍 Running ENHANCED conflict detection with proper filtering...")
        
        # Clear previous conflicts
        self.detected_conflicts = []
        
        # Step 1: Build resource dependency graph
        self.build_resource_dependency_graph()
        logger.info(f"Found {len(self.sql_resources)} SQL-enabled nodes")
        
        if len(self.sql_resources) < 2:
            logger.info("Not enough SQL nodes for conflict analysis")
            return {'total_sql_nodes': len(self.sql_resources), 'conflicts_found': 0, 'output_file': self.conflict_output_file}
        
        # Step 2: Identify ONLY truly parallel scenarios (this is the key filter)
        parallel_scenarios = self.identify_all_parallel_paths()
        logger.info(f"Found {len(parallel_scenarios)} truly parallel scenarios")
        
        if not parallel_scenarios:
            logger.info("No truly parallel scenarios found - no realistic deadlock potential")
            return {'total_sql_nodes': len(self.sql_resources), 'conflicts_found': 0, 'output_file': self.conflict_output_file}
        
        # Step 3: Only check conflicts within validated parallel scenarios
        conflict_count = 0
        analyzed_pairs = set()
        
        for scenario in parallel_scenarios:
            gateway_type = scenario['gateway_type']
            paths = scenario['paths']
            scenario_name = scenario['gateway_name']
            
            # FILTER 1: Skip XOR scenarios entirely
            if 'XOR' in gateway_type:
                logger.info(f"SKIPPING XOR scenario: {scenario_name} - not truly parallel")
                continue
            
            # FILTER 2: Only analyze conflicts between different paths in the same scenario
            for i, path1 in enumerate(paths):
                for j, path2 in enumerate(paths):
                    if i >= j:  # Avoid duplicate analysis
                        continue
                    
                    logger.info(f"Analyzing {gateway_type} scenario: {scenario_name} - Path {i+1} vs Path {j+1}")
                    
                    # Check each node in path1 vs each node in path2
                    for node1 in path1:
                        for node2 in path2:
                            if node1 == node2:
                                continue
                            
                            # Create sorted pair to avoid duplicates
                            pair = tuple(sorted([node1, node2]))
                            if pair in analyzed_pairs:
                                continue
                            analyzed_pairs.add(pair)
                            
                            # FILTER 3: Both nodes must have SQL
                            if node1 not in self.sql_resources or node2 not in self.sql_resources:
                                continue
                            
                            # FILTER 4: Skip if in same sequential path
                            if self._are_in_same_sequential_path(node1, node2):
                                node1_name = self.sql_resources[node1].get('name', node1)
                                node2_name = self.sql_resources[node2].get('name', node2)
                                logger.info(f"  SKIPPING sequential: {node1_name} ↔ {node2_name}")
                                continue
                            
                            # FILTER 5: Check for actual SQL conflicts with ALL validation
                            conflict = self._check_specific_node_conflicts_enhanced(node1, node2, gateway_type)
                            if conflict:
                                conflict_count += 1
                                node1_name = self.sql_resources[node1].get('name', node1)
                                node2_name = self.sql_resources[node2].get('name', node2)
                                logger.info(f"  ✅ VALID CONFLICT #{conflict_count}: {node1_name} ↔ {node2_name} in {gateway_type}")
        
        logger.info(f"✅ Enhanced conflict detection completed! Found {conflict_count} VALIDATED conflicts")
        logger.info(f"📄 Results saved to: {self.conflict_output_file}")
        
        return {
            'total_sql_nodes': len(self.sql_resources),
            'conflicts_found': conflict_count,
            'output_file': self.conflict_output_file,
            'parallel_scenarios_analyzed': len(parallel_scenarios)
        }
    
    def _check_specific_node_conflicts_enhanced(self, node1: str, node2: str, gateway_type: str) -> Dict:
        """Enhanced conflict checking with ALL filters applied properly"""
        if node1 not in self.sql_resources or node2 not in self.sql_resources:
            return None
            
        res1 = self.sql_resources[node1]['resources']
        res2 = self.sql_resources[node2]['resources']
        
        node1_name = self.sql_resources[node1].get('name', node1)
        node2_name = self.sql_resources[node2].get('name', node2)
        
        # ENHANCED FILTER 1: Check for mutual exclusion - if conditions are mutually exclusive, no conflict possible
        if self._check_mutual_exclusion(res1, res2):
            logger.info(f"  ❌ FILTERED: {node1_name} ↔ {node2_name} - mutually exclusive WHERE conditions")
            return None
        
        # ENHANCED FILTER 2: Skip if no shared resources at all
        table_overlap = res1['tables'].intersection(res2['tables'])
        column_overlap = res1['columns'].intersection(res2['columns'])
        
        if not table_overlap and not column_overlap:
            logger.info(f"  ❌ FILTERED: {node1_name} ↔ {node2_name} - no shared resources")
            return None
        
        # ENHANCED FILTER 3: Check operations - must have conflicting operations
        ops1 = res1['operations']
        ops2 = res2['operations']
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        # Only these scenarios create real deadlock potential:
        has_write_write = (ops1.intersection(write_ops) and ops2.intersection(write_ops))
        has_write_read = ((ops1.intersection(write_ops) and 'SELECT' in ops2) or 
                         ('SELECT' in ops1 and ops2.intersection(write_ops)))
        
        if not has_write_write and not has_write_read:
            logger.info(f"  ❌ FILTERED: {node1_name} ↔ {node2_name} - no conflicting operations")
            return None
        
        # ENHANCED FILTER 4: Write-Read conflicts only valid on same tables
        if has_write_read and not has_write_write and not table_overlap:
            logger.info(f"  ❌ FILTERED: {node1_name} ↔ {node2_name} - Write-Read requires same table")
            return None
        
        # ENHANCED FILTER 5: Gateway-specific validation
        if not self._validate_gateway_specific_conflict(gateway_type, ops1, ops2, table_overlap, column_overlap):
            logger.info(f"  ❌ FILTERED: {node1_name} ↔ {node2_name} - gateway-specific validation failed")
            return None
        
        # Build conflict data - ONLY if all filters passed
        conflicts = {
            'table_conflicts': table_overlap,
            'column_conflicts': column_overlap,
            'operation_conflicts': []
        }
        
        # Record specific conflict types
        shared_resources = list(table_overlap) if table_overlap else list(column_overlap)
        
        if has_write_write:
            if table_overlap:
                conflicts['operation_conflicts'].append(('WRITE-WRITE', list(table_overlap)))
            elif column_overlap:
                all_tables = list(res1['tables'].union(res2['tables']))
                conflicts['operation_conflicts'].append(('WRITE-WRITE-CROSS-TABLE', all_tables))
                conflicts['table_conflicts'] = res1['tables'].union(res2['tables'])
        
        if has_write_read and table_overlap:
            conflicts['operation_conflicts'].append(('WRITE-READ', list(table_overlap)))
        
        # FINAL FILTER: Must have operation conflicts
        if not conflicts['operation_conflicts']:
            logger.info(f"  ❌ FILTERED: {node1_name} ↔ {node2_name} - no valid operation conflicts")
            return None
        
        logger.info(f"  ✅ CONFLICT VALIDATED: {node1_name} ↔ {node2_name}")
        
        # Save conflict to JSON tracking
        conflict_data = {
            'timestamp': datetime.now().isoformat(),
            'node1': {
                'id': node1,
                'name': node1_name,
                'tables': list(res1['tables']),
                'columns': list(res1['columns']),
                'operations': list(res1['operations'])
            },
            'node2': {
                'id': node2,
                'name': node2_name,
                'tables': list(res2['tables']),
                'columns': list(res2['columns']),
                'operations': list(res2['operations'])
            },
            'conflict_details': {
                'shared_tables': list(table_overlap) if table_overlap else [],
                'shared_columns': list(column_overlap) if column_overlap else [],
                'all_involved_tables': list(conflicts['table_conflicts']),
                'operation_conflicts': conflicts['operation_conflicts'],
                'conflict_type': 'SAME-TABLE' if table_overlap else 'CROSS-TABLE',
                'shared_resources': shared_resources,
                'gateway_type': gateway_type,
                'validation_passed': True
            }
        }
        
        self.detected_conflicts.append(conflict_data)
        self._save_conflicts_to_json()
        
        return conflicts
    
    def _validate_gateway_specific_conflict(self, gateway_type: str, ops1: Set[str], ops2: Set[str], 
                                          table_overlap: Set[str], column_overlap: Set[str]) -> bool:
        """Gateway-specific conflict validation"""
        
        # AND_SPLIT/AND_JOIN: Always parallel - any resource conflict is valid
        if 'AND_' in gateway_type:
            return bool(table_overlap or column_overlap)
        
        # OR_SPLIT/OR_JOIN: Conditional parallel - need stronger conflict evidence
        elif 'OR_' in gateway_type:
            # For OR gateways, require either:
            # 1. Same table conflicts (high confidence)
            # 2. Write-Write conflicts (even across tables)
            write_ops = {'UPDATE', 'INSERT', 'DELETE'}
            has_write_write = (ops1.intersection(write_ops) and ops2.intersection(write_ops))
            
            return bool(table_overlap) or has_write_write
        
        # XOR: Should never reach here (filtered out earlier)
        elif 'XOR' in gateway_type:
            return False
        
        return True
    
    def identify_all_parallel_paths(self) -> List[Dict]:
        """Enhanced parallel path identification with better filtering"""
        parallel_scenarios = []
        
        # Focus on gateways that can cause real deadlocks
        realistic_gateways = {
            'split': ['AND_SPLIT', 'OR_SPLIT'],  # XOR_SPLIT removed
            'join': ['AND_JOIN', 'OR_JOIN']      # XOR_JOIN removed
        }
        
        # Method 1: Analyze from SPLIT gateways
        for split_type in realistic_gateways['split']:
            split_gateways = self._find_gateways_by_type(split_type)
            
            for gateway_info in split_gateways:
                source_id = gateway_info['source_id']
                gateway_props = gateway_info.get('properties', {})
                
                # Find paths from this split
                parallel_paths = self._find_truly_parallel_paths(source_id, split_type)
                
                # FILTER: Only include if we have multiple paths with SQL nodes
                sql_path_count = sum(1 for path in parallel_paths if len(path) > 0)
                if sql_path_count > 1:
                    scenario = {
                        'analysis_type': 'SPLIT_FORWARD',
                        'gateway_node_id': source_id,
                        'gateway_type': split_type,
                        'gateway_name': self.graph_data['nodes'][source_id]['properties'].get('name', f'Split_{source_id}'),
                        'gateway_id': gateway_props.get('gateway_id', 'Unknown'),
                        'paths': parallel_paths,
                        'path_count': len(parallel_paths),
                        'sql_path_count': sql_path_count,
                        'is_truly_parallel': True
                    }
                    
                    parallel_scenarios.append(scenario)
                    logger.info(f"✅ Found VALID {split_type} with {sql_path_count} SQL paths")
                else:
                    logger.info(f"❌ Filtered {split_type} - insufficient SQL paths ({sql_path_count})")
        
        return parallel_scenarios
    
    def _find_gateways_by_type(self, gateway_type: str) -> List[Dict]:
        """Find all gateways of a specific type"""
        gateways = []
        
        for rel in self.graph_data['relationships']:
            if gateway_type in rel['rel_type']:
                gateways.append({
                    'source_id': rel['source_id'],
                    'target_id': rel['target_id'],
                    'rel_type': rel['rel_type'],
                    'properties': rel.get('properties', {})
                })
        
        return gateways

    def _calculate_pair_severity(self, conflict: Dict, ops1: Set[str], ops2: Set[str]) -> str:
        """Calculate severity for a specific deadlock pair"""
        score = 0
        
        # Factor 1: Table conflicts (most critical)
        if conflict.get('table_conflicts'):
            score += 30
        
        # Factor 2: Column conflicts
        if conflict.get('column_conflicts'):
            score += 15
        
        # Factor 3: Operation conflicts
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        if ops1.intersection(write_ops) and ops2.intersection(write_ops):
            score += 25  # Write-Write conflict
        elif (ops1.intersection(write_ops) and 'SELECT' in ops2) or ('SELECT' in ops1 and ops2.intersection(write_ops)):
            score += 15  # Read-Write conflict
        
        # Factor 4: Multiple conflicts
        conflict_count = len(conflict.get('operation_conflicts', []))
        score += conflict_count * 5
        
        if score >= 50:
            return 'CRITICAL'
        elif score >= 30:
            return 'HIGH'
        elif score >= 15:
            return 'MEDIUM'
        else:
            return 'LOW'

    def detect_sql_deadlock_pairs(self) -> List[Dict]:
        """FIXED: Detect SQL conflicts ONLY in validated parallel scenarios"""
        logger.info("Starting ENHANCED SQL conflict detection with proper filtering...")
        
        conflict_pairs = []
        
        # Step 1: Build resource dependency graph
        self.build_resource_dependency_graph()
        logger.info(f"Found {len(self.sql_resources)} SQL-enabled nodes")
        
        # Step 2: Identify ONLY truly parallel scenarios
        parallel_scenarios = self.identify_all_parallel_paths()
        logger.info(f"Found {len(parallel_scenarios)} truly parallel scenarios")
        
        if not parallel_scenarios:
            logger.info("No truly parallel scenarios found - no realistic deadlock potential")
            return []
        
        # Step 3: ONLY analyze conflicts within validated parallel scenarios
        analyzed_pairs = set()
        
        for scenario in parallel_scenarios:
            gateway_type = scenario['gateway_type']
            paths = scenario['paths']
            scenario_name = scenario['gateway_name']
            
            # CRITICAL FILTER: Skip XOR scenarios entirely
            if 'XOR' in gateway_type:
                logger.info(f"SKIPPING XOR scenario: {scenario_name} - not truly parallel")
                continue
            
            logger.info(f"Analyzing {gateway_type} scenario: {scenario_name}")
            
            # Only analyze conflicts between different paths in the same scenario
            for i, path1 in enumerate(paths):
                for j, path2 in enumerate(paths):
                    if i >= j:  # Avoid duplicate analysis
                        continue
                    
                    # Check each node in path1 vs each node in path2
                    for node1 in path1:
                        for node2 in path2:
                            if node1 == node2:
                                continue
                            
                            # Create sorted pair to avoid duplicates
                            pair = tuple(sorted([node1, node2]))
                            if pair in analyzed_pairs:
                                continue
                            analyzed_pairs.add(pair)
                            
                            # Both nodes must have SQL
                            if node1 not in self.sql_resources or node2 not in self.sql_resources:
                                continue
                            
                            # Skip if in same sequential path
                            if self._are_in_same_sequential_path(node1, node2):
                                continue
                            
                            # Check for actual SQL conflicts with ALL validation
                            conflict = self._check_specific_node_conflicts_enhanced(node1, node2, gateway_type)
                            if conflict:
                                # Create edge data for analysis
                                edge_data = {
                                    'conflict': conflict,
                                    'gateway_type': gateway_type,
                                    'scenario': scenario_name,
                                    'execution_type': 'PARALLEL' if 'AND_' in gateway_type else 'CONDITIONAL_PARALLEL',
                                    'analysis_type': scenario.get('analysis_type', 'UNKNOWN'),
                                    'gateway_id': scenario.get('gateway_id', 'Unknown')
                                }
                                
                                # Analyze the deadlock pair
                                conflict_pair = self._analyze_deadlock_pair(node1, node2, edge_data)
                                if conflict_pair:
                                    conflict_pairs.append(conflict_pair)
        
        logger.info(f"Found {len(conflict_pairs)} VALIDATED SQL conflict pairs")
        return conflict_pairs
    
    def detect_deadlocks(self) -> List[Dict]:
        """Main deadlock detection method - now uses enhanced filtering"""
        return self.detect_sql_deadlock_pairs()

    def _get_severity_breakdown(self, deadlock_pairs: List[Dict]) -> Dict:
        """Get breakdown of deadlock pairs by severity"""
        breakdown = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for pair in deadlock_pairs:
            severity = pair.get('severity', 'LOW')
            breakdown[severity] += 1
        return breakdown

    def generate_report(self) -> Dict:
        """Generate focused SQL deadlock detection report - with enhanced filtering"""
        deadlock_pairs = self.detect_deadlocks()
        
        # Extract statistics
        deadlocked_nodes = set()
        gateway_types_summary = set()
        tables_involved = set()
        analysis_types_summary = set()
        
        for pair in deadlock_pairs:
            deadlocked_nodes.add(pair['node1']['id'])
            deadlocked_nodes.add(pair['node2']['id'])
            gateway_types_summary.add(pair['gateway_context']['type'])
            tables_involved.update(pair['conflict_details']['shared_tables'])
            if 'analysis_type' in pair['gateway_context']:
                analysis_types_summary.add(pair['gateway_context']['analysis_type'])
        
        return {
            'summary': {
                'total_nodes_analyzed': len(self.graph_data['nodes']) if self.graph_data else 0,
                'deadlocked_nodes': len(deadlocked_nodes),
                'total_sql_nodes': len(self.sql_resources),
                'deadlock_pairs_found': len(deadlock_pairs),
                'tables_involved': list(tables_involved),
                'gateway_types_involved': list(gateway_types_summary),
                'analysis_types_used': list(analysis_types_summary),
                'severity_breakdown': self._get_severity_breakdown(deadlock_pairs)
            },
            'deadlock_pairs': deadlock_pairs,
            'graph_statistics': {
                'total_nodes': len(self.graph_data['nodes']) if self.graph_data else 0,
                'total_relationships': len(self.graph_data['relationships']) if self.graph_data else 0,
                'wait_for_graph_nodes': 0,  # Not used in enhanced version
                'wait_for_graph_edges': 0   # Not used in enhanced version
            },
            'analysis_methods': {
                'focus_strategy': 'ENHANCED deadlock detection - only validated parallel scenarios',
                'conflict_analysis': 'Multi-layer filtering: parallel scenarios -> gateway validation -> SQL conflicts',
                'gateway_coverage': 'AND_SPLIT/JOIN (parallel), OR_SPLIT/JOIN (conditional) - XOR excluded',
                'exclusions': 'XOR gateways, sequential paths, non-conflicting operations, mutually exclusive conditions',
                'validation_layers': '5-layer filtering: parallel validation, XOR exclusion, sequential path detection, resource conflict validation, operation conflict validation'
            }
        }

    def load_from_json_file(self, json_file_path: str):
        """Load graph data directly from JSON file instead of Neo4j - Enhanced for JOIN analysis"""
        import json
        import os
        
        try:
            if not os.path.exists(json_file_path):
                logger.error(f"JSON file not found: {json_file_path}")
                return None
                
            with open(json_file_path, 'r') as f:
                data = json.load(f)
            
            # Convert JSON format to expected format with better handling
            nodes = {}
            for node in data.get('nodes', []):
                if node.get('id'):  # Skip nodes with null id
                    nodes[node['id']] = {
                        'labels': node.get('labels', []),
                        'properties': node.get('properties', {})
                    }
            
            relationships = []
            for rel in data.get('relationships', []):
                if rel.get('source_id') and rel.get('target_id'):  # Skip relationships with null source/target
                    # Enhanced relationship type mapping for better JOIN detection
                    rel_type = rel.get('relationship', '')
                    relationships.append({
                        'source_id': rel['source_id'],
                        'target_id': rel['target_id'],
                        'rel_type': rel_type,
                        'properties': rel.get('properties', {})
                    })
            
            self.graph_data = {
                'nodes': nodes,
                'relationships': relationships
            }
            
            logger.info(f"Loaded graph data from JSON: {len(nodes)} nodes, {len(relationships)} relationships")
            
            # Analyze JOIN gateways specifically
            self._analyze_join_gateways_from_json()
            
            return self.graph_data
            
        except Exception as e:
            logger.error(f"Error loading JSON file: {e}")
            import traceback
            traceback.print_exc()
            return None

    def _analyze_join_gateways_from_json(self):
        """Analyze JOIN gateways specifically from the loaded JSON data"""
        join_gateways = []
        
        # Find all JOIN relationships
        for rel in self.graph_data['relationships']:
            rel_type = rel['rel_type']
            if 'JOIN' in rel_type:
                join_gateways.append({
                    'target_id': rel['target_id'],
                    'source_id': rel['source_id'],
                    'type': rel_type,
                    'properties': rel.get('properties', {})
                })
        
        logger.info(f"Found {len(join_gateways)} JOIN gateways in JSON:")
        for gateway in join_gateways:
            gateway_id = gateway['properties'].get('gateway_id', 'Unknown')
            logger.info(f"  - {gateway['type']} at {gateway['target_id']} (Gateway ID: {gateway_id})")
        
        return join_gateways

    def _is_parent_child_relationship(self, node1: str, node2: str, max_depth: int = 10) -> bool:
        """Check if node1 and node2 have a parent-child relationship (direct or indirect)"""
        # Check if node1 is ancestor of node2
        if self._is_ancestor_of(node1, node2, max_depth):
            return True
        # Check if node2 is ancestor of node1  
        if self._is_ancestor_of(node2, node1, max_depth):
            return True
        return False

    def _is_ancestor_of(self, potential_ancestor: str, node: str, max_depth: int = 10) -> bool:
        """Check if potential_ancestor is an ancestor of node by tracing relationships"""
        visited = set()
        current = node
        depth = 0
        
        while current and current not in visited and depth < max_depth:
            visited.add(current)
            depth += 1
            
            # Find immediate predecessors
            predecessors = []
            for rel in self.graph_data['relationships']:
                if rel['target_id'] == current:
                    predecessors.append(rel['source_id'])
            
            # Check if potential_ancestor is among predecessors
            if potential_ancestor in predecessors:
                return True
            
            # Continue tracing from first predecessor
            current = predecessors[0] if predecessors else None
            
        return False

    def _are_in_same_sequential_path(self, node1: str, node2: str) -> bool:
        """Enhanced check if two nodes are in the same sequential execution path"""
        # If they have parent-child relationship, they're in same path
        if self._is_parent_child_relationship(node1, node2):
            logger.debug(f"  {node1} and {node2} have parent-child relationship - sequential")
            return True
        
        # Check if they share a common immediate parent (siblings)
        node1_parents = set()
        node2_parents = set()
        
        for rel in self.graph_data['relationships']:
            if rel['target_id'] == node1:
                node1_parents.add(rel['source_id'])
            if rel['target_id'] == node2:
                node2_parents.add(rel['source_id'])
        
        # If they share immediate parent and are not from parallel split, they're sequential
        common_parents = node1_parents.intersection(node2_parents)
        if common_parents:
            # Check if common parent is a sequential split (non-parallel)
            for parent in common_parents:
                for rel in self.graph_data['relationships']:
                    if rel['source_id'] == parent and any(split_type in rel['rel_type'] for split_type in ['XOR_SPLIT']):
                        logger.debug(f"  {node1} and {node2} share XOR_SPLIT parent - sequential")
                        return True  # XOR_SPLIT means only one path executes
        
        return False

    def read_saved_conflicts(self):
        """Read and display previously saved conflicts from JSON file"""
        try:
            if not os.path.exists(self.conflict_output_file):
                logger.info(f"No conflict file found at {self.conflict_output_file}")
                return None
            
            with open(self.conflict_output_file, 'r') as f:
                data = json.load(f)
            
            conflicts = data.get('conflicts', [])
            analysis_info = data.get('analysis_info', {})
            
            print(f"\n📖 READING SAVED CONFLICTS FROM: {self.conflict_output_file}")
            print("="*60)
            print(f"Analysis Date: {analysis_info.get('timestamp', 'Unknown')}")
            print(f"Total Conflicts: {analysis_info.get('total_conflicts_detected', len(conflicts))}")
            print(f"Analyzer Version: {analysis_info.get('analyzer_version', 'Unknown')}")
            print("="*60)
            
            if conflicts:
                for i, conflict in enumerate(conflicts, 1):
                    print(f"\n🔴 CONFLICT #{i}:")
                    print(f"   Timestamp: {conflict.get('timestamp', 'Unknown')}")
                    print(f"   Resources: {conflict.get('shared_resources', [])}")
                    print(f"   Conflict Type: {conflict.get('conflict_type', 'Unknown')}")
                    
                    # Display node details
                    node1 = conflict.get('node1', {})
                    node2 = conflict.get('node2', {})
                    
                    if node1:
                        print(f"   📍 Node 1: {node1.get('name', 'Unknown')}")
                        print(f"      • ID: {node1.get('id', 'Unknown')}")
                        print(f"      • Tables: {node1.get('tables', [])}")
                        print(f"      • Operations: {node1.get('operations', [])}")
                    
                    if node2:
                        print(f"   📍 Node 2: {node2.get('name', 'Unknown')}")
                        print(f"      • ID: {node2.get('id', 'Unknown')}")
                        print(f"      • Tables: {node2.get('tables', [])}")
                        print(f"      • Operations: {node2.get('operations', [])}")
                        
                    if conflict.get('conflict_details'):
                        print(f"   💥 Details: {conflict['conflict_details']}")
            else:
                print("✅ No conflicts found in saved data")
            
            return data
            
        except Exception as e:
            logger.error(f"Error reading saved conflicts: {e}")
            return None

def main():
    """Enhanced main function with better conflict detection flow"""
    print("=== STARTING ENHANCED SQL DEADLOCK DETECTOR ===")
    
    # Check for different modes
    import sys
    conflict_only_mode = '--conflict-only' in sys.argv or '-c' in sys.argv
    read_conflicts_mode = '--read-conflicts' in sys.argv or '-r' in sys.argv
    help_mode = '--help' in sys.argv or '-h' in sys.argv
    
    if help_mode:
        print("=== SQL DEADLOCK DETECTOR - USAGE ===")
        print("python backup_sql.py [OPTIONS]")
        print("\nOPTIONS:")
        print("  --conflict-only, -c    Run enhanced conflict detection (faster, saves to JSON)")
        print("  --read-conflicts, -r   Read and display previously saved conflicts")
        print("  --help, -h            Show this help message")
        print("\nEXAMPLES:")
        print("  python backup_sql.py                    # Full deadlock analysis")
        print("  python backup_sql.py --conflict-only    # Enhanced conflict detection")
        print("  python backup_sql.py --read-conflicts   # View saved conflicts")
        return
    
    if conflict_only_mode:
        print("🔍 RUNNING IN ENHANCED CONFLICT-ONLY MODE")
        print("   Using improved filtering and validation")
    elif read_conflicts_mode:
        print("📖 RUNNING IN READ-CONFLICTS MODE")
        print("   Reading previously saved conflicts from JSON file")
    
    try:
        print("Step 1: Starting program...")
        
        # Initialize detector with better error handling
        try:
            import os
            print("Step 2: Importing modules...")
            
            parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            sys.path.append(parent_dir)
            print(f"Step 3: Added parent directory to path: {parent_dir}")
            
            print("Step 4: Loading config...")
            try:
                from config_deadlock import NEO4J_CONFIG
                NEO4J_URI = NEO4J_CONFIG['uri']
                NEO4J_USER = NEO4J_CONFIG['user']
                NEO4J_PASSWORD = NEO4J_CONFIG['password']
                NEO4J_DATABASE = NEO4J_CONFIG.get('database', 'neo4j')
                print(f"Config loaded successfully. URI: {NEO4J_URI}, Database: {NEO4J_DATABASE}")
            except ImportError as e:
                print(f"Warning: Could not load config file: {e}")
                print("Using default configuration...")
                NEO4J_URI = "bolt://localhost:7687"
                NEO4J_USER = "neo4j"
                NEO4J_PASSWORD = "12345678"
                NEO4J_DATABASE = "neo4j"
                print(f"Default config - URI: {NEO4J_URI}, Database: {NEO4J_DATABASE}")
            except Exception as e:
                print(f"Error in config loading: {e}")
                import traceback
                traceback.print_exc()
                return
        
        except Exception as e:
            print(f"Error in initialization phase: {e}")
            import traceback
            traceback.print_exc()
            return
        
        print("Step 5: Initializing SQLDeadlockDetector...")
        try:
            detector = SQLDeadlockDetector(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE)
            print("✅ Detector initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize detector: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Handle read-conflicts mode early (doesn't need Neo4j connection)
        if read_conflicts_mode:
            print("Step 6: Reading saved conflicts...")
            try:
                saved_data = detector.read_saved_conflicts()
                if saved_data:
                    print("✅ Successfully read saved conflicts")
                else:
                    print("⚠️  No saved conflicts found or error reading file")
                return
            except Exception as e:
                print(f"❌ Error reading saved conflicts: {e}")
                import traceback
                traceback.print_exc()
                return
        
        # Test Neo4j connection
        print("Step 6: Testing Neo4j connection...")
        try:
            # Test connection with a simple query
            with detector.driver.session(database=NEO4J_DATABASE) as session:
                result = session.run("RETURN 1 as test")
                test_result = result.single()
                if test_result and test_result['test'] == 1:
                    print("✅ Neo4j connection successful")
                else:
                    print("❌ Neo4j connection test failed")
                    return
        except Exception as e:
            print(f"❌ Neo4j connection failed: {e}")
            print("Please check:")
            print("1. Neo4j is running")
            print("2. URI, username, and password are correct")
            print("3. Database exists")
            import traceback
            traceback.print_exc()
            return
        
        # Fetch data from Neo4j
        print(f"Step 7: Fetching data from Neo4j database: {NEO4J_DATABASE}")
        try:
            graph_data = detector.fetch_graph_data()
            if graph_data:
                print(f"✅ Successfully fetched data from Neo4j")
                print(f"   Nodes count: {len(graph_data.get('nodes', {}))}")
                print(f"   Relationships count: {len(graph_data.get('relationships', []))}")
                
                if len(graph_data.get('nodes', {})) == 0:
                    print("⚠️  Warning: No nodes found in the database")
                    print("   Make sure your BPMN data has been imported into Neo4j")
                    return
                    
            else:
                print("❌ No data retrieved from Neo4j")
                return
        except Exception as e:
            print(f"❌ Error fetching graph data: {e}")
            import traceback
            traceback.print_exc()
            return
        
        # Execute based on mode
        if conflict_only_mode:
            print("Step 8: Running ENHANCED conflict-only detection...")
            try:
                result = detector.run_conflict_detection_only()
                conflicts_found = result['conflicts_found']
                scenarios_analyzed = result.get('parallel_scenarios_analyzed', 0)
                
                print(f"✅ Enhanced conflict detection completed")
                print(f"   Parallel scenarios found: {scenarios_analyzed}")
                print(f"   Conflicts found: {conflicts_found}")
                
                if conflicts_found > 0:
                    print(f"📄 Conflict details saved to: {result['output_file']}")
                    print("🔍 You can examine the JSON file for detailed conflict information")
                else:
                    print("✅ No conflicts detected between SQL operations")
                
                print("\n" + "="*60)
                print("    ENHANCED CONFLICT-ONLY MODE RESULTS")
                print("="*60)
                print(f"Total SQL nodes analyzed: {result['total_sql_nodes']}")
                print(f"Parallel scenarios analyzed: {scenarios_analyzed}")
                print(f"Total conflicts detected: {conflicts_found}")
                print(f"Output file: {result['output_file']}")
                print("="*60)
                return
                
            except Exception as e:
                print(f"❌ Error in enhanced conflict detection: {e}")
                import traceback
                traceback.print_exc()
                return
        else:
            # Full analysis mode
            print("Step 8: Running full enhanced deadlock analysis...")
            try:
                report = detector.generate_report()
                print("✅ Enhanced report generated successfully")
            except Exception as e:
                print(f"❌ Error generating enhanced report: {e}")
                import traceback
                traceback.print_exc()
                return
        
        # Print header
        print("\n" + "="*80)
        print("    ENHANCED SQL DEADLOCK DETECTION REPORT")
        print("    With Improved Filtering and Validation")
        print("="*80)
        
        # Print summary
        summary = report['summary']
        print(f"\n📊 ENHANCED ANALYSIS SUMMARY:")
        print(f"   • Total Nodes Analyzed: {summary['total_nodes_analyzed']}")
        print(f"   • SQL-Enabled Nodes: {summary['total_sql_nodes']}")
        print(f"   • Deadlock Pairs Found: {summary['deadlock_pairs_found']}")
        print(f"   • Deadlocked Nodes: {summary['deadlocked_nodes']}")
        print(f"   • Tables Involved: {', '.join(summary['tables_involved']) if summary['tables_involved'] else 'None'}")
        print(f"   • Gateway Types: {', '.join(summary['gateway_types_involved']) if summary['gateway_types_involved'] else 'None'}")
        
        # Print severity breakdown
        severity = summary['severity_breakdown']
        print(f"   • Severity Breakdown:")
        print(f"     - CRITICAL: {severity.get('CRITICAL', 0)}")
        print(f"     - HIGH: {severity.get('HIGH', 0)}")
        print(f"     - MEDIUM: {severity.get('MEDIUM', 0)}")
        print(f"     - LOW: {severity.get('LOW', 0)}")
        
        # Print conclusion
        if summary['deadlock_pairs_found'] == 0:
            print(f"\n✅ CONCLUSION: No realistic SQL deadlock pairs detected!")
            print("   The enhanced filtering successfully eliminated false positives.")
        else:
            critical_count = summary['severity_breakdown'].get('CRITICAL', 0)
            high_count = summary['severity_breakdown'].get('HIGH', 0)
            if critical_count > 0 or high_count > 0:
                print(f"\n⚠️  CONCLUSION: {critical_count + high_count} high-priority SQL deadlock pairs require immediate attention!")
            else:
                print(f"\n⚡ CONCLUSION: {summary['deadlock_pairs_found']} realistic SQL deadlock pairs detected.")
        
        print("\n" + "="*80)
        print("✅ Enhanced analysis completed successfully!")
            
    except Exception as e:
        print(f"\n❌ Unexpected error during enhanced analysis: {e}")
        logger.error(f"Enhanced analysis failed: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'detector' in locals():
            try:
                detector.close()
                print("🔌 Neo4j connection closed.")
            except:
                pass

if __name__ == "__main__":
    # Set up logging for debug
    logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
    main()