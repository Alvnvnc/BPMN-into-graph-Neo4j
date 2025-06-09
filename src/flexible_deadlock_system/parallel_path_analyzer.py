#!/usr/bin/env python3
"""
Parallel Path Analyzer Module
Handles identification and analysis of parallel execution paths in BPMN processes.
Refactored from backup_sql.py for modular architecture.
"""

import logging
from typing import Dict, List, Set, Optional
from collections import defaultdict, deque

logger = logging.getLogger(__name__)

class ParallelPathAnalyzer:
    """
    Analyzes BPMN processes to identify parallel execution paths
    """
    
    def __init__(self):
        """
        Initialize the parallel path analyzer
        """
        logger.debug("Initializing ParallelPathAnalyzer")
    
    def _identify_gateways(self) -> List[Dict]:
        """
        Identify gateway nodes from BPMN data with improved detection
        
        Returns:
            List[Dict]: Gateway information with id, type, and label
        """
        gateways = []
        gateway_ids = set()  # Track unique gateway IDs
        
        # Method 1: Check nodes for gateway patterns
        nodes_data = self.bpmn_data.get('nodes', {})
        for node_id, node_data in nodes_data.items():
            # Extract type and label from node data
            labels = node_data.get('labels', [])
            properties = node_data.get('properties', {})
            
            # Combine labels and properties to determine type and label
            node_type = ' '.join(labels).lower() if labels else ''
            node_label = properties.get('name', '').lower()
            
            # Enhanced gateway detection patterns
            gateway_patterns = ['gateway', 'split', 'join', 'fork', 'merge', 'and', 'or', 'xor', 'parallel']
            
            if any(pattern in node_type or pattern in node_label for pattern in gateway_patterns):
                 if node_id not in gateway_ids:
                     gateway_info = {
                         'id': node_id,
                         'type': node_type,
                         'label': node_label,
                         'labels': labels,
                         'properties': properties,
                         'gateway_type': self._determine_gateway_type(node_type, node_label)
                     }
                     gateways.append(gateway_info)
                     gateway_ids.add(node_id)
                     logger.debug(f"Found gateway from node: {node_id} ({gateway_info['gateway_type']})")
        
        # Method 2: Check relationships for gateway patterns
        for rel in self.bpmn_data.get('relationships', []):
            rel_type = rel.get('rel_type', rel.get('relationship', '')).lower()
            source_id = rel.get('source_id')
            
            gateway_patterns = ['split', 'join', 'fork', 'merge', 'and', 'or', 'xor', 'parallel']
            
            if any(pattern in rel_type for pattern in gateway_patterns):
                if source_id and source_id not in gateway_ids:
                    gateway_info = {
                        'id': source_id,
                        'type': rel_type,
                        'label': '',
                        'gateway_type': self._determine_gateway_type(rel_type, '')
                    }
                    gateways.append(gateway_info)
                    gateway_ids.add(source_id)
                    logger.debug(f"Found gateway from relationship: {source_id} ({gateway_info['gateway_type']})")
        
        # Method 2.5: Extract gateways from Neo4j relationship properties (gateway_id and gateway_type)
        for rel in self.bpmn_data.get('relationships', []):
            # Check if relationship has gateway properties (from converter)
            properties = rel.get('properties', {})
            gateway_id = properties.get('gateway_id')
            gateway_type = properties.get('gateway_type')
            rel_type = rel.get('rel_type', '').upper()
            
            if gateway_id and gateway_type and gateway_id not in gateway_ids:
                # Determine gateway type from relationship type and gateway_type property
                detected_type = self._determine_neo4j_gateway_type(rel_type, gateway_type)
                
                gateway_info = {
                    'id': gateway_id,
                    'type': f'neo4j_gateway_{gateway_type.lower()}',
                    'label': gateway_type,
                    'gateway_type': detected_type,
                    'properties': {'gateway_type': gateway_type}
                }
                gateways.append(gateway_info)
                gateway_ids.add(gateway_id)
                logger.debug(f"Found Neo4j gateway: {gateway_id} ({detected_type}) from rel_type: {rel_type}")
        
        # Method 3: Detect structural gateways (nodes with multiple outgoing edges)
        node_outgoing_count = {}
        for rel in self.bpmn_data.get('relationships', []):
            source_id = rel.get('source_id')
            if source_id:
                node_outgoing_count[source_id] = node_outgoing_count.get(source_id, 0) + 1
        
        for node_id, count in node_outgoing_count.items():
            if count > 1 and node_id not in gateway_ids:
                # This could be an implicit split gateway
                gateway_info = {
                    'id': node_id,
                    'type': 'implicit_split',
                    'label': '',
                    'gateway_type': 'AND_SPLIT'  # Default to AND_SPLIT for multiple outgoing
                }
                gateways.append(gateway_info)
                gateway_ids.add(node_id)
                logger.debug(f"Found implicit gateway: {node_id} (multiple outgoing: {count})")
        
        logger.info(f"Total gateways identified: {len(gateways)}")
        
        # Enhanced logging to show all identified gateways
        logger.debug("Gateway identification details:")
        gateway_type_counts = {}
        for gateway in gateways:
            gateway_type = gateway['gateway_type']
            gateway_type_counts[gateway_type] = gateway_type_counts.get(gateway_type, 0) + 1
            logger.debug(f"  Gateway {gateway['id']}: {gateway_type} (from {gateway.get('type', 'unknown')})")
        
        logger.info(f"Gateway type distribution: {gateway_type_counts}")
        return gateways
    
    def _determine_gateway_type(self, node_type: str, node_label: str) -> str:
        """
        Determine the specific type of gateway from node type and label
        
        Args:
            node_type: Type of the node
            node_label: Label of the node
            
        Returns:
            str: Gateway type (AND_SPLIT, OR_SPLIT, etc.)
        """
        type_text = (node_type + ' ' + node_label).lower()
        
        # Check for specific gateway patterns
        # Note: Check XOR before OR since XOR contains OR as substring
        if 'and' in type_text or 'parallel' in type_text:
            if 'join' in type_text or 'merge' in type_text:
                return 'AND_JOIN'
            else:
                return 'AND_SPLIT'
        elif 'xor' in type_text or 'exclusive' in type_text:
            if 'join' in type_text or 'merge' in type_text:
                return 'XOR_JOIN'
            else:
                return 'XOR_SPLIT'
        elif 'or' in type_text or 'inclusive' in type_text:
            if 'join' in type_text or 'merge' in type_text:
                return 'OR_JOIN'
            else:
                return 'OR_SPLIT'
        elif 'split' in type_text or 'fork' in type_text:
            return 'AND_SPLIT'  # Default split type
        elif 'join' in type_text or 'merge' in type_text:
            return 'AND_JOIN'   # Default join type
        
        return 'UNKNOWN'
    
    def _determine_neo4j_gateway_type(self, rel_type: str, gateway_type: str) -> str:
        """
        Determine gateway type from Neo4j relationship type and gateway_type property
        
        Args:
            rel_type: Neo4j relationship type (e.g., 'AND_JOIN', 'AND_SPLIT')
            gateway_type: Gateway type property (e.g., 'Parallel', 'Exclusive')
            
        Returns:
            str: Determined gateway type
        """
        # First check rel_type for specific patterns
        # Note: Check XOR before OR since XOR_JOIN contains OR_JOIN as substring
        if 'AND_JOIN' in rel_type:
            return 'AND_JOIN'
        elif 'AND_SPLIT' in rel_type:
            return 'AND_SPLIT'
        elif 'XOR_JOIN' in rel_type:
            return 'XOR_JOIN'
        elif 'XOR_SPLIT' in rel_type:
            return 'XOR_SPLIT'
        elif 'OR_JOIN' in rel_type:
            return 'OR_JOIN'
        elif 'OR_SPLIT' in rel_type:
            return 'OR_SPLIT'
        
        # If rel_type doesn't have clear patterns, use gateway_type property
        gateway_type_lower = gateway_type.lower()
        if 'parallel' in gateway_type_lower:
            # Need to determine if it's split or join from rel_type
            if 'join' in rel_type.lower():
                return 'AND_JOIN'
            else:
                return 'AND_SPLIT'
        elif 'exclusive' in gateway_type_lower:
            if 'join' in rel_type.lower():
                return 'XOR_JOIN'
            else:
                return 'XOR_SPLIT'
        elif 'inclusive' in gateway_type_lower:
            if 'join' in rel_type.lower():
                return 'OR_JOIN'
            else:
                return 'OR_SPLIT'
        
        return 'UNKNOWN'
     
    def identify_parallel_scenarios(self, graph_data: Dict) -> List[Dict]:
        """
        Identify parallel execution scenarios from BPMN graph data
        
        Args:
            graph_data: BPMN graph data containing nodes and relationships
        
        Returns:
            List[Dict]: List of parallel execution scenarios
        """
        self.graph_data = graph_data
        self.bpmn_data = graph_data  # Set bpmn_data for _identify_gateways method
        parallel_scenarios = []
        
        logger.info("Identifying parallel execution paths...")
        
        # First, identify all gateways in the graph
        gateways = self._identify_gateways()
        
        # Focus on gateways that can cause real deadlocks - excluding XOR gateways
        # XOR gateways are mutually exclusive by design, so no parallel execution
        realistic_gateway_types = ['AND_SPLIT', 'OR_SPLIT', 'AND_JOIN', 'OR_JOIN']
        
        # Filter gateways to only include realistic ones
        realistic_gateways = [g for g in gateways if g['gateway_type'] in realistic_gateway_types]
        
        logger.info(f"Found {len(realistic_gateways)} realistic gateways for parallel analysis")
        
        
        # Method 1: Analyze from SPLIT gateways (forward analysis)
        split_gateways = [g for g in realistic_gateways if 'SPLIT' in g['gateway_type']]
        for gateway in split_gateways:
            split_scenarios = self._analyze_split_gateway(gateway)
            parallel_scenarios.extend(split_scenarios)
        
        # Method 2: Analyze from JOIN gateways (backward analysis)
        join_gateways = [g for g in realistic_gateways if 'JOIN' in g['gateway_type']]
        logger.info(f"Processing {len(join_gateways)} JOIN gateways for backward analysis")
        
        for gateway in join_gateways:
            logger.info(f"Analyzing JOIN gateway: {gateway['id']} ({gateway['gateway_type']})")
            join_scenarios = self._analyze_join_gateway(gateway)
            logger.info(f"JOIN gateway {gateway['id']} produced {len(join_scenarios)} scenarios")
            
            # Filter out duplicates
            for scenario in join_scenarios:
                if not self._is_duplicate_scenario(scenario, parallel_scenarios):
                    parallel_scenarios.append(scenario)
                    logger.info(f"ADDED {scenario['gateway_type']} scenario from gateway {scenario['gateway_node_id']}")
                else:
                    logger.info(f"SKIPPED {scenario['gateway_type']} scenario from gateway {scenario['gateway_node_id']} - duplicate detected")
        
        logger.info(f"Found {len(parallel_scenarios)} parallel execution scenarios")
        return parallel_scenarios
    
    def _analyze_split_gateway(self, gateway: Dict) -> List[Dict]:
        """
        Analyze a SPLIT gateway for parallel paths (forward analysis)
        
        Args:
            gateway: Gateway information dictionary
            
        Returns:
            List[Dict]: List of parallel scenarios from this split gateway
        """
        scenarios = []
        gateway_id = gateway['id']
        gateway_type = gateway['gateway_type']
        
        # Find all paths from this split gateway
        parallel_paths = self._find_truly_parallel_paths(gateway_id, gateway_type)
        
        if len(parallel_paths) > 1:
            scenario = {
                'analysis_type': 'SPLIT_FORWARD',
                'gateway_node_id': gateway_id,
                'gateway_type': gateway_type,
                'gateway_name': gateway.get('label', f'Split_{gateway_id}'),
                'paths': parallel_paths,
                'path_count': len(parallel_paths),
                'is_truly_parallel': self._validate_truly_parallel_execution(parallel_paths, gateway_type)
            }
            
            # Only include scenarios that are truly parallel
            if scenario['is_truly_parallel']:
                scenarios.append(scenario)
                logger.info(f"Found TRULY PARALLEL {gateway_type} with {len(parallel_paths)} paths (forward analysis)")
            else:
                logger.debug(f"Skipping {gateway_type} - paths merge before potential conflicts (forward analysis)")
        
        return scenarios
    
    def _analyze_join_gateway(self, gateway: Dict) -> List[Dict]:
        """
        Analyze a JOIN gateway for parallel paths (backward analysis)
        
        Args:
            gateway: Gateway information dictionary
            
        Returns:
            List[Dict]: List of parallel scenarios from this join gateway
        """
        scenarios = []
        gateway_id = gateway['id']
        gateway_type = gateway['gateway_type']
        
        # Enhanced logging for AND_JOIN debugging
        if gateway_type == 'AND_JOIN':
            logger.debug(f"Analyzing AND_JOIN gateway: {gateway_id}")
        
        # Find all paths that lead to this join gateway
        converging_paths = self._find_converging_parallel_paths(gateway_id, gateway_type)
        
        # Enhanced logging for AND_JOIN
        if gateway_type == 'AND_JOIN':
            logger.debug(f"AND_JOIN {gateway_id}: Found {len(converging_paths)} converging paths")
            for i, path in enumerate(converging_paths):
                logger.debug(f"  Path {i+1}: {len(path)} nodes - {path}")
        
        if len(converging_paths) > 1:
            is_truly_parallel = self._validate_converging_parallel_execution(converging_paths, gateway_type)
            
            # Enhanced logging for AND_JOIN validation
            if gateway_type == 'AND_JOIN':
                logger.info(f"AND_JOIN {gateway_id}: Validation result = {is_truly_parallel}")
                logger.info(f"AND_JOIN {gateway_id}: Building scenario with {len(converging_paths)} paths")
            
            scenario = {
                'analysis_type': 'JOIN_BACKWARD',
                'gateway_node_id': gateway_id,
                'gateway_type': gateway_type,
                'gateway_name': gateway.get('label', f'Join_{gateway_id}'),
                'paths': converging_paths,
                'path_count': len(converging_paths),
                'is_truly_parallel': is_truly_parallel
            }
            
            # Only include scenarios that are truly parallel
            if scenario['is_truly_parallel']:
                scenarios.append(scenario)
                if gateway_type == 'AND_JOIN':
                    logger.info(f"ADDED AND_JOIN {gateway_id} scenario to result list")
                logger.info(f"Found TRULY PARALLEL {gateway_type} with {len(converging_paths)} converging paths (backward analysis)")
            else:
                if gateway_type == 'AND_JOIN':
                    logger.warning(f"SKIPPING AND_JOIN {gateway_id}: Validation failed - paths not truly parallel")
                else:
                    logger.debug(f"Skipping {gateway_type} - paths not truly parallel (backward analysis)")
        else:
            if gateway_type == 'AND_JOIN':
                logger.debug(f"AND_JOIN {gateway_id}: Only {len(converging_paths)} path(s) found - insufficient for parallel analysis")
        
        return scenarios
    
    def _find_truly_parallel_paths(self, gateway_id: str, gateway_type: str) -> List[List[str]]:
        """
        Find truly parallel paths from a SPLIT gateway
        
        Args:
            gateway_id: ID of the gateway node
            gateway_type: Type of the gateway
            
        Returns:
            List[List[str]]: List of parallel paths (each path is a list of node IDs)
        """
        paths = []
        
        # Get immediate successors from this gateway
        successors = []
        for rel in self.graph_data['relationships']:
            if rel['source_id'] == gateway_id and gateway_type in rel['rel_type']:
                successors.append(rel['target_id'])
        
        logger.debug(f"Gateway {gateway_id} has {len(successors)} immediate successors")
        
        # For each successor, trace the path until corresponding join or end
        for successor in successors:
            path = self._trace_path_forward_from_split(successor, gateway_type)
            if path:  # Only include paths that have SQL nodes
                paths.append(path)
                logger.debug(f"  Forward path found with {len(path)} SQL nodes")
        
        return paths
    
    def _find_converging_parallel_paths(self, join_node_id: str, join_type: str) -> List[List[str]]:
        """
        Find paths that converge at a JOIN gateway (backward analysis)
        
        Args:
            join_node_id: ID of the join gateway node
            join_type: Type of the join gateway
            
        Returns:
            List[List[str]]: List of converging paths (each path is a list of node IDs)
        """
        paths = []
        
        # Method 1: Traditional approach - find relationships where target_id matches join_node_id
        predecessors = []
        for rel in self.graph_data['relationships']:
            if rel['target_id'] == join_node_id and join_type in rel['rel_type']:
                predecessors.append(rel['source_id'])
        
        logger.debug(f"Traditional Join {join_node_id} has {len(predecessors)} immediate predecessors")
        
        # Method 2: Neo4j gateway approach - find relationships with gateway_id in properties
        if len(predecessors) == 0:
            logger.debug(f"No traditional predecessors found, trying Neo4j gateway method for {join_node_id}")
            neo4j_paths = self._find_converging_parallel_paths_neo4j(join_node_id, join_type)
            if neo4j_paths:
                return neo4j_paths
        
        # For each predecessor, trace the path backward until corresponding split
        for predecessor in predecessors:
            path = self._trace_path_backward_from_join(predecessor, join_type)
            if path:  # Only include paths that have SQL nodes before join
                paths.append(path)
                logger.debug(f"  Backward path found with {len(path)} SQL nodes")
            else:
                logger.debug(f"  No SQL nodes found in backward path from {predecessor}")
        
        # Enhanced logging for AND_JOIN scenarios
        if join_type == 'AND_JOIN' and len(paths) > 0:
            logger.info(f"AND_JOIN {join_node_id}: Found {len(paths)} converging paths with SQL nodes")
            for i, path in enumerate(paths):
                logger.info(f"  Path {i+1}: {len(path)} SQL nodes - {path}")
        
        return paths
    
    def _find_converging_parallel_paths_neo4j(self, join_gateway_id: str, join_type: str) -> List[List[str]]:
        """
        Find paths that converge at a JOIN gateway using Neo4j gateway properties (backward analysis)
        This method looks for relationships that have gateway_id in their properties
        
        Args:
            join_gateway_id: ID of the join gateway (from converter)
            join_type: Type of the join gateway
            
        Returns:
            List[List[str]]: List of converging paths (each path is a list of node IDs)
        """
        paths = []
        
        # Get relationships that have this gateway_id in their properties
        gateway_relationships = []
        for rel in self.graph_data['relationships']:
            properties = rel.get('properties', {})
            rel_gateway_id = properties.get('gateway_id')
            rel_type = rel.get('rel_type', '')
            
            # Match by gateway_id and relationship type
            if rel_gateway_id == join_gateway_id and join_type in rel_type:
                gateway_relationships.append(rel)
        
        logger.debug(f"Neo4j Join {join_gateway_id}: Found {len(gateway_relationships)} gateway relationships")
        
        # For each gateway relationship, get the source node and trace backward
        predecessors = []
        for rel in gateway_relationships:
            predecessors.append(rel['source_id'])
        
        logger.debug(f"Neo4j Join {join_gateway_id}: Found {len(predecessors)} immediate predecessors: {predecessors}")
        
        # For each predecessor, trace the path backward until corresponding split
        for predecessor in predecessors:
            path = self._trace_path_backward_from_join(predecessor, join_type)
            if path:  # Only include paths that have SQL nodes before join
                paths.append(path)
                logger.debug(f"  Neo4j backward path found with {len(path)} SQL nodes")
            else:
                logger.debug(f"  Neo4j: No SQL nodes found in backward path from {predecessor}")
        
        # Enhanced logging for AND_JOIN scenarios
        if join_type == 'AND_JOIN' and len(paths) > 0:
            logger.info(f"Neo4j AND_JOIN {join_gateway_id}: Found {len(paths)} converging paths with SQL nodes")
            for i, path in enumerate(paths):
                logger.info(f"  Neo4j Path {i+1}: {len(path)} SQL nodes - {path}")
        
        return paths
    
    def _trace_path_forward_from_split(self, start_node: str, split_type: str, max_depth: int = 20) -> List[str]:
        """
        Trace execution path forward from SPLIT until it hits corresponding JOIN gateway
        
        Args:
            start_node: Starting node ID
            split_type: Type of split gateway
            max_depth: Maximum traversal depth
            
        Returns:
            List[str]: Path of SQL-enabled nodes
        """
        sql_path = []
        current = start_node
        visited = set()
        depth = 0
        
        # Determine corresponding JOIN types
        join_types = {
            'AND_SPLIT': ['AND_JOIN'],
            'OR_SPLIT': ['OR_JOIN', 'AND_JOIN']  # OR_SPLIT can lead to either OR_JOIN or AND_JOIN
        }
        corresponding_joins = join_types.get(split_type, [])
        
        while current and current not in visited and depth < max_depth:
            visited.add(current)
            depth += 1
            
            # Add SQL-enabled nodes to path
            if self._has_sql_operation(current):
                sql_path.append(current)
            
            # Check if we hit a JOIN gateway
            outgoing_rels = [rel for rel in self.graph_data['relationships'] if rel['source_id'] == current]
            
            for rel in outgoing_rels:
                if any(join_type in rel['rel_type'] for join_type in corresponding_joins):
                    # We hit a corresponding join - stop tracing this path
                    logger.debug(f"    Forward path stopped at {rel['rel_type']} gateway")
                    return sql_path
            
            # Find next node (non-join)
            next_nodes = [rel['target_id'] for rel in outgoing_rels 
                         if not any(join_type in rel['rel_type'] for join_type in corresponding_joins)]
            
            # Continue with first next node (simplified traversal)
            current = next_nodes[0] if next_nodes else None
        
        return sql_path
    
    def _trace_path_backward_from_join(self, start_node: str, join_type: str, max_depth: int = 20) -> List[str]:
        """
        Trace execution path backward from JOIN until it hits corresponding SPLIT gateway
        
        Args:
            start_node: Starting node ID
            join_type: Type of join gateway
            max_depth: Maximum traversal depth
            
        Returns:
            List[str]: Path of SQL-enabled nodes (excluding shared parent nodes)
        """
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
        
        logger.debug(f"Tracing backward from {start_node} for {join_type}")
        
        while current and current not in visited and depth < max_depth:
            visited.add(current)
            depth += 1
            
            # Add SQL-enabled nodes to path (in reverse order)
            if self._has_sql_operation(current):
                sql_path.insert(0, current)  # Insert at beginning to maintain execution order
                logger.debug(f"    Found SQL node: {current}")
            
            # Check if we hit a SPLIT gateway
            incoming_rels = [rel for rel in self.graph_data['relationships'] if rel['target_id'] == current]
            
            for rel in incoming_rels:
                if any(split_type in rel['rel_type'] for split_type in corresponding_splits):
                    # We hit a corresponding split - stop tracing this path
                    logger.debug(f"    Backward path stopped at {rel['rel_type']} gateway")
                    # For AND_JOIN scenarios, filter out shared parent nodes
                    if join_type == 'AND_JOIN':
                        return self._filter_shared_parent_nodes(sql_path, start_node, join_type)
                    return sql_path
            
            # Find previous node (non-split)
            prev_nodes = [rel['source_id'] for rel in incoming_rels 
                         if not any(split_type in rel['rel_type'] for split_type in corresponding_splits)]
            
            # Continue with first previous node (simplified traversal)
            current = prev_nodes[0] if prev_nodes else None
            
            if current:
                logger.debug(f"    Moving to previous node: {current}")
        
        logger.debug(f"Backward trace completed. Found {len(sql_path)} SQL nodes: {sql_path}")
        
        # For AND_JOIN scenarios, filter out shared parent nodes
        if join_type == 'AND_JOIN':
            return self._filter_shared_parent_nodes(sql_path, start_node, join_type)
        
        return sql_path
    
    def _has_sql_operation(self, node_id: str) -> bool:
        """
        Check if a node has SQL operations
        
        Args:
            node_id: Node ID to check
            
        Returns:
            bool: True if node has SQL operations
        """
        if node_id not in self.graph_data['nodes']:
            logger.debug(f"Node {node_id} not found in graph data")
            return False
        
        props = self.graph_data['nodes'][node_id]['properties']
        has_sql = 'SQL' in props and props['SQL']
        
        if has_sql:
            logger.debug(f"Node {node_id} has SQL operation: {props.get('name', 'unnamed')}")
        
        return has_sql
    
    def _validate_truly_parallel_execution(self, paths: List[List[str]], split_type: str) -> bool:
        """
        Validate if paths from a split gateway are truly executed in parallel
        
        Args:
            paths: List of paths to validate
            split_type: Type of split gateway
            
        Returns:
            bool: True if paths are truly parallel
        """
        # For AND_SPLIT: All paths are executed in parallel
        if split_type == 'AND_SPLIT':
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        # For OR_SPLIT: Paths can be parallel if multiple conditions are triggered
        elif split_type == 'OR_SPLIT':
            # OR_SPLIT can lead to parallel execution in certain scenarios
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        return False
    
    def _validate_converging_parallel_execution(self, paths: List[List[str]], join_type: str) -> bool:
        """
        Validate if converging paths were truly executed in parallel
        
        Args:
            paths: List of converging paths
            join_type: Type of join gateway
            
        Returns:
            bool: True if paths were truly parallel
        """
        # For AND_JOIN: Paths must have come from AND_SPLIT - always parallel
        if join_type == 'AND_JOIN':
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        # For OR_JOIN: Paths could have come from OR_SPLIT or AND_SPLIT
        elif join_type == 'OR_JOIN':
            # Similar validation as OR_SPLIT - can be parallel if multiple conditions triggered
            return len(paths) > 1 and all(len(path) > 0 for path in paths)
        
        return False
    
    def _is_duplicate_scenario(self, new_scenario: Dict, existing_scenarios: List[Dict]) -> bool:
        """
        Check if a scenario is already covered by existing scenarios
        
        Args:
            new_scenario: New scenario to check
            existing_scenarios: List of existing scenarios
            
        Returns:
            bool: True if scenario is duplicate
        """
        new_paths_set = set()
        for path in new_scenario['paths']:
            new_paths_set.add(tuple(sorted(path)))
        
        for existing in existing_scenarios:
            existing_paths_set = set()
            for path in existing['paths']:
                existing_paths_set.add(tuple(sorted(path)))
            
            # A scenario is only a duplicate if:
            # 1. Same gateway type AND same gateway node AND same paths, OR
            # 2. Exact same set of paths (covers forward/backward analysis of same scenario)
            same_gateway = (new_scenario['gateway_type'] == existing['gateway_type'] and 
                          new_scenario['gateway_node_id'] == existing['gateway_node_id'])
            same_paths = new_paths_set == existing_paths_set
            
            if same_gateway and same_paths:
                logger.debug(f"Exact duplicate scenario detected - skipping {new_scenario['gateway_type']} from {new_scenario['gateway_node_id']}")
                return True
            elif same_paths and not same_gateway:
                # Same paths but different gateway types - this is suspicious but can happen
                # Allow it but log for debugging
                logger.debug(f"Same paths but different gateways: {new_scenario['gateway_type']} vs {existing['gateway_type']}")
        
        return False
    
    def get_path_statistics(self, parallel_scenarios: List[Dict]) -> Dict:
        """
        Get statistics about the identified parallel paths
        
        Args:
            parallel_scenarios: List of parallel scenarios
            
        Returns:
            Dict: Statistics about the paths
        """
        stats = {
            'total_scenarios': len(parallel_scenarios),
            'split_scenarios': 0,
            'join_scenarios': 0,
            'and_gateways': 0,
            'or_gateways': 0,
            'total_paths': 0,
            'avg_path_length': 0.0
        }
        
        total_path_length = 0
        total_paths = 0
        
        for scenario in parallel_scenarios:
            if scenario['analysis_type'] == 'SPLIT_FORWARD':
                stats['split_scenarios'] += 1
            else:
                stats['join_scenarios'] += 1
            
            if 'AND' in scenario['gateway_type']:
                stats['and_gateways'] += 1
            else:
                stats['or_gateways'] += 1
            
            for path in scenario['paths']:
                total_paths += 1
                total_path_length += len(path)
        
        stats['total_paths'] = total_paths
        if total_paths > 0:
            stats['avg_path_length'] = round(total_path_length / total_paths, 2)
        
        return stats
    
    def _filter_shared_parent_nodes(self, sql_path: List[str], start_node: str, join_type: str) -> List[str]:
        """
        Filter out shared parent nodes from AND_JOIN paths to ensure only truly parallel nodes remain
        
        For AND_JOIN scenarios, we want to exclude nodes that appear in all paths leading to the join,
        as these represent shared parent nodes rather than truly parallel execution branches.
        
        Args:
            sql_path: Original SQL path from backward tracing
            start_node: The starting node for this path (immediate predecessor to join)
            join_type: Type of join gateway
            
        Returns:
            List[str]: Filtered path with shared parent nodes removed
        """
        if join_type != 'AND_JOIN' or len(sql_path) <= 1:
            return sql_path
        
        # Strategy: Include nodes that are truly part of the parallel execution branch
        # Exclude nodes that are shared ancestors across multiple parallel paths
        
        filtered_path = []
        
        # Priority 1: Include the start_node if it has SQL operations
        if self._has_sql_operation(start_node):
            filtered_path.append(start_node)
            logger.debug(f"    Added start_node {start_node} to filtered path")
        
        # Priority 2: If start_node has no SQL, look for SQL nodes in the immediate vicinity
        # that are clearly part of this specific parallel branch
        if not filtered_path and len(sql_path) > 0:
            # Look backwards from the start_node to find the closest SQL node
            # that belongs to this specific parallel branch
            for i, node in enumerate(reversed(sql_path)):
                if self._has_sql_operation(node):
                    # Check if this node is truly part of the parallel branch
                    if self._is_truly_parallel_node(node, start_node):
                        filtered_path.append(node)
                        logger.debug(f"    Added parallel node {node} to filtered path")
                        # Only include the closest truly parallel SQL node
                        break
                    else:
                        logger.debug(f"    Skipping shared parent node {node}")
        
        # Priority 3: If no specific parallel nodes found, include a limited set
        # This handles edge cases where the heuristics above don't work
        if not filtered_path and len(sql_path) > 0:
            # As a fallback, include only the last SQL node (closest to join)
            for node in reversed(sql_path):
                if self._has_sql_operation(node):
                    filtered_path.append(node)
                    logger.debug(f"    Added fallback SQL node {node} to filtered path")
                    break
        
        logger.debug(f"Filtered AND_JOIN path from {len(sql_path)} to {len(filtered_path)} nodes: {sql_path} -> {filtered_path}")
        return filtered_path
    
    def _is_truly_parallel_node(self, node_id: str, target_node: str) -> bool:
        """
        Check if a node is truly part of a parallel execution branch
        
        A node is considered truly parallel if:
        1. It has SQL operations
        2. It leads to only one specific branch (not shared across multiple branches)
        
        Args:
            node_id: Node to check
            target_node: Target node this should lead to
            
        Returns:
            bool: True if node is truly parallel
        """
        if not self._has_sql_operation(node_id):
            return False
        
        # Check outgoing relationships from this node
        outgoing_rels = [rel for rel in self.graph_data['relationships'] if rel['source_id'] == node_id]
        
        # For simplicity, consider a node truly parallel if it has direct path to target
        for rel in outgoing_rels:
            if rel['target_id'] == target_node:
                return True
        
        # Check indirect path (one level deep)
        for rel in outgoing_rels:
            indirect_rels = [r for r in self.graph_data['relationships'] if r['source_id'] == rel['target_id']]
            for indirect_rel in indirect_rels:
                if indirect_rel['target_id'] == target_node:
                    return True
        
        return False