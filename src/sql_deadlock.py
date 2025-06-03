import logging
import re
import sqlparse
from typing import Dict, List, Set, Tuple, Optional
from neo4j import GraphDatabase
from collections import defaultdict, deque
import networkx as nx

logger = logging.getLogger(__name__)

class SQLDeadlockDetector:
    """
    Advanced SQL Deadlock Detector using Graph Theory:
    - Tarjan's Algorithm for Strongly Connected Components
    - Topological Sorting for dependency analysis
    - Automated SQL resource extraction
    - Structural deadlock detection based on gateway combinations
    - No hardcoded patterns - fully dynamic analysis
    """
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, database: str = "neo4j"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.database = database
        self.graph_data = None
        self.resource_graph = nx.DiGraph()
        self.wait_for_graph = nx.DiGraph()
        self.sql_resources = {}
        self.deadlock_risks = []
        self.structural_deadlocks = []
        
        # Gateway combination rules for structural deadlock detection
        self.problematic_combinations = {
            ('AND_SPLIT', 'OR_JOIN'): 'AND-split activates all paths, but OR-join continues after first arrival',
            ('AND_SPLIT', 'XOR_JOIN'): 'AND-split activates all paths, but XOR-join only accepts one token',
            ('OR_SPLIT', 'AND_JOIN'): 'OR-split may not activate all paths, but AND-join requires all paths',
            ('XOR_SPLIT', 'AND_JOIN'): 'XOR-split activates only one path, but AND-join waits for all paths'
        }
        
        self.safe_combinations = {
            ('AND_SPLIT', 'AND_JOIN'): 'AND-split activates all paths and AND-join waits for all paths',
            ('XOR_SPLIT', 'XOR_JOIN'): 'XOR-split activates one path and XOR-join continues after one path',
            ('OR_SPLIT', 'OR_JOIN'): 'OR-split activates paths and OR-join continues when active paths complete',
            ('XOR_SPLIT', 'OR_JOIN'): 'XOR-split activates one path and OR-join continues after completion'
        }
        
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
        """Extract database resources from SQL query"""
        if not sql_query:
            return {'tables': set(), 'columns': set(), 'operations': set()}
            
        try:
            # Parse SQL using sqlparse
            parsed = sqlparse.parse(sql_query.upper())
            resources = {
                'tables': set(),
                'columns': set(), 
                'operations': set()
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
                
                # Extract column names from WHERE clauses
                where_pattern = r'WHERE\s+([\w]+)\s*[=<>!]'
                where_matches = re.findall(where_pattern, sql_text, re.IGNORECASE)
                resources['columns'].update(where_matches)
                
                # Extract SET clause columns (for UPDATE)
                set_pattern = r'SET\s+([\w]+)\s*='
                set_matches = re.findall(set_pattern, sql_text, re.IGNORECASE)
                resources['columns'].update(set_matches)
                
            return resources
            
        except Exception as e:
            logger.warning(f"Error parsing SQL: {e}")
            return {'tables': set(), 'columns': set(), 'operations': set()}
    
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
    
    def identify_parallel_execution_paths(self) -> List[List[str]]:
        """Identify parallel execution paths using gateway analysis"""
        parallel_groups = []
        
        # Find parallel gateways (AND_SPLIT)
        for rel in self.graph_data['relationships']:
            if 'AND_SPLIT' in rel['rel_type']:
                source_id = rel['source_id']
                
                # Find all paths from this split gateway
                parallel_paths = self._find_paths_from_split(source_id)
                if len(parallel_paths) > 1:
                    parallel_groups.append(parallel_paths)
                    
        return parallel_groups
    
    def _find_paths_from_split(self, split_node_id: str) -> List[List[str]]:
        """Find all execution paths from a split gateway"""
        paths = []
        
        # Get immediate successors
        successors = []
        for rel in self.graph_data['relationships']:
            if rel['source_id'] == split_node_id and 'SPLIT' in rel['rel_type']:
                successors.append(rel['target_id'])
        
        # For each successor, trace the path until join or end
        for successor in successors:
            path = self._trace_path_until_join(successor)
            if path:
                paths.append(path)
                
        return paths
    
    def _trace_path_until_join(self, start_node: str) -> List[str]:
        """Trace execution path until reaching a join gateway or end"""
        path = []
        current = start_node
        visited = set()
        
        while current and current not in visited:
            visited.add(current)
            
            # Add SQL-enabled nodes to path
            if current in self.sql_resources:
                path.append(current)
            
            # Find next node
            next_nodes = []
            for rel in self.graph_data['relationships']:
                if rel['source_id'] == current:
                    # Stop at join gateways
                    if 'JOIN' in rel['rel_type']:
                        break
                    next_nodes.append(rel['target_id'])
            
            # Continue with first next node (simplified)
            current = next_nodes[0] if next_nodes else None
            
        return path
    
    def build_wait_for_graph(self):
        """Build wait-for graph based on resource conflicts"""
        parallel_groups = self.identify_parallel_execution_paths()
        
        for group in parallel_groups:
            # Check resource conflicts between parallel paths
            for i, path1 in enumerate(group):
                for j, path2 in enumerate(group):
                    if i >= j:  # Avoid duplicate comparisons
                        continue
                        
                    # Check for resource conflicts between paths
                    conflicts = self._check_resource_conflicts(path1, path2)
                    if conflicts:
                        # Add edges to wait-for graph only for nodes that actually have conflicts
                        for node1 in path1:
                            for node2 in path2:
                                if node1 in self.sql_resources and node2 in self.sql_resources:
                                    # Check if these specific nodes have resource conflicts
                                    specific_conflicts = self._check_specific_node_conflicts(node1, node2)
                                    if specific_conflicts:
                                        self.wait_for_graph.add_edge(node1, node2, conflict=specific_conflicts)
                                        self.wait_for_graph.add_edge(node2, node1, conflict=specific_conflicts)
    
    def _check_resource_conflicts(self, path1: List[str], path2: List[str]) -> Dict:
        """Check for resource conflicts between two execution paths"""
        conflicts = {
            'table_conflicts': set(),
            'column_conflicts': set(),
            'operation_conflicts': []
        }
        
        for node1 in path1:
            for node2 in path2:
                if node1 in self.sql_resources and node2 in self.sql_resources:
                    res1 = self.sql_resources[node1]['resources']
                    res2 = self.sql_resources[node2]['resources']
                    
                    # Check table conflicts
                    table_overlap = res1['tables'].intersection(res2['tables'])
                    if table_overlap:
                        conflicts['table_conflicts'].update(table_overlap)
                    
                    # Check column conflicts
                    column_overlap = res1['columns'].intersection(res2['columns'])
                    if column_overlap:
                        conflicts['column_conflicts'].update(column_overlap)
                    
                    # Check operation conflicts (write-write, read-write)
                    ops1 = res1['operations']
                    ops2 = res2['operations']
                    
                    write_ops = {'UPDATE', 'INSERT', 'DELETE'}
                    if (ops1.intersection(write_ops) and ops2.intersection(write_ops)) or \
                       (ops1.intersection(write_ops) and 'SELECT' in ops2) or \
                       ('SELECT' in ops1 and ops2.intersection(write_ops)):
                        conflicts['operation_conflicts'].append((node1, node2))
        
        return conflicts if any([conflicts['table_conflicts'], 
                               conflicts['column_conflicts'], 
                               conflicts['operation_conflicts']]) else None
    
    def _check_specific_node_conflicts(self, node1: str, node2: str) -> Dict:
        """Check for resource conflicts between two specific nodes"""
        if node1 not in self.sql_resources or node2 not in self.sql_resources:
            return None
            
        res1 = self.sql_resources[node1]['resources']
        res2 = self.sql_resources[node2]['resources']
        
        node1_name = self.sql_resources[node1].get('name', node1)
        node2_name = self.sql_resources[node2].get('name', node2)
        
        conflicts = {
            'table_conflicts': set(),
            'column_conflicts': set(),
            'operation_conflicts': []
        }
        
        # Check table conflicts
        table_overlap = res1['tables'].intersection(res2['tables'])
        if table_overlap:
            conflicts['table_conflicts'].update(table_overlap)
            print(f"      🔴 Table conflict: {node1_name} & {node2_name} both access tables: {table_overlap}")
        
        # Check column conflicts
        column_overlap = res1['columns'].intersection(res2['columns'])
        if column_overlap:
            conflicts['column_conflicts'].update(column_overlap)
            print(f"      🟡 Column conflict: {node1_name} & {node2_name} both access columns: {column_overlap}")
        
        # Check operation conflicts (write-write, read-write)
        ops1 = res1['operations']
        ops2 = res2['operations']
        
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        if (ops1.intersection(write_ops) and ops2.intersection(write_ops)):
            conflicts['operation_conflicts'].append((node1, node2))
            print(f"      🔥 Write-Write conflict: {node1_name}({ops1 & write_ops}) vs {node2_name}({ops2 & write_ops})")
        elif (ops1.intersection(write_ops) and 'SELECT' in ops2):
            conflicts['operation_conflicts'].append((node1, node2))
            print(f"      ⚡ Write-Read conflict: {node1_name}({ops1 & write_ops}) vs {node2_name}(SELECT)")
        elif ('SELECT' in ops1 and ops2.intersection(write_ops)):
            conflicts['operation_conflicts'].append((node1, node2))
            print(f"      ⚡ Read-Write conflict: {node1_name}(SELECT) vs {node2_name}({ops2 & write_ops})")
        
        has_conflicts = any([conflicts['table_conflicts'], 
                           conflicts['column_conflicts'], 
                           conflicts['operation_conflicts']])
        
        if has_conflicts:
            print(f"      ✅ Conflict confirmed between {node1_name} and {node2_name}")
        else:
            print(f"      ❌ No specific conflicts between {node1_name} and {node2_name}")
            
        return conflicts if has_conflicts else None
    
    def tarjan_scc(self) -> List[List[str]]:
        """Tarjan's algorithm for finding strongly connected components"""
        if not self.wait_for_graph.nodes():
            return []
            
        index_counter = [0]
        stack = []
        lowlinks = {}
        index = {}
        on_stack = {}
        sccs = []
        
        def strongconnect(node):
            index[node] = index_counter[0]
            lowlinks[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack[node] = True
            
            for successor in self.wait_for_graph.successors(node):
                if successor not in index:
                    strongconnect(successor)
                    lowlinks[node] = min(lowlinks[node], lowlinks[successor])
                elif on_stack.get(successor, False):
                    lowlinks[node] = min(lowlinks[node], index[successor])
            
            if lowlinks[node] == index[node]:
                component = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    component.append(w)
                    if w == node:
                        break
                if len(component) > 1:  # Only cycles with more than 1 node
                    sccs.append(component)
        
        for node in self.wait_for_graph.nodes():
            if node not in index:
                strongconnect(node)
                
        return sccs
    
    def detect_structural_deadlocks(self) -> List[Dict]:
        """Detect structural deadlocks based on gateway combinations"""
        logger.info("Starting structural deadlock detection...")
        
        if not self.graph_data:
            self.fetch_graph_data()
        
        structural_deadlocks = []
        
        # Find all split-join pairs
        split_join_pairs = self._find_split_join_pairs()
        
        for pair in split_join_pairs:
            split_node = pair['split_node']
            join_node = pair['join_node']
            split_type = pair['split_type']
            join_type = pair['join_type']
            
            # Analyze path between split and join
            path_info = self._analyze_split_join_path(pair.get('split_id', ''), pair.get('join_id', ''))
            
            # Check if combination is problematic
            combination = (split_type, join_type)
            
            if combination in self.problematic_combinations:
                deadlock = {
                    'type': 'Structural Deadlock',
                    'split_node': split_node,
                    'join_node': join_node,
                    'split_type': split_type,
                    'join_type': join_type,
                    'severity': 'CRITICAL',
                    'description': f"Structural deadlock: {self.problematic_combinations[combination]}",
                    'path_info': path_info,
                    'recommendation': self._generate_structural_recommendation(combination)
                }
                structural_deadlocks.append(deadlock)
                
            elif combination == ('OR_SPLIT', 'XOR_JOIN'):
                # Potential race condition
                deadlock = {
                    'type': 'Potential Race Condition',
                    'split_node': split_node,
                    'join_node': join_node,
                    'split_type': split_type,
                    'join_type': join_type,
                    'severity': 'MEDIUM',
                    'description': 'OR-split may activate multiple paths but XOR-join only accepts first arrival',
                    'path_info': path_info,
                    'recommendation': 'Consider using OR-join instead of XOR-join or ensure only one path is activated'
                }
                structural_deadlocks.append(deadlock)
        
        self.structural_deadlocks = structural_deadlocks
        return structural_deadlocks
    
    def _find_split_join_pairs(self) -> List[Dict]:
        """Find all balanced split-join processes in the graph"""
        processes = []
        
        # Find all split gateways
        split_nodes = {}
        for rel in self.graph_data['relationships']:
            rel_type = rel['rel_type']
            if '_SPLIT' in rel_type:
                source_id = rel['source_id']
                if source_id in self.graph_data['nodes']:
                    node_name = self.graph_data['nodes'][source_id]['properties'].get('name', '')
                    if node_name != 'Start':  # Exclude start node
                        split_type = rel_type.replace('_SPLIT', '_SPLIT')
                        split_nodes[source_id] = {
                            'name': node_name,
                            'type': split_type
                        }
                        logger.info(f"Found split gateway: {node_name} ({split_type})")
        
        logger.info(f"Total split gateways found: {len(split_nodes)}")
        
        # For each split node, find all balanced processes
        for split_id, split_info in split_nodes.items():
            balanced_processes = self._find_balanced_processes(split_id)
            logger.info(f"Split '{split_info['name']}' has {len(balanced_processes)} balanced processes")
            
            for process in balanced_processes:
                # Analyze each path in the balanced process for deadlocks
                process_deadlocks = self._analyze_process_for_deadlocks(process)
                
                process_info = {
                    'split_node': split_info['name'],
                    'join_node': process['join_name'],
                    'split_type': split_info['type'],
                    'join_type': process['join_type'],
                    'split_id': split_id,
                    'join_id': process['join_id'],
                    'all_paths': process['all_paths'],
                    'path_count': len(process['all_paths']),
                    'is_balanced': process['is_balanced'],
                    'deadlock_analysis': process_deadlocks
                }
                processes.append(process_info)
                
                logger.info(f"Balanced Process: {split_info['name']} -> {process['join_name']} with {len(process['all_paths'])} paths, Deadlocks: {len(process_deadlocks)}")
        
        logger.info(f"Total balanced processes found: {len(processes)}")
        return processes
    
    def _analyze_process_for_deadlocks(self, process: Dict) -> List[Dict]:
        """Analyze all paths in a balanced process for potential deadlocks"""
        deadlocks = []
        paths = process['all_paths']
        
        # Check each combination of paths for resource conflicts
        for i, path1 in enumerate(paths):
            for j, path2 in enumerate(paths):
                if i >= j:  # Avoid duplicate comparisons
                    continue
                
                # Check for resource conflicts between these two paths
                conflicts = self._check_path_conflicts(path1, path2)
                if conflicts:
                    deadlock = {
                        'type': 'Resource Conflict in Balanced Process',
                        'path1': path1['path'],
                        'path2': path2['path'],
                        'conflicts': conflicts,
                        'severity': 'HIGH' if conflicts['operation_conflicts'] else 'MEDIUM'
                    }
                    deadlocks.append(deadlock)
        
        return deadlocks
    
    def _check_path_conflicts(self, path1: Dict, path2: Dict) -> Dict:
        """Check for resource conflicts between two specific paths"""
        conflicts = {
            'table_conflicts': set(),
            'column_conflicts': set(),
            'operation_conflicts': []
        }
        
        # Get SQL resources from nodes in both paths
        path1_resources = self._get_path_resources(path1['path'])
        path2_resources = self._get_path_resources(path2['path'])
        
        # Check for overlapping resources
        table_overlap = path1_resources['tables'].intersection(path2_resources['tables'])
        if table_overlap:
            conflicts['table_conflicts'].update(table_overlap)
        
        column_overlap = path1_resources['columns'].intersection(path2_resources['columns'])
        if column_overlap:
            conflicts['column_conflicts'].update(column_overlap)
        
        # Check operation conflicts
        ops1 = path1_resources['operations']
        ops2 = path2_resources['operations']
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        
        if (ops1.intersection(write_ops) and ops2.intersection(write_ops)) or \
           (ops1.intersection(write_ops) and 'SELECT' in ops2) or \
           ('SELECT' in ops1 and ops2.intersection(write_ops)):
            conflicts['operation_conflicts'].append((path1['path'], path2['path']))
        
        return conflicts if any([conflicts['table_conflicts'], 
                               conflicts['column_conflicts'], 
                               conflicts['operation_conflicts']]) else None
    
    def _get_path_resources(self, path: List[str]) -> Dict[str, Set[str]]:
        """Get all SQL resources used in a path"""
        resources = {
            'tables': set(),
            'columns': set(),
            'operations': set()
        }
        
        for node_id in path:
            if node_id in self.sql_resources:
                node_resources = self.sql_resources[node_id]['resources']
                resources['tables'].update(node_resources['tables'])
                resources['columns'].update(node_resources['columns'])
                resources['operations'].update(node_resources['operations'])
        
        return resources
    
    def _find_balanced_processes(self, split_id: str) -> List[Dict]:
        """Find all balanced processes (equal split and join count) from a split node"""
        balanced_processes = []
        
        # Find all possible paths from split using DFS
        all_paths = self._find_all_paths_from_split(split_id)
        
        # Group paths by their join nodes
        paths_by_join = defaultdict(list)
        for path in all_paths:
            if path['join_id']:
                paths_by_join[path['join_id']].append(path)
        
        # Check each join node for balanced process
        for join_id, paths in paths_by_join.items():
            split_count = self._count_splits_in_paths(paths)
            join_count = self._count_joins_in_paths(paths)
            
            # Check if this is a balanced process (equal splits and joins)
            if split_count == join_count:
                join_name = self.graph_data['nodes'][join_id]['properties'].get('name', 'Unknown')
                join_type = self._get_join_type_from_paths(paths)
                
                balanced_process = {
                    'join_id': join_id,
                    'join_name': join_name,
                    'join_type': join_type,
                    'all_paths': paths,
                    'split_count': split_count,
                    'join_count': join_count,
                    'is_balanced': True
                }
                balanced_processes.append(balanced_process)
                
                logger.info(f"  Balanced process found: Split->Join with {split_count} splits and {join_count} joins")
        
        return balanced_processes
    
    def _find_all_paths_from_split(self, split_id: str, max_depth: int = 15) -> List[Dict]:
        """Find all possible paths from a split node using DFS"""
        all_paths = []
        
        def dfs_paths(current_id: str, path: List[str], visited_in_path: Set[str], depth: int):
            if depth > max_depth or current_id in visited_in_path:
                return
            
            visited_in_path.add(current_id)
            path.append(current_id)
            
            # Find all outgoing relationships
            outgoing_rels = []
            for rel in self.graph_data['relationships']:
                if rel['source_id'] == current_id:
                    outgoing_rels.append(rel)
            
            # Check if current node leads to a join
            join_found = False
            for rel in outgoing_rels:
                if '_JOIN' in rel['rel_type']:
                    target_id = rel['target_id']
                    if target_id in self.graph_data['nodes']:
                        node_name = self.graph_data['nodes'][target_id]['properties'].get('name', '')
                        if node_name != 'End':
                            complete_path = path + [target_id]
                            path_info = {
                                'path': complete_path.copy(),
                                'join_id': target_id,
                                'join_type': rel['rel_type'],
                                'length': len(complete_path),
                                'splits_in_path': [node for node in complete_path if self._is_split_node(node)],
                                'joins_in_path': [node for node in complete_path if self._is_join_node(node)]
                            }
                            all_paths.append(path_info)
                            join_found = True
            
            # Continue DFS if no join found
            if not join_found:
                for rel in outgoing_rels:
                    if '_JOIN' not in rel['rel_type']:
                        target_id = rel['target_id']
                        dfs_paths(target_id, path.copy(), visited_in_path.copy(), depth + 1)
        
        # Start DFS from split node
        dfs_paths(split_id, [], set(), 0)
        return all_paths
    
    def _is_split_node(self, node_id: str) -> bool:
        """Check if a node is a split gateway"""
        for rel in self.graph_data['relationships']:
            if rel['source_id'] == node_id and '_SPLIT' in rel['rel_type']:
                return True
        return False
    
    def _is_join_node(self, node_id: str) -> bool:
        """Check if a node is a join gateway"""
        for rel in self.graph_data['relationships']:
            if rel['target_id'] == node_id and '_JOIN' in rel['rel_type']:
                return True
        return False
    
    def _count_splits_in_paths(self, paths: List[Dict]) -> int:
        """Count total number of splits in all paths"""
        all_splits = set()
        for path in paths:
            all_splits.update(path['splits_in_path'])
        return len(all_splits)
    
    def _count_joins_in_paths(self, paths: List[Dict]) -> int:
        """Count total number of joins in all paths"""
        all_joins = set()
        for path in paths:
            all_joins.update(path['joins_in_path'])
        return len(all_joins)
    
    def _get_join_type_from_paths(self, paths: List[Dict]) -> str:
        """Get join type from the first path that reaches the join"""
        if paths:
            return paths[0]['join_type']
        return 'UNKNOWN_JOIN'
    
    def _analyze_split_join_path(self, split_id: str, join_id: str) -> Dict:
        """Analyze the path between split and join nodes"""
        # Count tasks and gateways in between
        tasks_count = 0
        gateways_count = 0
        sql_tasks = []
        
        # Simple path analysis (can be enhanced with more sophisticated graph traversal)
        visited = set()
        queue = deque([split_id])
        
        while queue:
            current_id = queue.popleft()
            if current_id in visited or current_id == join_id:
                continue
            visited.add(current_id)
            
            if current_id in self.graph_data['nodes']:
                node_data = self.graph_data['nodes'][current_id]
                labels = node_data['labels']
                
                if 'Task' in labels:
                    tasks_count += 1
                    if current_id in self.sql_resources:
                        sql_tasks.append(self.sql_resources[current_id]['name'])
                elif 'Gateway' in labels:
                    gateways_count += 1
        
        return {
            'tasks_count': tasks_count,
            'gateways_count': gateways_count,
            'sql_tasks': sql_tasks,
            'path_complexity': tasks_count + gateways_count
        }
    
    def _generate_structural_recommendation(self, combination: Tuple[str, str]) -> str:
        """Generate recommendations for structural deadlocks"""
        split_type, join_type = combination
        
        recommendations = {
            ('AND_SPLIT', 'OR_JOIN'): 'Replace OR-join with AND-join to wait for all parallel paths',
            ('AND_SPLIT', 'XOR_JOIN'): 'Replace XOR-join with AND-join to accept all parallel tokens',
            ('OR_SPLIT', 'AND_JOIN'): 'Replace AND-join with OR-join or ensure all paths are always activated',
            ('XOR_SPLIT', 'AND_JOIN'): 'Replace AND-join with XOR-join to match single path activation'
        }
        
        return recommendations.get(combination, 'Review gateway combination for proper flow semantics')
    
    def detect_deadlocks(self) -> List[Dict]:
        """Main deadlock detection method - combines SQL and structural deadlock detection"""
        logger.info("Starting comprehensive deadlock detection...")
        
        all_deadlocks = []
        
        # Step 1: Detect structural deadlocks
        structural_deadlocks = self.detect_structural_deadlocks()
        all_deadlocks.extend(structural_deadlocks)
        logger.info(f"Found {len(structural_deadlocks)} structural deadlocks")
        
        # Step 2: Build resource dependency graph
        self.build_resource_dependency_graph()
        logger.info(f"Found {len(self.sql_resources)} SQL-enabled nodes")
        
        # Step 3: Build wait-for graph
        self.build_wait_for_graph()
        logger.info(f"Built wait-for graph with {len(self.wait_for_graph.nodes())} nodes")
        
        # Step 4: Find strongly connected components (potential SQL deadlocks)
        sccs = self.tarjan_scc()
        logger.info(f"Found {len(sccs)} strongly connected components")
        
        # Step 5: Analyze each SCC for deadlock characteristics
        sql_deadlocks = []
        for i, scc in enumerate(sccs):
            deadlock_info = self._analyze_scc_deadlock(scc, i)
            if deadlock_info:
                sql_deadlocks.append(deadlock_info)
        
        all_deadlocks.extend(sql_deadlocks)
        logger.info(f"Found {len(sql_deadlocks)} SQL resource deadlocks")
        
        self.deadlock_risks = all_deadlocks
        return all_deadlocks
    
    def _analyze_scc_deadlock(self, scc: List[str], scc_id: int) -> Optional[Dict]:
        """Analyze a strongly connected component for deadlock characteristics"""
        if len(scc) < 2:
            return None
            
        print(f"\n🔍 DEBUG: Analyzing SCC {scc_id} with {len(scc)} nodes: {scc}")
        
        # Get resource conflicts within the SCC
        conflicts = []
        tables_involved = set()
        operations_involved = set()
        conflict_details = []
        
        for i, node1 in enumerate(scc):
            for j, node2 in enumerate(scc):
                if i >= j:
                    continue
                    
                print(f"  🔎 Checking conflict between {node1} and {node2}...")
                
                if self.wait_for_graph.has_edge(node1, node2):
                    edge_data = self.wait_for_graph[node1][node2]
                    if 'conflict' in edge_data:
                        conflict = edge_data['conflict']
                        
                        # Debug: Show detailed conflict information
                        node1_name = self.sql_resources.get(node1, {}).get('name', node1)
                        node2_name = self.sql_resources.get(node2, {}).get('name', node2)
                        
                        print(f"    ⚠️  CONFLICT FOUND: {node1_name} ↔ {node2_name}")
                        print(f"       Tables: {conflict.get('table_conflicts', set())}")
                        print(f"       Columns: {conflict.get('column_conflicts', set())}")
                        print(f"       Operations: {conflict.get('operation_conflicts', [])}")
                        
                        conflicts.append({
                            'node1': node1,
                            'node2': node2,
                            'node1_name': node1_name,
                            'node2_name': node2_name,
                            'conflict': conflict
                        })
                        
                        # Store detailed conflict information
                        conflict_details.append({
                            'pair': f"{node1_name} ↔ {node2_name}",
                            'tables': list(conflict.get('table_conflicts', set())),
                            'columns': list(conflict.get('column_conflicts', set())),
                            'operations': conflict.get('operation_conflicts', [])
                        })
                        
                        tables_involved.update(conflict.get('table_conflicts', set()))
                        
                        # Get operations from both nodes
                        if node1 in self.sql_resources:
                            operations_involved.update(self.sql_resources[node1]['resources']['operations'])
                        if node2 in self.sql_resources:
                            operations_involved.update(self.sql_resources[node2]['resources']['operations'])
                else:
                    print(f"    ✅ No conflict between {node1} and {node2}")
        
        if not conflicts:
            print(f"  ❌ No conflicts found in SCC {scc_id}")
            return None
            
        # Calculate severity
        severity = self._calculate_deadlock_severity(scc, conflicts, operations_involved)
        
        # Only include nodes that actually have conflicts (deadlocked nodes)
        deadlocked_nodes = set()
        for conflict in conflicts:
            deadlocked_nodes.add(conflict['node1'])
            deadlocked_nodes.add(conflict['node2'])
        
        # If no conflicts found, include all SCC nodes as fallback
        if not deadlocked_nodes:
            deadlocked_nodes = set(scc)
        
        # Debug summary
        print(f"\n📊 DEADLOCK SUMMARY for SCC {scc_id}:")
        print(f"   Total conflicts found: {len(conflicts)}")
        print(f"   Deadlocked nodes: {len(deadlocked_nodes)}")
        print(f"   Node names: {[self.sql_resources.get(node, {}).get('name', node) for node in deadlocked_nodes]}")
        print(f"   Tables involved: {list(tables_involved)}")
        print(f"   Operations: {list(operations_involved)}")
        print(f"   Severity: {severity}")
        
        print(f"\n🔗 CONFLICT COMBINATIONS:")
        for detail in conflict_details:
            print(f"   • {detail['pair']}")
            if detail['tables']:
                print(f"     Tables: {detail['tables']}")
            if detail['columns']:
                print(f"     Columns: {detail['columns']}")
            if detail['operations']:
                print(f"     Operations: {detail['operations']}")
        
        return {
            'type': 'SQL Resource Deadlock',
            'scc_id': scc_id,
            'nodes_involved': list(deadlocked_nodes),
            'node_names': [self.sql_resources[node]['name'] for node in deadlocked_nodes if node in self.sql_resources],
            'tables_involved': list(tables_involved),
            'operations_involved': list(operations_involved),
            'conflicts': conflicts,
            'conflict_details': conflict_details,
            'severity': severity,
            'description': f"Circular dependency detected among {len(deadlocked_nodes)} SQL tasks involving tables: {', '.join(tables_involved)}",
            'recommendation': self._generate_recommendation(conflicts, operations_involved)
        }
    
    def _calculate_deadlock_severity(self, scc: List[str], conflicts: List[Dict], operations: Set[str]) -> str:
        """Calculate deadlock severity based on various factors"""
        score = 0
        
        # Factor 1: Number of nodes in cycle
        score += len(scc) * 10
        
        # Factor 2: Type of operations
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        if operations.intersection(write_ops):
            score += 30
        
        # Factor 3: Number of conflicts
        score += len(conflicts) * 15
        
        # Factor 4: Table conflicts vs column conflicts
        for conflict in conflicts:
            if conflict['conflict']['table_conflicts']:
                score += 20
            if conflict['conflict']['column_conflicts']:
                score += 10
        
        if score >= 80:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_recommendation(self, conflicts: List[Dict], operations: Set[str]) -> str:
        """Generate enhanced recommendations for resolving deadlocks with consistent resource ordering"""
        recommendations = []
        
        # Extract table names from conflicts for ordering
        tables_involved = set()
        for conflict in conflicts:
            if 'conflict' in conflict and conflict['conflict']:
                tables_involved.update(conflict['conflict'].get('table_conflicts', set()))
        
        # Primary recommendations for consistent resource ordering
        if tables_involved:
            sorted_tables = sorted(list(tables_involved))  # Alphabetical ordering
            recommendations.append(f"Implement consistent resource ordering: Access tables in this order: {' -> '.join(sorted_tables)}")
        
        write_ops = {'UPDATE', 'INSERT', 'DELETE'}
        if operations.intersection(write_ops):
            recommendations.append("Use explicit locking with UPDLOCK hints: SELECT * FROM table WITH (UPDLOCK, HOLDLOCK)")
            recommendations.append("Apply table-level locking hierarchy to prevent circular waits")
        
        if 'UPDATE' in operations:
            recommendations.append("Use MERGE statements with consistent table access order")
            recommendations.append("Implement SELECT FOR UPDATE pattern with ordered resource acquisition")
        
        if len(conflicts) > 2:
            recommendations.append("Break complex transactions: Separate read and write operations")
            recommendations.append("Use transaction isolation levels (READ_COMMITTED_SNAPSHOT)")
        
        # Advanced deadlock prevention strategies
        recommendations.append("Implement deadlock detection with immediate rollback")
        recommendations.append("Use timeout mechanisms (SET LOCK_TIMEOUT 5000)")
        recommendations.append("Apply retry logic with exponential backoff (max 3 retries)")
        
        return "; ".join(recommendations)
    
    def generate_report(self) -> Dict:
        """Generate focused deadlock detection report - only deadlocked nodes"""
        all_deadlocks = self.detect_deadlocks()
        
        # Separate deadlocks by type
        structural_deadlocks = [d for d in all_deadlocks if d['type'] in ['Structural Deadlock', 'Potential Race Condition']]
        sql_deadlocks = [d for d in all_deadlocks if d['type'] == 'SQL Resource Deadlock']
        
        # Extract only deadlocked nodes (focus on deadlock participants only)
        deadlocked_nodes = set()
        for deadlock in all_deadlocks:
            if 'nodes_involved' in deadlock:
                deadlocked_nodes.update(deadlock['nodes_involved'])
            elif 'split_id' in deadlock and 'join_id' in deadlock:
                deadlocked_nodes.add(deadlock['split_id'])
                deadlocked_nodes.add(deadlock['join_id'])
        
        # Filter graph data to include only deadlocked nodes and their direct relationships
        filtered_graph = self._filter_graph_to_deadlocked_nodes(deadlocked_nodes)
        
        return {
            'summary': {
                'total_nodes_analyzed': len(self.graph_data['nodes']) if self.graph_data else 0,
                'deadlocked_nodes_only': len(deadlocked_nodes),
                'total_sql_nodes': len(self.sql_resources),
                'total_deadlocks': len(all_deadlocks),
                'structural_deadlocks': len(structural_deadlocks),
                'sql_resource_deadlocks': len(sql_deadlocks),
                'severity_breakdown': self._get_severity_breakdown(all_deadlocks)
            },
            'deadlocked_nodes_focus': list(deadlocked_nodes),
            'filtered_graph': filtered_graph,
            'structural_deadlocks': structural_deadlocks,
            'sql_resource_deadlocks': sql_deadlocks,
            'all_deadlocks': all_deadlocks,
            'graph_statistics': {
                'total_nodes': len(self.graph_data['nodes']) if self.graph_data else 0,
                'total_relationships': len(self.graph_data['relationships']) if self.graph_data else 0,
                'deadlocked_nodes': len(deadlocked_nodes),
                'filtered_relationships': len(filtered_graph.get('relationships', [])),
                'wait_for_graph_nodes': len(self.wait_for_graph.nodes()),
                'wait_for_graph_edges': len(self.wait_for_graph.edges()),
                'resource_graph_nodes': len(self.resource_graph.nodes())
            },
            'analysis_methods': {
                'focus_strategy': 'Deadlocked nodes only - excluding non-participating relationships',
                'structural_analysis': 'Gateway combination pattern matching',
                'sql_analysis': 'Tarjan\'s strongly connected components algorithm',
                'resource_extraction': 'Automated SQL parsing and resource identification',
                'topology_analysis': 'Graph traversal and dependency mapping'
            }
        }
    
    def _get_severity_breakdown(self, deadlocks: List[Dict]) -> Dict:
        """Get breakdown of deadlocks by severity"""
        breakdown = {'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0}
        for deadlock in deadlocks:
            severity = deadlock.get('severity', 'LOW')
            breakdown[severity] += 1
        return breakdown
    
    def _filter_graph_to_deadlocked_nodes(self, deadlocked_nodes: set) -> Dict:
        """Filter graph data to include only deadlocked nodes and their direct relationships"""
        if not self.graph_data or not deadlocked_nodes:
            return {'nodes': {}, 'relationships': []}
        
        # Filter nodes - only include deadlocked nodes
        # Note: self.graph_data['nodes'] is a dictionary with node_id as keys
        filtered_nodes = {}
        nodes_dict = self.graph_data.get('nodes', {})
        for node_id, node_data in nodes_dict.items():
            if node_id in deadlocked_nodes:
                filtered_nodes[node_id] = node_data
        
        # Filter relationships - only include relationships between deadlocked nodes
        filtered_relationships = []
        for rel in self.graph_data.get('relationships', []):
            start_node = rel.get('source_id')
            end_node = rel.get('target_id')
            
            # Include relationship only if both nodes are in deadlocked set
            if start_node in deadlocked_nodes and end_node in deadlocked_nodes:
                filtered_relationships.append(rel)
        
        return {
            'nodes': filtered_nodes,
            'relationships': filtered_relationships,
            'deadlock_focus': True,
            'original_node_count': len(self.graph_data.get('nodes', {})),
            'filtered_node_count': len(filtered_nodes),
            'original_relationship_count': len(self.graph_data.get('relationships', [])),
            'filtered_relationship_count': len(filtered_relationships)
        }


def main():
    """Example usage of SQLDeadlockDetector"""
    # Try to import configuration from config_deadlock.py
    try:
        import sys
        import os
        # Add parent directory to path to import config_deadlock
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.append(parent_dir)
        
        from config_deadlock import NEO4J_CONFIG
        NEO4J_URI = NEO4J_CONFIG['uri']
        NEO4J_USER = NEO4J_CONFIG['user']
        NEO4J_PASSWORD = NEO4J_CONFIG['password']
        NEO4J_DATABASE = NEO4J_CONFIG.get('database', 'neo4j')
        print(f"✅ Loaded configuration from config_deadlock.py")
        print(f"   URI: {NEO4J_URI}")
        print(f"   User: {NEO4J_USER}")
        print(f"   Database: {NEO4J_DATABASE}")
    except ImportError:
        # Fallback to manual configuration
        print("⚠️  Could not import config_deadlock.py, using manual configuration")
        NEO4J_URI = "bolt://localhost:7687"
        NEO4J_USER = "neo4j"
        NEO4J_PASSWORD = "12345678"  # Updated to match your working config
        NEO4J_DATABASE = "neo4j"
    
    # Initialize detector
    detector = SQLDeadlockDetector(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD, NEO4J_DATABASE)
    
    try:
        # Generate comprehensive report
        report = detector.generate_report()
        
        # Print header
        print("\n" + "="*80)
        print("    COMPREHENSIVE BPMN DEADLOCK DETECTION REPORT")
        print("    Using Tarjan's Algorithm + Structural Analysis")
        print("="*80)
        
        # Print summary
        summary = report['summary']
        print(f"\n📊 ANALYSIS SUMMARY:")
        print(f"   • Total Nodes Analyzed: {summary['total_nodes_analyzed']}")
        print(f"   • SQL-Enabled Nodes: {summary['total_sql_nodes']}")
        print(f"   • Total Deadlocks Found: {summary['total_deadlocks']}")
        print(f"   • Structural Deadlocks: {summary['structural_deadlocks']}")
        print(f"   • SQL Resource Deadlocks: {summary['sql_resource_deadlocks']}")
        print(f"   • Severity Breakdown: {summary['severity_breakdown']}")
        
        # Print analysis methods
        methods = report['analysis_methods']
        print(f"\n🔬 ANALYSIS METHODS:")
        for method, description in methods.items():
            print(f"   • {method.replace('_', ' ').title()}: {description}")
        
        # Print graph statistics
        stats = report['graph_statistics']
        print(f"\n📈 GRAPH STATISTICS:")
        print(f"   • Total Nodes: {stats['total_nodes']}")
        print(f"   • Total Relationships: {stats['total_relationships']}")
        print(f"   • Wait-for Graph Nodes: {stats['wait_for_graph_nodes']}")
        print(f"   • Wait-for Graph Edges: {stats['wait_for_graph_edges']}")
        print(f"   • Resource Graph Nodes: {stats['resource_graph_nodes']}")
        
        # Print structural deadlocks
        if report['structural_deadlocks']:
            print(f"\n🚨 STRUCTURAL DEADLOCKS ({len(report['structural_deadlocks'])})")
            print("-" * 60)
            for i, deadlock in enumerate(report['structural_deadlocks'], 1):
                print(f"\n[{i}] {deadlock['type']} - {deadlock['severity']}")
                print(f"    Split Gateway: {deadlock.get('split_node', 'N/A')} ({deadlock.get('split_type', 'N/A')})")
                print(f"    Join Gateway: {deadlock.get('join_node', 'N/A')} ({deadlock.get('join_type', 'N/A')})")
                print(f"    Description: {deadlock.get('description', 'N/A')}")
                print(f"    Recommendation: {deadlock.get('recommendation', 'N/A')}")
                
                # Safe access to path_info
                path_info = deadlock.get('path_info', {})
                if path_info:
                    tasks_count = path_info.get('tasks_count', 0)
                    gateways_count = path_info.get('gateways_count', 0)
                    sql_tasks = path_info.get('sql_tasks', [])
                    
                    print(f"    Path Info: {tasks_count} tasks, {gateways_count} gateways")
                    if sql_tasks:
                        print(f"    SQL Tasks: {', '.join(sql_tasks)}")
                else:
                    print(f"    Path Info: Not available")
        
        # Print SQL resource deadlocks
        if report['sql_resource_deadlocks']:
            print(f"\n💾 SQL RESOURCE DEADLOCKS ({len(report['sql_resource_deadlocks'])})")
            print("-" * 60)
            for i, deadlock in enumerate(report['sql_resource_deadlocks'], 1):
                print(f"\n[{i}] {deadlock['type']} - {deadlock['severity']}")
                if 'node_names' in deadlock:
                    print(f"    Nodes: {', '.join(deadlock['node_names'])}")
                if 'tables_involved' in deadlock:
                    print(f"    Tables: {', '.join(deadlock['tables_involved'])}")
                if 'operations_involved' in deadlock:
                    print(f"    Operations: {', '.join(deadlock['operations_involved'])}")
                print(f"    Description: {deadlock['description']}")
                print(f"    Recommendation: {deadlock['recommendation']}")
        
        # Print conclusion
        if summary['total_deadlocks'] == 0:
            print(f"\n✅ CONCLUSION: No deadlocks detected in the BPMN flow!")
        else:
            critical_count = summary['severity_breakdown'].get('CRITICAL', 0)
            high_count = summary['severity_breakdown'].get('HIGH', 0)
            if critical_count > 0 or high_count > 0:
                print(f"\n⚠️  CONCLUSION: {critical_count + high_count} high-priority deadlocks require immediate attention!")
            else:
                print(f"\n⚡ CONCLUSION: {summary['total_deadlocks']} potential deadlocks detected. Review recommendations.")
        
        print("\n" + "="*80)
            
    except Exception as e:
        print(f"\n❌ Error during analysis: {e}")
        logger.error(f"Analysis failed: {e}")
    finally:
        detector.close()
        print("\n🔌 Neo4j connection closed.")


if __name__ == "__main__":
    main()