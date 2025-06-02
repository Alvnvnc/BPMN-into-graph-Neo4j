from typing import List, Dict, Set, Optional
from neo4j import GraphDatabase
from config import load_config
import logging
import re
import json
from datetime import datetime

# Configure logging to see output
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SQLDeadlockDetector:
    def __init__(self, config: Dict):
        try:
            self.driver = GraphDatabase.driver(
                config['neo4j_uri'], 
                auth=(config['neo4j_user'], config['neo4j_password'])
            )
            logger.info("Successfully connected to Neo4j")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
        self.resource_waits: Dict[str, Set[str]] = {}
        self.resource_locks: Dict[str, Dict[str, str]] = {}  # resource -> {node_id: lock_type}
        self.transaction_order: Dict[str, int] = {}  # node execution order
        self.deadlock_cycles: List[List[str]] = []
        self.node_details: Dict[str, Dict] = {}
        self.bpmn_relationships: List[Dict] = []  # Store BPMN flow relationships
        self.execution_paths: Dict[str, List[str]] = {}  # Track possible execution paths

    def fetch_sql_nodes(self) -> List[Dict]:
        with self.driver.session() as session:
            result = session.run("""
                MATCH (n)
                WHERE n.SQL IS NOT NULL
                RETURN n.id AS node_id, n.SQL AS sql, n.name AS name
            """)
            nodes = [record.data() for record in result]
            logger.info(f"Found {len(nodes)} SQL nodes")
            
            # Debug: Print first few nodes
            for i, node in enumerate(nodes[:3]):
                logger.info(f"Node {i+1}: {node}")
            
            for node in nodes:
                self.node_details[node['node_id']] = {
                    'name': node.get('name', 'Unknown'),
                    'sql': node['sql']
                }
            return nodes

    def extract_resources(self, sql_script: str) -> Set[str]:
        # Clean SQL and fix common formatting issues
        sql_clean = re.sub(r'\s+', ' ', sql_script.strip())
        
        # Fix malformed SQL where table names are concatenated with SET (e.g., "PurchaseOrdersSET")
        sql_clean = re.sub(r'(\w+)SET\s+', r'\1 SET ', sql_clean, flags=re.IGNORECASE)
        
        # Improved patterns that properly handle SQL keywords
        patterns = [
            r"UPDATE\s+([\w\.]+)(?:\s+SET|\s|$)",  # UPDATE table SET - stop before SET
            r"INSERT\s+INTO\s+([\w\.]+)",          # INSERT INTO table
            r"DELETE\s+FROM\s+([\w\.]+)",          # DELETE FROM table
            r"FROM\s+([\w\.]+)(?:\s+WHERE|\s+JOIN|\s+ORDER|\s+GROUP|\s|$)",  # FROM table - stop before keywords
            r"JOIN\s+([\w\.]+)(?:\s+ON|\s+WHERE|\s|$)",   # JOIN table - stop before ON/WHERE
        ]
        
        tables = set()
        for pattern in patterns:
            matches = re.findall(pattern, sql_clean, re.IGNORECASE)
            for match in matches:
                table = match.strip()
                # Additional filtering for false positives
                if table and not table.upper() in ['GETDATE', 'VALUES', 'SELECT', 'WHERE', 'AND', 'OR', 'YEAR', 'SET', 'ON']:
                    tables.add(table)
        
        # Debug logging
        logger.debug(f"Original SQL: {sql_script[:100]}...")
        logger.debug(f"Cleaned SQL: {sql_clean[:100]}...")
        logger.debug(f"Extracted tables: {tables}")
        return tables

    def analyze_sql_operation(self, sql_script: str) -> Dict[str, str]:
        """Analyze SQL to determine operation type and lock requirements"""
        sql_clean = re.sub(r'\s+', ' ', sql_script.strip().upper())
        
        operations = {
            'SELECT': 'SHARED',
            'INSERT': 'EXCLUSIVE', 
            'UPDATE': 'EXCLUSIVE',
            'DELETE': 'EXCLUSIVE'
        }
        
        # Determine primary operation
        for op, lock_type in operations.items():
            if sql_clean.startswith(op):
                return {'operation': op, 'lock_type': lock_type}
        
        # Check for mixed operations (like SELECT within UPDATE)
        if 'UPDATE' in sql_clean or 'INSERT' in sql_clean or 'DELETE' in sql_clean:
            return {'operation': 'WRITE', 'lock_type': 'EXCLUSIVE'}
        elif 'SELECT' in sql_clean:
            return {'operation': 'READ', 'lock_type': 'SHARED'}
        
        return {'operation': 'UNKNOWN', 'lock_type': 'SHARED'}

    def extract_resources_with_locks(self, sql_script: str) -> Dict[str, str]:
        """Extract resources and their required lock types"""
        # Clean SQL and normalize whitespace
        sql_clean = re.sub(r'\s+', ' ', sql_script.strip())
        
        # Fix malformed SQL where table names are concatenated with SET (e.g., "PurchaseOrdersSET")
        sql_clean = re.sub(r'(\w+)SET\s+', r'\1 SET ', sql_clean, flags=re.IGNORECASE)
        
        # Use the same improved patterns as extract_resources
        patterns = [
            r"UPDATE\s+([\w\.]+)(?:\s+SET|\s|$)",  # UPDATE table SET - stop before SET
            r"INSERT\s+INTO\s+([\w\.]+)",          # INSERT INTO table
            r"DELETE\s+FROM\s+([\w\.]+)",          # DELETE FROM table
            r"FROM\s+([\w\.]+)(?:\s+WHERE|\s+JOIN|\s+ORDER|\s+GROUP|\s|$)",  # FROM table - stop before keywords
            r"JOIN\s+([\w\.]+)(?:\s+ON|\s+WHERE|\s|$)",   # JOIN table - stop before ON/WHERE
        ]
        
        resources = {}
        operation_info = self.analyze_sql_operation(sql_script)
        
        for pattern in patterns:
            matches = re.findall(pattern, sql_clean, re.IGNORECASE)
            for match in matches:
                table = match.strip()
                # Additional filtering for false positives
                if table and not table.upper() in ['GETDATE', 'VALUES', 'SELECT', 'WHERE', 'AND', 'OR', 'YEAR', 'SET', 'ON']:
                    resources[table] = operation_info['lock_type']
                    logger.debug(f"Resource found: {table} -> {operation_info['lock_type']}")
        
        return resources

    def detect_lock_conflicts(self, resource: str, requesting_node: str, requesting_lock: str) -> List[str]:
        """Detect which nodes would conflict with the requesting lock"""
        conflicts = []
        
        if resource not in self.resource_locks:
            return conflicts
            
        for holding_node, holding_lock in self.resource_locks[resource].items():
            if holding_node == requesting_node:
                continue
                
            # Lock conflict rules:
            # SHARED-SHARED: No conflict
            # SHARED-EXCLUSIVE: Conflict
            # EXCLUSIVE-SHARED: Conflict  
            # EXCLUSIVE-EXCLUSIVE: Conflict
            if (requesting_lock == 'EXCLUSIVE' or holding_lock == 'EXCLUSIVE'):
                conflicts.append(holding_node)
                
        return conflicts

    def load_bpmn_flow_data(self, bpmn_file_path: str = "bpmn_flow_analysis.json") -> None:
        """Load BPMN flow data to understand process execution patterns"""
        try:
            with open(bpmn_file_path, 'r') as f:
                bpmn_data = json.load(f)
                
            self.bpmn_relationships = bpmn_data.get('relationships', [])
            
            # Build execution order based on BPMN flow
            self.build_execution_order_from_bpmn()
            logger.info(f"Loaded {len(self.bpmn_relationships)} BPMN relationships")
            
        except FileNotFoundError:
            logger.warning(f"BPMN flow file not found: {bpmn_file_path}")
        except Exception as e:
            logger.error(f"Error loading BPMN data: {e}")

    def build_execution_order_from_bpmn(self) -> None:
        """Build realistic execution order based on BPMN sequence flows"""
        # Create adjacency list from BPMN relationships
        flow_graph = {}
        for rel in self.bpmn_relationships:
            if rel['relationship'] == 'Sequence':
                source = rel['source_id']
                target = rel['target_id']
                if source not in flow_graph:
                    flow_graph[source] = []
                flow_graph[source].append(target)
        
        # Find execution paths that could run concurrently
        self.find_concurrent_execution_paths(flow_graph)
        
        logger.info(f"Found {len(self.execution_paths)} potential concurrent execution paths")

    def find_concurrent_execution_paths(self, flow_graph: Dict[str, List[str]]) -> None:
        """Identify nodes that could execute concurrently and cause resource conflicts"""
        # Look for parallel splits and joins - ONLY AND_SPLIT creates concurrency
        parallel_branches = {}
        
        for rel in self.bpmn_relationships:
            # Only AND_SPLIT creates true concurrent execution
            if 'AND_SPLIT' in rel['relationship']:
                gateway_id = rel['properties'].get('gateway_id')
                if gateway_id not in parallel_branches:
                    parallel_branches[gateway_id] = {'branches': [], 'type': rel['relationship']}
                parallel_branches[gateway_id]['branches'].append(rel['target_id'])
                
        logger.info(f"Found {len(parallel_branches)} parallel gateways (AND_SPLIT only)")
        
        # For each parallel branch, trace execution paths
        for gateway_id, branch_info in parallel_branches.items():
            if len(branch_info['branches']) > 1:
                logger.info(f"Found concurrent execution (AND_SPLIT): {branch_info['branches']}")
                # These branches can execute concurrently
                for i, branch1 in enumerate(branch_info['branches']):
                    for branch2 in branch_info['branches'][i+1:]:
                        path1 = self.trace_execution_path(branch1, flow_graph)
                        path2 = self.trace_execution_path(branch2, flow_graph)
                        
                        # Store concurrent paths for deadlock analysis
                        if branch1 not in self.execution_paths:
                            self.execution_paths[branch1] = path1
                        if branch2 not in self.execution_paths:
                            self.execution_paths[branch2] = path2

    def trace_execution_path(self, start_node: str, flow_graph: Dict[str, List[str]], 
                           visited: Set[str] = None, max_depth: int = 10) -> List[str]:
        """Trace execution path from a starting node"""
        if visited is None:
            visited = set()
        
        if start_node in visited or max_depth <= 0:
            return [start_node]
        
        visited.add(start_node)
        path = [start_node]
        
        if start_node in flow_graph:
            for next_node in flow_graph[start_node]:
                if next_node not in visited:
                    sub_path = self.trace_execution_path(next_node, flow_graph, visited.copy(), max_depth - 1)
                    path.extend(sub_path[1:])  # Exclude duplicate start node
                    break  # Take first path for simplicity
        
        return path

    def analyze_concurrent_resource_conflicts(self, nodes: List[Dict]) -> None:
        """Analyze resource conflicts between concurrently executing paths"""
        logger.info("Analyzing concurrent resource conflicts...")
        
        # Group nodes by their resources
        resource_to_nodes = {}
        for node in nodes:
            if 'sql' not in node:
                continue
                
            node_id = node['node_id']
            resources = self.extract_resources_with_locks(node['sql'])
            logger.debug(f"Node {node_id} resources: {resources}")
            
            for resource, lock_type in resources.items():
                if resource not in resource_to_nodes:
                    resource_to_nodes[resource] = []
                resource_to_nodes[resource].append({
                    'node_id': node_id,
                    'lock_type': lock_type,
                    'sql': node['sql']
                })
        
        logger.info(f"Found {len(resource_to_nodes)} unique resources")
        
        # Check for conflicts between concurrent execution paths
        conflicts_found = 0
        for path_start, execution_path in self.execution_paths.items():
            for other_path_start, other_execution_path in self.execution_paths.items():
                if path_start >= other_path_start:  # Avoid duplicate checks
                    continue
                
                # Check if these paths access common resources with conflicting locks
                conflicts = self.find_path_conflicts(execution_path, other_execution_path, resource_to_nodes)
                
                if conflicts:
                    conflicts_found += len(conflicts)
                    logger.warning(f"Potential deadlock between paths starting at {path_start} and {other_path_start}")
                    logger.warning(f"Conflicting resources: {[c['resource'] for c in conflicts]}")
                    
                    # Create wait relationships for conflicting nodes
                    self.create_realistic_wait_relationships(conflicts)
        
        logger.info(f"Total conflicts found: {conflicts_found}")

    def find_path_conflicts(self, path1: List[str], path2: List[str], 
                          resource_to_nodes: Dict[str, List[Dict]]) -> List[Dict]:
        """Find resource conflicts between two execution paths"""
        conflicts = []
        
        # Check each resource for conflicts between the two paths
        for resource, accessing_nodes in resource_to_nodes.items():
            path1_nodes = [n for n in accessing_nodes if n['node_id'] in path1]
            path2_nodes = [n for n in accessing_nodes if n['node_id'] in path2]
            
            if path1_nodes and path2_nodes:
                # Check for lock conflicts
                for node1 in path1_nodes:
                    for node2 in path2_nodes:
                        if (node1['lock_type'] == 'EXCLUSIVE' or node2['lock_type'] == 'EXCLUSIVE'):
                            conflicts.append({
                                'resource': resource,
                                'node1': node1,
                                'node2': node2,
                                'conflict_type': f"{node1['lock_type']}-{node2['lock_type']}"
                            })
        
        return conflicts

    def create_realistic_wait_relationships(self, conflicts: List[Dict]) -> None:
        """Create wait relationships based on realistic execution scenarios"""
        logger.info(f"Creating wait relationships for {len(conflicts)} conflicts...")
        
        for conflict in conflicts:
            node1_id = conflict['node1']['node_id']
            node2_id = conflict['node2']['node_id']
            resource = conflict['resource']
            
            # Create bidirectional wait relationship (potential deadlock)
            self.resource_waits.setdefault(node1_id, set()).add(node2_id)
            self.resource_waits.setdefault(node2_id, set()).add(node1_id)
            
            node1_name = self.node_details.get(node1_id, {}).get('name', node1_id)
            node2_name = self.node_details.get(node2_id, {}).get('name', node2_id)
            
            logger.info(f"Created wait relationship: '{node1_name}' <-> '{node2_name}' on resource '{resource}'")
            logger.info(f"  Conflict type: {conflict['conflict_type']}")

    def build_waits_graph(self, nodes: List[Dict]) -> None:
        logger.info("Building sophisticated waits graph based on BPMN flow and lock conflicts...")
        
        # Load BPMN flow data first
        self.load_bpmn_flow_data()
        
        # Build resource locks mapping for traditional analysis
        for i, node in enumerate(nodes):
            self.transaction_order[node['node_id']] = i
            node_id = node['node_id']
            resources_with_locks = self.extract_resources_with_locks(node['sql'])
            
            for resource, lock_type in resources_with_locks.items():
                if resource not in self.resource_locks:
                    self.resource_locks[resource] = {}
                self.resource_locks[resource][node_id] = lock_type
        
        # Analyze concurrent resource conflicts based on BPMN flow
        self.analyze_concurrent_resource_conflicts(nodes)
        
        logger.info(f"Wait graph has {len(self.resource_waits)} nodes with dependencies")
        
        # Log detailed wait relationships with BPMN context
        for node, waits in self.resource_waits.items():
            node_name = self.node_details.get(node, {}).get('name', node)
            wait_names = [self.node_details.get(w, {}).get('name', w) for w in waits]
            logger.info(f"'{node_name}' waits for: {wait_names}")

    def detect_bpmn_based_deadlocks(self, nodes: List[Dict]) -> None:
        """Detect deadlocks based on BPMN execution patterns - only for concurrent (AND_SPLIT) branches"""
        
        # Find nodes that are in different parallel branches but access same resources
        for rel in self.bpmn_relationships:
            # Only consider AND_SPLIT for deadlock potential
            if 'AND_SPLIT' in rel['relationship']:
                gateway_id = rel['properties'].get('gateway_id')
                
                # Find all branches from this parallel gateway
                parallel_branches = []
                for other_rel in self.bpmn_relationships:
                    if (other_rel['properties'].get('gateway_id') == gateway_id and 
                        'AND_SPLIT' in other_rel['relationship']):
                        parallel_branches.append(other_rel['target_id'])
                
                # Check for resource conflicts between parallel branches
                for i, branch1_id in enumerate(parallel_branches):
                    for branch2_id in parallel_branches[i+1:]:
                        branch1_nodes = self.find_nodes_in_parallel_branch(branch1_id)
                        branch2_nodes = self.find_nodes_in_parallel_branch(branch2_id)
                        
                        # Check each combination for resource conflicts
                        for node1_id in branch1_nodes:
                            for node2_id in branch2_nodes:
                                if self.check_resource_conflict_between_nodes(node1_id, node2_id):
                                    # These nodes could deadlock if they execute concurrently
                                    self.resource_waits.setdefault(node1_id, set()).add(node2_id)
                                    self.resource_waits.setdefault(node2_id, set()).add(node1_id)
                                    
                                    logger.info(f"BPMN-based deadlock risk (AND_SPLIT): {node1_id} <-> {node2_id}")

    def find_nodes_in_parallel_branch(self, start_node: str) -> List[str]:
        """Find all nodes that could execute in a parallel branch"""
        if start_node in self.execution_paths:
            return self.execution_paths[start_node]
        return [start_node]

    def check_resource_conflict_between_nodes(self, node1_id: str, node2_id: str) -> bool:
        """Check if two nodes have conflicting resource access that could cause deadlock"""
        if node1_id not in self.node_details or node2_id not in self.node_details:
            return False
        
        node1_sql = self.node_details[node1_id].get('sql', '')
        node2_sql = self.node_details[node2_id].get('sql', '')
        
        if not node1_sql or not node2_sql:
            return False
        
        resources1 = self.extract_resources_with_locks(node1_sql)
        resources2 = self.extract_resources_with_locks(node2_sql)
        
        # Check for common resources with conflicting locks
        common_resources = set(resources1.keys()) & set(resources2.keys())
        
        for resource in common_resources:
            # Deadlock potential exists when:
            # 1. Both need EXCLUSIVE locks (write-write conflict)
            # 2. One needs EXCLUSIVE and other needs SHARED (write-read conflict)
            if (resources1[resource] == 'EXCLUSIVE' and resources2[resource] == 'EXCLUSIVE'):
                logger.debug(f"Write-write conflict on {resource}: {node1_id} vs {node2_id}")
                return True
            elif (resources1[resource] == 'EXCLUSIVE' and resources2[resource] == 'SHARED') or \
                 (resources1[resource] == 'SHARED' and resources2[resource] == 'EXCLUSIVE'):
                logger.debug(f"Write-read conflict on {resource}: {node1_id} vs {node2_id}")
                return True
        
        return False

    def _tarjans_algorithm(self) -> List[List[str]]:
        index = 0
        indices: Dict[str, Optional[int]] = {}
        lowlink: Dict[str, int] = {}
        on_stack: Dict[str, bool] = {}
        stack: List[str] = []
        sccs: List[List[str]] = []

        def strongconnect(node: str):
            nonlocal index
            indices[node] = index
            lowlink[node] = index
            index += 1
            stack.append(node)
            on_stack[node] = True

            for neighbor in self.resource_waits.get(node, []):
                if indices.get(neighbor) is None:
                    strongconnect(neighbor)
                    lowlink[node] = min(lowlink[node], lowlink[neighbor])
                elif on_stack.get(neighbor, False):
                    lowlink[node] = min(lowlink[node], indices[neighbor])

            if lowlink[node] == indices[node]:
                scc: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == node:
                        break
                if len(scc) > 1:  # Hanya siklus dengan minimal 2 node
                    sccs.append(scc)

        for node in self.resource_waits:
            if indices.get(node) is None:
                strongconnect(node)
                
        return sccs

    def detect_deadlocks(self) -> bool:
        sccs = self._tarjans_algorithm()
        self.deadlock_cycles = sccs
        return len(sccs) > 0

    def generate_report(self, output_path: str = "deadlock_report.json") -> None:
        # Enhanced report with BPMN flow analysis
        resource_analysis = {}
        for resource, locks in self.resource_locks.items():
            resource_analysis[resource] = {
                'nodes_accessing': len(locks),
                'lock_types': list(set(locks.values())),
                'potential_conflicts': len(locks) > 1 and 'EXCLUSIVE' in locks.values()
            }
        
        bpmn_analysis = {
            'concurrent_paths_found': len(self.execution_paths),
            'parallel_branches_analyzed': len([r for r in self.bpmn_relationships if 'AND_SPLIT' in r['relationship']]),
            'flow_based_conflicts': len([k for k, v in self.resource_waits.items() if len(v) > 0])
        }
        
        report = {
            "analysis_summary": {
                "total_sql_nodes": len(self.node_details),
                "nodes_with_waits": len(self.resource_waits),
                "deadlock_cycles_found": len(self.deadlock_cycles),
                "resources_analyzed": len(self.resource_locks)
            },
            "bpmn_flow_analysis": bpmn_analysis,
            "resource_analysis": resource_analysis,
            "deadlocks": []
        }
        
        if not self.deadlock_cycles:
            logger.info("No deadlocks detected.")
            report["message"] = "No deadlocks detected based on BPMN flow analysis"
        else:
            for i, cycle in enumerate(self.deadlock_cycles):
                detailed_cycle = {
                    "cycle_id": i + 1,
                    "severity": "HIGH" if len(cycle) > 2 else "MEDIUM",
                    "detection_method": "BPMN Flow Analysis",
                    "nodes": []
                }
                
                for node_id in cycle:
                    node_resources = self.extract_resources_with_locks(
                        self.node_details.get(node_id, {}).get('sql', '')
                    )
                    
                    # Find BPMN context for this node
                    bpmn_context = self.get_bpmn_context(node_id)
                    
                    node_info = {
                        "node_id": node_id,
                        "name": self.node_details.get(node_id, {}).get('name', 'Unknown'),
                        "sql": self.node_details.get(node_id, {}).get('sql', ''),
                        "resources_accessed": list(node_resources.keys()),
                        "lock_types": list(node_resources.values()),
                        "bpmn_context": bpmn_context
                    }
                    detailed_cycle["nodes"].append(node_info)
                
                report["deadlocks"].append(detailed_cycle)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        logger.info(f"Enhanced BPMN-based report generated: {output_path}")
        logger.info(f"Report summary: {report['analysis_summary']}")

    def get_bpmn_context(self, node_id: str) -> Dict:
        """Get BPMN context information for a node"""
        context = {
            "incoming_flows": [],
            "outgoing_flows": [],
            "parallel_branches": []
        }
        
        for rel in self.bpmn_relationships:
            if rel['source_id'] == node_id:
                context["outgoing_flows"].append({
                    "relationship": rel['relationship'],
                    "target": rel['target_name']
                })
            elif rel['target_id'] == node_id:
                context["incoming_flows"].append({
                    "relationship": rel['relationship'],
                    "source": rel['source_name']
                })
        
        return context

    def export_deadlock_to_neo4j(self) -> None:
        """Add deadlock properties to existing Neo4j nodes (no new nodes/relationships/labels)"""
        logger.info("Adding deadlock properties to existing nodes...")
        
        try:
            with self.driver.session() as session:
                # First, clear any existing deadlock properties from all nodes
                session.run("""
                    MATCH (n) 
                    WHERE n.deadlock_detected IS NOT NULL
                    REMOVE n.deadlock_detected, n.deadlock_severity, n.deadlock_cycle_id, 
                           n.deadlock_resources, n.deadlock_lock_types, n.deadlock_context,
                           n.deadlock_wait_for, n.deadlock_detection_method, n.deadlock_detection_timestamp,
                           n.deadlock, n.deadlock_description
                """)
                logger.info("Cleared existing deadlock properties from all nodes")
                
                # Add deadlock properties only to existing nodes that are involved in deadlocks
                nodes_updated = 0
                for cycle_id, cycle in enumerate(self.deadlock_cycles):
                    severity = "HIGH" if len(cycle) > 2 else "MEDIUM"
                    
                    for node_id in cycle:
                        # Get node details for this existing node
                        node_resources = self.extract_resources_with_locks(
                            self.node_details.get(node_id, {}).get('sql', '')
                        )
                        bpmn_context = self.get_bpmn_context(node_id)
                        wait_for_nodes = list(self.resource_waits.get(node_id, set()))
                        wait_for_names = [self.node_details.get(w, {}).get('name', 'Unknown') for w in wait_for_nodes]
                        
                        # Create comprehensive deadlock information
                        deadlock_info = {
                            "detected": True,
                            "severity": severity,
                            "cycle_id": cycle_id + 1,
                            "resources": list(node_resources.keys()),
                            "lock_types": list(node_resources.values()),
                            "wait_for": wait_for_names,
                            "detection_method": "BPMN Flow Analysis",
                            "description": f"This node is involved in deadlock cycle {cycle_id + 1} with severity {severity}"
                        }
                        
                        # Add deadlock properties to existing node (no labels, no new nodes)
                        result = session.run("""
                            MATCH (n {id: $node_id})
                            SET n.deadlock_detected = $detected,
                                n.deadlock_severity = $severity,
                                n.deadlock_cycle_id = $cycle_id,
                                n.deadlock_resources = $resources,
                                n.deadlock_lock_types = $lock_types,
                                n.deadlock_context = $context,
                                n.deadlock_wait_for = $wait_for,
                                n.deadlock_detection_method = $detection_method,
                                n.deadlock_detection_timestamp = datetime(),
                                n.deadlock = $deadlock_info,
                                n.deadlock_description = $description
                            RETURN count(n) as updated
                        """, {
                            'node_id': node_id,
                            'detected': True,
                            'severity': severity,
                            'cycle_id': cycle_id + 1,
                            'resources': list(node_resources.keys()),
                            'lock_types': list(node_resources.values()),
                            'context': json.dumps(bpmn_context),
                            'wait_for': wait_for_names,
                            'detection_method': "BPMN Flow Analysis",
                            'deadlock_info': json.dumps(deadlock_info),
                            'description': f"This node is involved in deadlock cycle {cycle_id + 1} with severity {severity}. Conflicts on resources: {', '.join(node_resources.keys())}"
                        })
                        
                        updated_count = result.single()['updated']
                        if updated_count > 0:
                            nodes_updated += 1
                            logger.info(f"Added deadlock properties to existing node '{node_id}'")
                        else:
                            logger.warning(f"Node {node_id} not found in Neo4j, skipping...")
                
                logger.info(f"Successfully added deadlock properties to {nodes_updated} existing nodes in {len(self.deadlock_cycles)} cycles")
                
        except Exception as e:
            logger.error(f"Error adding deadlock properties to existing nodes: {e}")
            raise

    def query_deadlock_nodes(self) -> List[Dict]:
        """Query existing nodes that have deadlock properties (no special labels required)"""
        try:
            with self.driver.session() as session:
                result = session.run("""
                    MATCH (n)
                    WHERE n.deadlock_detected IS NOT NULL AND n.deadlock_detected = true
                    RETURN n.id as node_id, 
                           n.name as name,
                           n.SQL as sql,
                           n.deadlock_severity as severity,
                           n.deadlock_cycle_id as cycle_id,
                           n.deadlock_resources as resources,
                           n.deadlock_lock_types as lock_types,
                           n.deadlock_wait_for as wait_for,
                           n.deadlock as deadlock_info,
                           n.deadlock_description as description,
                           labels(n) as node_labels,
                           n.Time as time,
                           n.process_id as process_id,
                           n.subtype as subtype,
                           n.type as type
                    ORDER BY n.deadlock_cycle_id, n.name
                """)
                
                deadlock_nodes = [record.data() for record in result]
                logger.info(f"Retrieved {len(deadlock_nodes)} existing nodes with deadlock properties")
                return deadlock_nodes
                
        except Exception as e:
            logger.error(f"Error querying deadlock nodes: {e}")
            return []

    def generate_neo4j_export_report(self, output_path: str = "neo4j_export_report.json") -> None:
        """Generate a report of deadlock properties added to existing nodes"""
        deadlock_nodes = self.query_deadlock_nodes()
        
        export_report = {
            "export_summary": {
                "total_nodes_with_deadlock_properties": len(deadlock_nodes),
                "deadlock_cycles_detected": len(self.deadlock_cycles),
                "export_timestamp": str(datetime.now()),
                "detection_method": "BPMN Flow Analysis (AND_SPLIT only)",
                "approach": "Properties Added to Existing Nodes - No New Nodes/Relationships/Labels Created"
            },
            "nodes_with_deadlock_properties": deadlock_nodes,
            "neo4j_queries": {
                "view_nodes_with_deadlock": "MATCH (n) WHERE n.deadlock_detected = true RETURN n",
                "view_deadlock_properties_only": "MATCH (n) WHERE n.deadlock IS NOT NULL RETURN n.id, n.name, n.deadlock_description, n.deadlock_severity",
                "view_deadlock_cycles": "MATCH (n) WHERE n.deadlock_cycle_id IS NOT NULL RETURN n.deadlock_cycle_id, collect({id: n.id, name: n.name, description: n.deadlock_description, sql: substring(n.SQL, 0, 50)}) as nodes ORDER BY n.deadlock_cycle_id",
                "clear_deadlock_properties": "MATCH (n) WHERE n.deadlock_detected IS NOT NULL REMOVE n.deadlock_detected, n.deadlock_severity, n.deadlock_cycle_id, n.deadlock_resources, n.deadlock_lock_types, n.deadlock_context, n.deadlock_wait_for, n.deadlock_detection_method, n.deadlock_detection_timestamp, n.deadlock, n.deadlock_description",
                "count_nodes_with_deadlock": "MATCH (n) WHERE n.deadlock_detected = true RETURN count(n) as total"
            },
            "deadlock_statistics": {
                "nodes_by_severity": {},
                "resources_most_conflicted": {},
                "cycles_summary": []
            }
        }
        
        # Calculate statistics
        severity_count = {}
        resource_conflicts = {}
        
        for node in deadlock_nodes:
            # Count by severity
            severity = node.get('severity', 'UNKNOWN')
            severity_count[severity] = severity_count.get(severity, 0) + 1
            
            # Count resource conflicts
            resources = node.get('resources', [])
            for resource in resources:
                resource_conflicts[resource] = resource_conflicts.get(resource, 0) + 1
        
        export_report["deadlock_statistics"]["nodes_by_severity"] = severity_count
        export_report["deadlock_statistics"]["resources_most_conflicted"] = dict(
            sorted(resource_conflicts.items(), key=lambda x: x[1], reverse=True)[:5]
        )
        
        # Cycles summary
        cycles_summary = {}
        for node in deadlock_nodes:
            cycle_id = node.get('cycle_id')
            if cycle_id:
                if cycle_id not in cycles_summary:
                    cycles_summary[cycle_id] = []
                cycles_summary[cycle_id].append({
                    'node_id': node.get('node_id'),
                    'name': node.get('name'),
                    'severity': node.get('severity'),
                    'description': node.get('description'),
                    'sql': node.get('sql', '')[:100] + '...' if node.get('sql') else 'N/A',
                    'original_properties': {
                        'time': node.get('time'),
                        'process_id': node.get('process_id'),
                        'subtype': node.get('subtype'),
                        'type': node.get('type')
                    }
                })
        
        export_report["deadlock_statistics"]["cycles_summary"] = [
            {
                "cycle_id": cycle_id,
                "nodes_count": len(nodes),
                "nodes": nodes
            }
            for cycle_id, nodes in cycles_summary.items()
        ]
        
        with open(output_path, 'w') as f:
            json.dump(export_report, f, indent=4, default=str)
        
        logger.info(f"Neo4j property addition report generated: {output_path}")
        logger.info(f"Deadlock summary: {len(deadlock_nodes)} existing nodes now have deadlock properties in {len(cycles_summary)} cycles")
        return export_report

    def run_analysis(self, output_path: str = "deadlock_report.json", export_to_neo4j: bool = True) -> None:
        logger.info("Starting enhanced deadlock analysis (XOR-aware, AND_SPLIT only)...")
        try:
            nodes = self.fetch_sql_nodes()
            if not nodes:
                logger.warning("No SQL nodes found in the database!")
                logger.info("Checking if any nodes exist at all...")
                
                # Check if any nodes exist
                with self.driver.session() as session:
                    result = session.run("MATCH (n) RETURN count(n) as total")
                    total_nodes = result.single()['total']
                    logger.info(f"Total nodes in database: {total_nodes}")
                    
                    # Check nodes with SQL property
                    result = session.run("MATCH (n) WHERE n.SQL IS NOT NULL RETURN count(n) as sql_nodes")
                    sql_nodes = result.single()['sql_nodes']
                    logger.info(f"Nodes with SQL property: {sql_nodes}")
                
                return

            self.build_waits_graph(nodes)
            if self.detect_deadlocks():
                logger.warning(f"Found {len(self.deadlock_cycles)} potential deadlock cycles!")
                for i, cycle in enumerate(self.deadlock_cycles):
                    logger.warning(f"Cycle {i+1}: {' -> '.join(cycle)}")
                
                # Add deadlock properties to existing nodes (no new nodes/relationships/labels)
                if export_to_neo4j:
                    self.export_deadlock_to_neo4j()
                    
                    # Generate Neo4j export report
                    neo4j_report_path = output_path.replace('.json', '_neo4j_export.json')
                    self.generate_neo4j_export_report(neo4j_report_path)
                    
            else:
                logger.info("No deadlocks detected - XOR paths don't create concurrent execution.")
            
            self.generate_report(output_path)
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            raise

    def close(self) -> None:
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed.")

if __name__ == "__main__":
    config = load_config()
    detector = SQLDeadlockDetector(config)
    detector.run_analysis(export_to_neo4j=True)  # Enable Neo4j export
    detector.close()
