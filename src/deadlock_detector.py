import logging
from typing import Dict, List, Set, Tuple, Any
import re
import networkx as nx

logger = logging.getLogger(__name__)

class DeadlockDetector:
    """
    Specialized detector for identifying potential deadlocks in BPMN models.
    Can detect structural deadlocks, SQL deadlocks, and simulation time deadlocks.
    """
    
    def __init__(self, activities: Dict, transitions: Dict, gateways: Dict, gateway_patterns: Dict):
        """
        Initialize the deadlock detector with process data.
        
        Args:
            activities: Dictionary of activities from the process
            transitions: Dictionary of transitions in the process
            gateways: Dictionary of gateways in the process
            gateway_patterns: Dictionary of analyzed gateway patterns
        """
        self.activities = activities
        self.transitions = transitions
        self.gateways = gateways
        self.gateway_patterns = gateway_patterns
        self.deadlocks = []
    
    def detect_all_deadlocks(self) -> List[Dict]:
        """
        Run all deadlock detection algorithms.
        
        Returns:
            List of detected deadlocks with details
        """
        # Clear previous results
        self.deadlocks = []
        
        # Run all detection algorithms
        self.detect_structural_deadlocks()
        self.detect_sql_deadlocks()
        self.detect_time_deadlocks()
        
        return self.deadlocks
    
    def detect_structural_deadlocks(self) -> List[Dict]:
        """
        Detect structural deadlocks in the BPMN model.
        
        This primarily looks for:
        1. Inclusive/parallel gateways without matching convergence
        2. Paths that have no way to complete
        
        Returns:
            List of detected structural deadlocks
        """
        # Find gateways that split without matching convergence
        for gw_id, pattern in self.gateway_patterns.items():
            if pattern['pattern'] == 'Split' and pattern['subtype'] in ['Inclusive', 'Parallel']:
                # Check if this has a matching convergence
                has_convergence = False
                for other_id, other_pattern in self.gateway_patterns.items():
                    if (other_pattern['pattern'] == 'Join' and 
                        other_pattern['subtype'] == pattern['subtype'] and
                        self._are_gateways_connected(gw_id, other_id)):
                        has_convergence = True
                        break
                
                if not has_convergence:
                    # This is a structural deadlock
                    gateway = self.gateways[gw_id]
                    deadlock = {
                        'type': 'Structural',
                        'subtype': 'Missing Gateway Convergence',
                        'description': f"{pattern['subtype']} Gateway (ID: {gw_id}, Name: {gateway.get('name', 'Unnamed')}) "
                                      f"splits flow but has no matching convergence gateway",
                        'severity': 'Critical',
                        'location': gateway.get('lane_id', 'Unknown'),
                        'element_id': gw_id,
                        'element_name': gateway.get('name', 'Unnamed Gateway'),
                        'affected_nodes': [gw_id]
                    }
                    self.deadlocks.append(deadlock)
        
        return self.deadlocks
    
    def detect_sql_deadlocks(self) -> List[Dict]:
        """
        Enhanced detection of SQL deadlocks by analyzing SQL statements in activities.
        
        This includes detecting:
        1. Multiple activities updating the same tables in different orders
        2. Explicit SQL that might cause deadlocks (WAITFOR, DELAY, etc.)
        3. Transactions using BEGIN/COMMIT with conflicting table access patterns
        4. Cyclical lock patterns between transactions
        
        Returns:
            List of detected SQL deadlocks
        """
        # Build a map of all SQL transactions
        transactions = self._build_transaction_map()
        
        # Find concurrent execution paths using gateway information
        concurrent_paths = self._find_concurrent_execution_paths()
        
        # Detect deadlocks between any concurrent transactions
        self._detect_transaction_deadlocks(transactions, concurrent_paths)
        
        # Detect specific problematic SQL patterns
        self._detect_problematic_sql_patterns()
        
        # Build a transaction dependency graph to find cycles
        self._detect_transaction_cycles()
        
        return [d for d in self.deadlocks if d['type'] == 'SQL']
    
    def _build_transaction_map(self) -> Dict:
        """Build a map of all transactions in the process."""
        transactions = {}
        
        # First pass: identify all transaction blocks
        for act_id, activity in self.activities.items():
            sql = activity.get('SQL', '')
            if not sql or not isinstance(sql, str):
                continue
                
            # Check if this contains a transaction
            if re.search(r'BEGIN\s+(TRANSACTION|TRAN)', sql, re.IGNORECASE):
                # Extract transaction name if available
                match = re.search(r'BEGIN\s+(TRANSACTION|TRAN)\s+([A-Za-z0-9_]+)', sql, re.IGNORECASE)
                tran_name = match.group(2) if match and match.group(2) else f"Transaction_{act_id}"
                
                # Create transaction record
                transactions[act_id] = {
                    'transaction_name': tran_name,
                    'activity': activity,
                    'sql': sql,
                    'tables': self._extract_tables_from_sql(sql),
                    'table_operations': self._extract_table_operations(sql),
                    'has_delay': re.search(r'WAITFOR\s+DELAY', sql, re.IGNORECASE) is not None
                }
        
        return transactions
    
    def _extract_table_operations(self, sql: str) -> List[Dict]:
        """Extract detailed table operations in sequence from SQL."""
        if not isinstance(sql, str):
            return []
            
        operations = []
        
        # Capture operations with their sequence
        for i, match in enumerate(re.finditer(r'(SELECT|UPDATE|INSERT\s+INTO|DELETE\s+FROM|LOCK\s+TABLE)\s+([A-Za-z0-9_]+)', sql, re.IGNORECASE)):
            operation = match.group(1).upper()
            table = match.group(2).lower()
            
            # Determine lock type based on operation
            lock_type = 'X' if operation in ['UPDATE', 'INSERT INTO', 'DELETE FROM'] else 'S'
            
            operations.append({
                'sequence': i,
                'operation': operation,
                'table': table,
                'lock_type': lock_type
            })
            
        return operations
    
    def _find_concurrent_execution_paths(self) -> List[Tuple[str, str]]:
        """Find pairs of activities that can execute concurrently."""
        concurrent_pairs = []
        
        # Activities in the same lane might run concurrently
        lane_activities = {}
        for act_id, activity in self.activities.items():
            lane_id = activity.get('lane_id')
            if lane_id:
                if lane_id not in lane_activities:
                    lane_activities[lane_id] = []
                lane_activities[lane_id].append(act_id)
        
        # All activities in the same lane can potentially run concurrently
        for lane_id, activities in lane_activities.items():
            for i, act1_id in enumerate(activities):
                for act2_id in activities[i+1:]:
                    concurrent_pairs.append((act1_id, act2_id))
        
        # Activities in parallel gateway paths can run concurrently
        for gw_id, pattern in self.gateway_patterns.items():
            if pattern['pattern'] == 'Split' and pattern['subtype'] == 'Parallel':
                # Get all activities in each outgoing path
                outgoing_paths = []
                for outgoing in pattern['outgoing']:
                    path_activities = self._get_activities_in_path(outgoing['to'])
                    if path_activities:
                        outgoing_paths.append(path_activities)
                
                # Activities across different paths can execute concurrently
                for i, path1 in enumerate(outgoing_paths):
                    for path2 in outgoing_paths[i+1:]:
                        for act1_id in path1:
                            for act2_id in path2:
                                concurrent_pairs.append((act1_id, act2_id))
        
        return concurrent_pairs
    
    def _get_activities_in_path(self, start_id: str) -> List[str]:
        """Get all activities in a path starting from a given node."""
        activities = []
        visited = set()
        
        def dfs(node_id):
            if node_id in visited:
                return
            
            visited.add(node_id)
            
            # Add if it's an activity (not a gateway)
            if node_id in self.activities and node_id not in self.gateways:
                activities.append(node_id)
            
            # Continue traversing
            next_nodes = [t['to'] for t_id, t in self.transitions.items() if t['from'] == node_id]
            for next_node in next_nodes:
                dfs(next_node)
        
        dfs(start_id)
        return activities
    
    def _detect_transaction_deadlocks(self, transactions: Dict, concurrent_pairs: List[Tuple[str, str]]) -> None:
        """Detect deadlocks between concurrent transactions."""
        for act1_id, act2_id in concurrent_pairs:
            # Skip if either activity doesn't have a transaction
            if act1_id not in transactions or act2_id not in transactions:
                continue
                
            trans1 = transactions[act1_id]
            trans2 = transactions[act2_id]
            
            # Check for conflicting table access patterns
            conflict = self._check_transaction_conflict(trans1, trans2)
            
            if conflict:
                deadlock = {
                    'type': 'SQL',
                    'subtype': 'Transaction Lock Order Conflict',
                    'description': f"Deadlock between '{trans1['activity'].get('name')}' and '{trans2['activity'].get('name')}': "
                                  f"Conflicting lock order on tables {conflict['tables']}",
                    'severity': 'Critical',
                    'location': trans1['activity'].get('lane_id', 'Unknown'),
                    'element_id': act1_id,
                    'element2_id': act2_id,
                    'element_name': trans1['activity'].get('name', 'Unnamed'),
                    'element2_name': trans2['activity'].get('name', 'Unnamed'),
                    'tables': conflict['tables'],
                    'lock_sequence1': conflict['sequence1'],
                    'lock_sequence2': conflict['sequence2'],
                    'affected_nodes': [act1_id, act2_id],
                    'conflict_pattern': conflict['pattern']
                }
                self.deadlocks.append(deadlock)
    
    def _check_transaction_conflict(self, trans1: Dict, trans2: Dict) -> Dict:
        """
        Check if two transactions have conflicting table access patterns.
        
        Specifically looks for the classic deadlock pattern:
        - Trans1: locks A, then tries to lock B
        - Trans2: locks B, then tries to lock A
        """
        # Get table operations in sequence
        ops1 = trans1['table_operations']
        ops2 = trans2['table_operations']
        
        # Build tables accessed by each transaction
        tables1 = {op['table'] for op in ops1}
        tables2 = {op['table'] for op in ops2}
        
        # Find common tables
        common_tables = tables1.intersection(tables2)
        
        if len(common_tables) < 2:
            return None
            
        # Check for reverse access patterns
        for table_a in common_tables:
            for table_b in common_tables:
                if table_a == table_b:
                    continue
                    
                # Get operations for these tables in both transactions
                ops1_a = [op for op in ops1 if op['table'] == table_a]
                ops1_b = [op for op in ops1 if op['table'] == table_b]
                ops2_a = [op for op in ops2 if op['table'] == table_a]
                ops2_b = [op for op in ops2 if op['table'] == table_b]
                
                if not (ops1_a and ops1_b and ops2_a and ops2_b):
                    continue
                
                # Find write operations (they acquire exclusive locks)
                write_ops1_a = [op for op in ops1_a if op['lock_type'] == 'X']
                write_ops1_b = [op for op in ops1_b if op['lock_type'] == 'X']
                write_ops2_a = [op for op in ops2_a if op['lock_type'] == 'X']
                write_ops2_b = [op for op in ops2_b if op['lock_type'] == 'X']
                
                if not (write_ops1_a and write_ops1_b and write_ops2_a and write_ops2_b):
                    continue
                
                # Check for reverse access order (classic deadlock pattern)
                if (min(op['sequence'] for op in write_ops1_a) < min(op['sequence'] for op in write_ops1_b) and
                    min(op['sequence'] for op in write_ops2_b) < min(op['sequence'] for op in write_ops2_a)):
                    
                    return {
                        'tables': [table_a, table_b],
                        'sequence1': f"{table_a} → {table_b}",
                        'sequence2': f"{table_b} → {table_a}",
                        'pattern': 'reversed_lock_order'
                    }
                    
        return None
    
    def _detect_problematic_sql_patterns(self) -> None:
        """Detect specific SQL patterns that might lead to deadlocks."""
        waitfor_pattern = r'WAITFOR\s+DELAY'
        transaction_pattern = r'BEGIN\s+(TRANSACTION|TRAN)'
        
        for act_id, activity in self.activities.items():
            sql = activity.get('SQL', '')
            if not sql or not isinstance(sql, str):
                continue
                
            # Check for WAITFOR DELAY inside transaction (like in catatan.txt example)
            if (re.search(transaction_pattern, sql, re.IGNORECASE) and 
                re.search(waitfor_pattern, sql, re.IGNORECASE)):
                
                # Extract transaction details
                transaction_match = re.search(r'BEGIN\s+(TRANSACTION|TRAN)\s+([A-Za-z0-9_]+)?', sql, re.IGNORECASE)
                transaction_name = transaction_match.group(2) if transaction_match and len(transaction_match.groups()) > 1 else "Unnamed"
                
                # Find tables involved
                tables = [t[0] for t in self._extract_tables_from_sql(sql)]
                
                deadlock = {
                    'type': 'SQL',
                    'subtype': 'Transaction With Delay',
                    'description': f"Transaction '{transaction_name}' in activity '{activity.get('name')}' contains "
                                  f"WAITFOR DELAY which increases deadlock risk with tables: {', '.join(tables)}",
                    'severity': 'High',
                    'location': activity.get('lane_id', 'Unknown'),
                    'element_id': act_id,
                    'element_name': activity.get('name', 'Unnamed'),
                    'affected_nodes': [act_id],
                    'tables': tables,
                    'transaction_name': transaction_name
                }
                self.deadlocks.append(deadlock)
                
            # Check for other problematic patterns
            if re.search(r'UPDATE\s+.*\s+SET\s+.*\s+FROM\s+.*\s+JOIN', sql, re.IGNORECASE):
                deadlock = {
                    'type': 'SQL',
                    'subtype': 'Complex Update Join',
                    'description': f"Activity '{activity.get('name')}' contains a complex UPDATE with JOIN "
                                  f"that can lead to unpredictable lock acquisition",
                    'severity': 'Medium',
                    'location': activity.get('lane_id', 'Unknown'),
                    'element_id': act_id,
                    'element_name': activity.get('name', 'Unnamed'),
                    'affected_nodes': [act_id]
                }
                self.deadlocks.append(deadlock)
    
    def _detect_transaction_cycles(self) -> None:
        """Detect cycles in transaction dependency graph that indicate potential deadlocks."""
        # Build a directed graph of table dependencies
        G = nx.DiGraph()
        
        # Add edges for each table access in each transaction
        for act_id, activity in self.activities.items():
            sql = activity.get('SQL', '')
            if not sql or not isinstance(sql, str):
                continue
                
            # Extract tables in access order
            tables_order = self._extract_table_order_from_sql(sql)
            
            # Add edges between consecutive tables (indicating lock order)
            for i in range(len(tables_order) - 1):
                G.add_edge(tables_order[i], tables_order[i+1], activity_id=act_id)
        
        # Find cycles in the graph
        try:
            cycles = list(nx.simple_cycles(G))
            
            for cycle in cycles:
                if len(cycle) >= 2:  # Only consider cycles with at least 2 tables
                    # Get activities involved in the cycle
                    activities_in_cycle = set()
                    for i in range(len(cycle)):
                        u, v = cycle[i], cycle[(i+1) % len(cycle)]
                        if G.has_edge(u, v):
                            for _, _, attr in G.edges(data=True):
                                if 'activity_id' in attr:
                                    activities_in_cycle.add(attr['activity_id'])
                    
                    # Create deadlock record
                    deadlock = {
                        'type': 'SQL',
                        'subtype': 'Transaction Dependency Cycle',
                        'description': f"Cyclic dependency in table access: {' → '.join(cycle + [cycle[0]])}",
                        'severity': 'Critical',
                        'location': 'Multiple',
                        'affected_nodes': list(activities_in_cycle),
                        'tables': cycle,
                        'cycle': ' → '.join(cycle + [cycle[0]])
                    }
                    self.deadlocks.append(deadlock)
        except nx.NetworkXNoCycle:
            # No cycles found, so no deadlocks of this type
            pass
    
    def detect_time_deadlocks(self) -> List[Dict]:
        """
        Detect potential time-based deadlocks by analyzing processing times.
        
        Following the description in catatan.txt, this looks for:
        1. Long-running activities within parallel gateways
        2. Activities with exceptionally long processing times
        
        Returns:
            List of detected time deadlocks
        """
        # Set threshold for long-running activities (in minutes)
        long_processing_threshold = 60  # 1 hour
        very_long_threshold = 120  # 2 hours
        extreme_threshold = 240  # 4 hours
        
        # Find activities with long processing times
        for act_id, activity in self.activities.items():
            time_str = activity.get('Time', '0.00')
            try:
                time = float(time_str)
            except (ValueError, TypeError):
                continue
                
            if time > very_long_threshold:
                # Check if this is in a parallel gateway path
                in_parallel_path = False
                parallel_gateway_id = None
                
                for gw_id, pattern in self.gateway_patterns.items():
                    if pattern['subtype'] == 'Parallel' and pattern['pattern'] == 'Split':
                        # Check if activity is in any path from this gateway
                        if self._is_activity_in_gateway_path(gw_id, act_id):
                            in_parallel_path = True
                            parallel_gateway_id = gw_id
                            break
                
                # Set severity based on contextual factors
                severity = 'Medium' if not in_parallel_path else 'Critical'
                subtype = 'Long Processing Time'
                
                if time > extreme_threshold:
                    subtype = 'Extreme Processing Time'
                    severity = 'Critical'
                
                # Create deadlock record
                deadlock = {
                    'type': 'Time',
                    'subtype': subtype,
                    'description': f"Activity '{activity.get('name', 'Unnamed')}' has excessive "
                                  f"processing time: {time} minutes" + 
                                  (f", blocking parallel processes" if in_parallel_path else ""),
                    'severity': severity,
                    'location': activity.get('lane_id', 'Unknown'),
                    'element_id': act_id,
                    'element_name': activity.get('name', 'Unnamed'),
                    'processing_time': time,
                    'in_parallel_path': in_parallel_path,
                    'affected_nodes': [act_id]
                }
                
                # If in parallel path, add the gateway to affected nodes
                if in_parallel_path and parallel_gateway_id:
                    deadlock['parallel_gateway_id'] = parallel_gateway_id
                    deadlock['affected_nodes'].append(parallel_gateway_id)
                    
                    # Add the parallel gateway name for better context
                    if parallel_gateway_id in self.gateways:
                        deadlock['parallel_gateway_name'] = self.gateways[parallel_gateway_id].get('name', 'Unnamed Gateway')
                
                self.deadlocks.append(deadlock)
        
        return self.deadlocks
    
    def _are_gateways_connected(self, source_gw_id: str, target_gw_id: str) -> bool:
        """Check if two gateways are connected through paths."""
        # Get outgoing transitions from source gateway
        outgoing = [t for t_id, t in self.transitions.items() if t['from'] == source_gw_id]
        
        # Initialize visited activities set
        visited = set()
        
        # Check if there's a path to target gateway
        def dfs(node_id):
            if node_id == target_gw_id:
                return True
            if node_id in visited:
                return False
            
            visited.add(node_id)
            next_nodes = [t['to'] for t_id, t in self.transitions.items() if t['from'] == node_id]
            
            for next_node in next_nodes:
                if dfs(next_node):
                    return True
            return False
        
        # Check each outgoing path
        for transition in outgoing:
            if dfs(transition['to']):
                return True
        
        return False

    def _is_activity_in_gateway_path(self, gateway_id: str, activity_id: str) -> bool:
        """Check if an activity is in the path from a gateway."""
        visited = set()
        
        def dfs(node_id):
            if node_id == activity_id:
                return True
            if node_id in visited:
                return False
            
            visited.add(node_id)
            next_nodes = [t['to'] for t_id, t in self.transitions.items() if t['from'] == node_id]
            
            for next_node in next_nodes:
                if dfs(next_node):
                    return True
            return False
        
        # Get outgoing transitions from gateway
        outgoing = [t for t_id, t in self.transitions.items() if t['from'] == gateway_id]
        
        # Check each outgoing path
        for transition in outgoing:
            if dfs(transition['to']):
                return True
        
        return False
        
    def _extract_tables_from_sql(self, sql: str) -> List[Tuple[str, str]]:
        """
        Extract table names and operations from SQL statement.
        
        Returns:
            List of (table_name, operation) tuples
        """
        tables = []
        if not isinstance(sql, str):
            return tables
            
        sql = sql.upper()
        
        # Extract UPDATE operations
        update_matches = re.findall(r'UPDATE\s+([A-Za-z0-9_]+)', sql)
        for table in update_matches:
            tables.append((table.lower(), 'UPDATE'))
        
        # Extract INSERT operations
        insert_matches = re.findall(r'INSERT\s+INTO\s+([A-Za-z0-9_]+)', sql)
        for table in insert_matches:
            tables.append((table.lower(), 'INSERT'))
        
        # Extract SELECT operations
        select_matches = re.findall(r'FROM\s+([A-Za-z0-9_]+)', sql)
        for table in select_matches:
            tables.append((table.lower(), 'SELECT'))
        
        # Extract DELETE operations
        delete_matches = re.findall(r'DELETE\s+FROM\s+([A-Za-z0-9_]+)', sql)
        for table in delete_matches:
            tables.append((table.lower(), 'DELETE'))
        
        # Extract LOCK operations
        lock_matches = re.findall(r'LOCK\s+TABLE\s+([A-Za-z0-9_]+)', sql)
        for table in lock_matches:
            tables.append((table.lower(), 'LOCK'))
            
        return tables
    
    def _extract_table_order_from_sql(self, sql: str) -> List[str]:
        """Extract the order of table operations in an SQL statement."""
        tables = []
        if not isinstance(sql, str):
            return tables
            
        sql = sql.upper()
        
        # Find all table operations in order
        operations = ['UPDATE', 'INSERT INTO', 'FROM', 'DELETE FROM', 'LOCK TABLE']
        for match in re.finditer(r'(UPDATE|INSERT\s+INTO|FROM|DELETE\s+FROM|LOCK\s+TABLE)\s+([A-Za-z0-9_]+)', sql):
            tables.append(match.group(2).lower())
            
        return tables
