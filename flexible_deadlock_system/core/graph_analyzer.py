from typing import Dict, List, Set, Optional, Tuple
import networkx as nx
from collections import defaultdict, deque

class GraphAnalyzer:
    """Advanced graph analysis utilities for BPMN process graphs"""
    
    def __init__(self, graph_data: Dict):
        self.graph_data = graph_data
        self.nodes = graph_data.get('nodes', {})
        self.relationships = graph_data.get('relationships', [])
        self.nx_graph = self._build_networkx_graph()
        
    def _build_networkx_graph(self) -> nx.DiGraph:
        """Build NetworkX directed graph from data"""
        G = nx.DiGraph()
        
        # Add nodes
        if isinstance(self.nodes, dict):
            for node_id, node_data in self.nodes.items():
                G.add_node(node_id, **node_data)
        elif isinstance(self.nodes, list):
            for node in self.nodes:
                node_id = node.get('id')
                if node_id:
                    G.add_node(node_id, **node)
        
        # Add edges
        for rel in self.relationships:
            source = rel.get('source_id')
            target = rel.get('target_id')
            if source and target:
                G.add_edge(source, target, **rel)
                
        return G
    
    def find_parallel_paths(self) -> List[Dict]:
        """
        Find all parallel execution paths in the graph
        
        Returns:
            List of parallel path scenarios
        """
        parallel_scenarios = []
        
        # Find AND splits (guaranteed parallel)
        and_splits = self._find_gateway_splits('AND_SPLIT')
        for split in and_splits:
            scenario = self._analyze_split_scenario(split, 'AND_SPLIT')
            if scenario:
                parallel_scenarios.append(scenario)
        
        # Find OR splits (conditional parallel)
        or_splits = self._find_gateway_splits('OR_SPLIT')
        for split in or_splits:
            scenario = self._analyze_split_scenario(split, 'OR_SPLIT')
            if scenario:
                parallel_scenarios.append(scenario)
                
        return parallel_scenarios
    
    def _find_gateway_splits(self, gateway_type: str) -> List[Dict]:
        """Find all gateway splits of specified type"""
        splits = []
        
        for rel in self.relationships:
            rel_type = rel.get('rel_type', '')
            if gateway_type in rel_type:
                splits.append({
                    'source_id': rel.get('source_id'),
                    'target_id': rel.get('target_id'),
                    'gateway_type': gateway_type,
                    'properties': rel.get('properties', {})
                })
                
        return splits
    
    def _analyze_split_scenario(self, split: Dict, gateway_type: str) -> Optional[Dict]:
        """Analyze a split gateway scenario for parallel paths"""
        source_id = split['source_id']
        
        # Find all paths from this split
        paths = self._trace_paths_from_split(source_id, gateway_type)
        
        if len(paths) < 2:
            return None
            
        return {
            'gateway_type': gateway_type,
            'source_id': source_id,
            'paths': paths,
            'parallel_execution': gateway_type == 'AND_SPLIT',
            'conditional_execution': gateway_type == 'OR_SPLIT',
            'path_count': len(paths),
            'properties': split.get('properties', {})
        }
    
    def _trace_paths_from_split(self, source_id: str, gateway_type: str, max_depth: int = 15) -> List[List[str]]:
        """Trace execution paths from a split gateway"""
        paths = []
        
        # Get immediate successors of the split
        successors = list(self.nx_graph.successors(source_id))
        
        for successor in successors:
            path = self._trace_single_path(successor, gateway_type, max_depth)
            if path:
                paths.append([source_id] + path)
                
        return paths
    
    def _trace_single_path(self, start_node: str, gateway_type: str, max_depth: int) -> List[str]:
        """Trace a single execution path until join or end"""
        path = []
        current = start_node
        visited = set()
        depth = 0
        
        while current and current not in visited and depth < max_depth:
            path.append(current)
            visited.add(current)
            depth += 1
            
            successors = list(self.nx_graph.successors(current))
            
            # Stop at joins
            if self._is_join_gateway(current):
                break
                
            # Continue with first successor
            if successors:
                current = successors[0]
            else:
                break
                
        return path
    
    def _is_join_gateway(self, node_id: str) -> bool:
        """Check if node is a join gateway"""
        # Check incoming edges for join patterns
        for rel in self.relationships:
            if rel.get('target_id') == node_id:
                rel_type = rel.get('rel_type', '')
                if 'JOIN' in rel_type:
                    return True
        return False
    
    def find_convergent_paths(self) -> List[Dict]:
        """Find paths that converge at join gateways"""
        convergent_scenarios = []
        
        # Find all join gateways
        joins = self._find_join_gateways()
        
        for join in joins:
            scenario = self._analyze_convergent_scenario(join)
            if scenario:
                convergent_scenarios.append(scenario)
                
        return convergent_scenarios
    
    def _find_join_gateways(self) -> List[Dict]:
        """Find all join gateways in the graph"""
        joins = []
        
        for rel in self.relationships:
            rel_type = rel.get('rel_type', '')
            if 'JOIN' in rel_type:
                joins.append({
                    'target_id': rel.get('target_id'),
                    'source_id': rel.get('source_id'),
                    'join_type': rel_type,
                    'properties': rel.get('properties', {})
                })
                
        return joins
    
    def _analyze_convergent_scenario(self, join: Dict) -> Optional[Dict]:
        """Analyze a join gateway for convergent paths"""
        join_target = join['target_id']
        join_type = join['join_type']
        
        # Find all nodes that flow into this join
        predecessors = list(self.nx_graph.predecessors(join_target))
        
        if len(predecessors) < 2:
            return None
            
        # Trace backward from each predecessor
        convergent_paths = []
        for pred in predecessors:
            path = self._trace_backward_path(pred, join_type)
            if path:
                convergent_paths.append(path)
                
        if len(convergent_paths) < 2:
            return None
            
        return {
            'join_type': join_type,
            'join_target': join_target,
            'convergent_paths': convergent_paths,
            'path_count': len(convergent_paths),
            'properties': join.get('properties', {})
        }
    
    def _trace_backward_path(self, start_node: str, join_type: str, max_depth: int = 15) -> List[str]:
        """Trace execution path backward from join"""
        path = []
        current = start_node
        visited = set()
        depth = 0
        
        while current and current not in visited and depth < max_depth:
            path.insert(0, current)  # Insert at beginning for correct order
            visited.add(current)
            depth += 1
            
            predecessors = list(self.nx_graph.predecessors(current))
            
            # Stop at splits
            if self._is_split_gateway(current):
                break
                
            # Continue with first predecessor
            if predecessors:
                current = predecessors[0]
            else:
                break
                
        return path
    
    def _is_split_gateway(self, node_id: str) -> bool:
        """Check if node is a split gateway"""
        for rel in self.relationships:
            if rel.get('source_id') == node_id:
                rel_type = rel.get('rel_type', '')
                if 'SPLIT' in rel_type:
                    return True
        return False
    
    def detect_cycles(self) -> List[List[str]]:
        """Detect cycles in the graph using NetworkX"""
        try:
            cycles = list(nx.simple_cycles(self.nx_graph))
            return cycles
        except:
            return []
    
    def find_strongly_connected_components(self) -> List[List[str]]:
        """Find strongly connected components (potential deadlock areas)"""
        try:
            sccs = list(nx.strongly_connected_components(self.nx_graph))
            # Filter out single-node SCCs
            return [list(scc) for scc in sccs if len(scc) > 1]
        except:
            return []
    
    def calculate_node_centrality(self) -> Dict[str, float]:
        """Calculate betweenness centrality for nodes"""
        try:
            return nx.betweenness_centrality(self.nx_graph)
        except:
            return {}
    
    def find_critical_paths(self) -> List[List[str]]:
        """Find critical paths in the process"""
        critical_paths = []
        
        # Find start and end nodes
        start_nodes = [node for node in self.nx_graph.nodes() 
                      if self.nx_graph.in_degree(node) == 0]
        end_nodes = [node for node in self.nx_graph.nodes() 
                    if self.nx_graph.out_degree(node) == 0]
        
        # Find longest paths from start to end
        for start in start_nodes:
            for end in end_nodes:
                try:
                    if nx.has_path(self.nx_graph, start, end):
                        # Use a simple path finding approach
                        path = nx.shortest_path(self.nx_graph, start, end)
                        critical_paths.append(path)
                except:
                    continue
                    
        return critical_paths
    
    def get_node_sql_resources(self, node_id: str) -> Optional[Dict]:
        """Get SQL resources for a specific node"""
        node = self.get_node_by_id(node_id)
        if not node:
            return None
            
        properties = node.get('properties', {})
        sql_text = properties.get('SQL', '') or properties.get('sql', '')
        
        if not sql_text:
            return None
            
        return {
            'node_id': node_id,
            'sql_text': sql_text,
            'node_name': properties.get('name', node_id),
            'node_type': properties.get('type', 'Unknown')
        }
    
    def get_node_by_id(self, node_id: str) -> Optional[Dict]:
        """Get node data by ID"""
        if isinstance(self.nodes, dict):
            return self.nodes.get(node_id)
        elif isinstance(self.nodes, list):
            for node in self.nodes:
                if node.get('id') == node_id:
                    return node
        return None
