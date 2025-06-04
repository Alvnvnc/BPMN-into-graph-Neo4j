from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum

class DeadlockSeverity(Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class DeadlockResult:
    """Standard result format for deadlock detection"""
    node1_id: str
    node2_id: str
    node1_name: str
    node2_name: str
    severity: DeadlockSeverity
    confidence: float
    conflict_type: str
    shared_resources: List[str]
    strategy_name: str
    details: Dict[str, Any]
    recommendations: List[str] = None

class BaseDeadlockStrategy(ABC):
    """Abstract base class for deadlock detection strategies"""
    
    def __init__(self, name: str, description: str = ""):
        self.name = name
        self.description = description
        self.enabled = True
        self.priority = 1
        
    @abstractmethod
    def detect(self, graph_data: Dict, config: Dict = None) -> List[DeadlockResult]:
        """
        Detect deadlocks using this strategy
        
        Args:
            graph_data: Graph data containing nodes and relationships
            config: Strategy-specific configuration
            
        Returns:
            List of DeadlockResult objects
        """
        pass
        
    @abstractmethod
    def validate_conflict(self, node1: Dict, node2: Dict, context: Dict = None) -> bool:
        """
        Validate if a conflict is realistic for this strategy
        
        Args:
            node1: First node data
            node2: Second node data
            context: Additional context information
            
        Returns:
            True if conflict is valid, False otherwise
        """
        pass
        
    def get_severity(self, conflict_data: Dict) -> DeadlockSeverity:
        """Calculate severity based on conflict data"""
        # Default severity calculation - can be overridden
        score = 0
        
        if conflict_data.get('table_conflicts'):
            score += 30
        if conflict_data.get('write_operations'):
            score += 25
        if conflict_data.get('high_frequency'):
            score += 20
            
        if score >= 60:
            return DeadlockSeverity.CRITICAL
        elif score >= 40:
            return DeadlockSeverity.HIGH
        elif score >= 20:
            return DeadlockSeverity.MEDIUM
        else:
            return DeadlockSeverity.LOW
            
    def get_confidence(self, conflict_data: Dict) -> float:
        """Calculate confidence score (0.0 - 1.0)"""
        # Default confidence calculation - can be overridden
        confidence = 0.5
        
        if conflict_data.get('direct_resource_conflict'):
            confidence += 0.3
        if conflict_data.get('proven_parallel_execution'):
            confidence += 0.2
        if conflict_data.get('write_write_conflict'):
            confidence += 0.2
            
        return min(1.0, confidence)

class BaseGraphAnalyzer:
    """Base class for graph analysis utilities"""
    
    def __init__(self, graph_data: Dict):
        self.graph_data = graph_data
        self.nodes = graph_data.get('nodes', {})
        self.relationships = graph_data.get('relationships', [])
        
    def get_node_by_id(self, node_id: str) -> Optional[Dict]:
        """Get node data by ID"""
        if isinstance(self.nodes, dict):
            return self.nodes.get(node_id)
        elif isinstance(self.nodes, list):
            for node in self.nodes:
                if node.get('id') == node_id:
                    return node
        return None
        
    def get_predecessors(self, node_id: str) -> List[str]:
        """Get immediate predecessors of a node"""
        predecessors = []
        for rel in self.relationships:
            if rel.get('target_id') == node_id:
                predecessors.append(rel.get('source_id'))
        return predecessors
        
    def get_successors(self, node_id: str) -> List[str]:
        """Get immediate successors of a node"""
        successors = []
        for rel in self.relationships:
            if rel.get('source_id') == node_id:
                successors.append(rel.get('target_id'))
        return successors
        
    def find_paths_between(self, start_node: str, end_node: str, max_depth: int = 10) -> List[List[str]]:
        """Find all paths between two nodes"""
        paths = []
        
        def dfs(current: str, target: str, path: List[str], visited: set, depth: int):
            if depth > max_depth or current in visited:
                return
                
            path.append(current)
            visited.add(current)
            
            if current == target:
                paths.append(path.copy())
            else:
                for successor in self.get_successors(current):
                    dfs(successor, target, path, visited.copy(), depth + 1)
                    
            path.pop()
            
        dfs(start_node, end_node, [], set(), 0)
        return paths
        
    def is_parallel_gateway(self, node_id: str) -> bool:
        """Check if node is a parallel gateway"""
        node = self.get_node_by_id(node_id)
        if not node:
            return False
            
        # Check for parallel gateway indicators
        for rel in self.relationships:
            if rel.get('source_id') == node_id or rel.get('target_id') == node_id:
                rel_type = rel.get('rel_type', '').upper()
                if 'AND_SPLIT' in rel_type or 'AND_JOIN' in rel_type:
                    return True
                    
        return False
