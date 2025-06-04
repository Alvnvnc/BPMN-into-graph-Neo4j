"""
Flexible and Dynamic SQL Deadlock Detector
- Modular architecture for different deadlock patterns
- Plugin-based deadlock detection strategies
- Dynamic conflict resolution without hardcoded recommendations
"""

import sys
import os
import json
import logging
import networkx as nx
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional, Any, Callable
from abc import ABC, abstractmethod
from dataclasses import dataclass
from collections import defaultdict, deque
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class DeadlockPattern:
    """Data class for deadlock patterns"""
    pattern_id: str
    pattern_type: str
    severity: str
    nodes: List[str]
    resources: Set[str]
    gateway_type: str
    execution_context: str
    metadata: Dict[str, Any] = None

@dataclass
class ConflictResult:
    """Result of conflict detection"""
    has_conflict: bool
    conflict_type: str
    shared_resources: Set[str]
    operations: List[str]
    severity_score: int
    metadata: Dict[str, Any] = None

class DeadlockDetectionStrategy(ABC):
    """Abstract base class for deadlock detection strategies"""
    
    @abstractmethod
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        """Detect deadlocks based on specific strategy"""
        pass
    
    @abstractmethod
    def get_strategy_name(self) -> str:
        """Get strategy name"""
        pass

class ParallelGatewayStrategy(DeadlockDetectionStrategy):
    """Strategy for detecting parallel gateway deadlocks"""
    
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        patterns = []
        graph_data = context.get('graph_data')
        sql_resources = context.get('sql_resources')
        
        if not graph_data or not sql_resources:
            return patterns
            
        # Find AND_SPLIT gateways
        and_splits = self._find_gateway_splits(graph_data, 'AND_SPLIT')
        
        for split in and_splits:
            parallel_paths = self._trace_parallel_paths(split, graph_data)
            conflicts = self._check_path_conflicts(parallel_paths, sql_resources)
            
            for conflict in conflicts:
                if conflict.has_conflict:
                    pattern = DeadlockPattern(
                        pattern_id=f"parallel_{split['gateway_id']}_{conflict.conflict_type}",
                        pattern_type="PARALLEL_GATEWAY",
                        severity=self._calculate_severity(conflict),
                        nodes=conflict.metadata.get('nodes', []),
                        resources=conflict.shared_resources,
                        gateway_type="AND_SPLIT",
                        execution_context="GUARANTEED_PARALLEL",
                        metadata={
                            'gateway_id': split['gateway_id'],
                            'paths': parallel_paths,
                            'conflict_details': conflict
                        }
                    )
                    patterns.append(pattern)
        
        return patterns
    
    def get_strategy_name(self) -> str:
        return "ParallelGatewayStrategy"
    
    def _find_gateway_splits(self, graph_data: Dict, gateway_type: str) -> List[Dict]:
        """Find gateway splits of specific type"""
        splits = []
        for rel in graph_data.get('relationships', []):
            if gateway_type in rel.get('rel_type', ''):
                splits.append({
                    'gateway_id': rel.get('source_id'),
                    'targets': [rel.get('target_id')],
                    'rel_type': rel.get('rel_type')
                })
        return splits
    
    def _trace_parallel_paths(self, split: Dict, graph_data: Dict) -> List[List[str]]:
        """Trace parallel execution paths from split"""
        paths = []
        # Implementation for tracing paths
        # This is simplified - you can expand based on your needs
        return paths
    
    def _check_path_conflicts(self, paths: List[List[str]], sql_resources: Dict) -> List[ConflictResult]:
        """Check for conflicts between parallel paths"""
        conflicts = []
        # Implementation for checking conflicts
        return conflicts
    
    def _calculate_severity(self, conflict: ConflictResult) -> str:
        """Calculate severity based on conflict score"""
        score = conflict.severity_score
        if score >= 50:
            return 'CRITICAL'
        elif score >= 30:
            return 'HIGH'
        elif score >= 15:
            return 'MEDIUM'
        else:
            return 'LOW'

class ConvergentJoinStrategy(DeadlockDetectionStrategy):
    """Strategy for detecting convergent join deadlocks"""
    
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        patterns = []
        # Implementation for convergent join detection
        return patterns
    
    def get_strategy_name(self) -> str:
        return "ConvergentJoinStrategy"

class ResourceContentionStrategy(DeadlockDetectionStrategy):
    """Strategy for detecting resource contention deadlocks"""
    
    def detect(self, context: Dict[str, Any]) -> List[DeadlockPattern]:
        patterns = []
        # Implementation for resource contention detection
        return patterns
    
    def get_strategy_name(self) -> str:
        return "ResourceContentionStrategy"

class FlexibleSQLDeadlockDetector:
    """
    Flexible and Dynamic SQL Deadlock Detector
    - Plugin architecture for detection strategies
    - Dynamic pattern matching
    - Extensible conflict resolution
    """
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, database: str = "neo4j"):
        self.neo4j_uri = neo4j_uri
        self.neo4j_user = neo4j_user
        self.neo4j_password = neo4j_password
        self.database = database
        
        # Initialize Neo4j driver
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
            logger.info("Neo4j connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {e}")
            raise
        
        # Initialize components
        self.graph_data = None
        self.sql_resources = {}
        self.detection_strategies: List[DeadlockDetectionStrategy] = []
        self.detected_patterns: List[DeadlockPattern] = []
        
        # Register default strategies
        self._register_default_strategies()
        
        # Configuration
        self.config = {
            'max_path_depth': 20,
            'min_severity_threshold': 'LOW',
            'enable_filtering': True,
            'output_format': 'json'
        }
    
    def _register_default_strategies(self):
        """Register default detection strategies"""
        self.register_strategy(ParallelGatewayStrategy())
        self.register_strategy(ConvergentJoinStrategy())
        self.register_strategy(ResourceContentionStrategy())
    
    def register_strategy(self, strategy: DeadlockDetectionStrategy):
        """Register a new detection strategy"""
        self.detection_strategies.append(strategy)
        logger.info(f"Registered strategy: {strategy.get_strategy_name()}")
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def fetch_graph_data(self) -> Dict:
        """Fetch graph data from Neo4j"""
        with self.driver.session(database=self.database) as session:
            # Fetch nodes
            nodes_query = """
            MATCH (n) 
            RETURN n.id as id, labels(n) as labels, properties(n) as properties
            """
            nodes_result = session.run(nodes_query)
            nodes = {}
            
            for record in nodes_result:
                node_id = record['id']
                if node_id:
                    nodes[node_id] = {
                        'labels': record['labels'],
                        'properties': record['properties']
                    }
            
            # Fetch relationships
            relationships_query = """
            MATCH (a)-[r]->(b)
            RETURN a.id as source_id, b.id as target_id, type(r) as rel_type, properties(r) as properties
            """
            relationships_result = session.run(relationships_query)
            relationships = []
            
            for record in relationships_result:
                if record['source_id'] and record['target_id']:
                    relationships.append({
                        'source_id': record['source_id'],
                        'target_id': record['target_id'],
                        'rel_type': record['rel_type'],
                        'properties': record['properties'] or {}
                    })
            
            self.graph_data = {
                'nodes': nodes,
                'relationships': relationships
            }
            
            logger.info(f"Fetched {len(nodes)} nodes and {len(relationships)} relationships")
            return self.graph_data
    
    def extract_sql_resources(self, sql_query: str) -> Dict[str, Set[str]]:
        """Extract SQL resources from query"""
        if not sql_query:
            return {'tables': set(), 'columns': set(), 'operations': set()}
        
        import re
        
        # Extract tables
        table_patterns = [
            r'FROM\s+(\w+)',
            r'UPDATE\s+(\w+)',
            r'INSERT\s+INTO\s+(\w+)',
            r'DELETE\s+FROM\s+(\w+)',
            r'JOIN\s+(\w+)'
        ]
        
        tables = set()
        for pattern in table_patterns:
            matches = re.findall(pattern, sql_query, re.IGNORECASE)
            tables.update(matches)
        
        # Extract operations
        operations = set()
        if re.search(r'\bSELECT\b', sql_query, re.IGNORECASE):
            operations.add('SELECT')
        if re.search(r'\bUPDATE\b', sql_query, re.IGNORECASE):
            operations.add('UPDATE')
        if re.search(r'\bINSERT\b', sql_query, re.IGNORECASE):
            operations.add('INSERT')
        if re.search(r'\bDELETE\b', sql_query, re.IGNORECASE):
            operations.add('DELETE')
        
        # Extract columns (simplified)
        columns = set()
        column_pattern = r'(\w+)\s*='
        matches = re.findall(column_pattern, sql_query, re.IGNORECASE)
        columns.update(matches)
        
        return {
            'tables': tables,
            'columns': columns,
            'operations': operations
        }
    
    def build_sql_resource_map(self):
        """Build SQL resource mapping from graph data"""
        if not self.graph_data:
            logger.warning("No graph data available")
            return
        
        sql_node_count = 0
        
        for node_id, node_data in self.graph_data['nodes'].items():
            properties = node_data.get('properties', {})
            sql_query = properties.get('SQL') or properties.get('sql')
            
            if sql_query:
                resources = self.extract_sql_resources(sql_query)
                
                self.sql_resources[node_id] = {
                    'name': properties.get('name', f'Node_{node_id}'),
                    'sql': sql_query,
                    'resources': resources,
                    'node_type': node_data.get('labels', ['Unknown'])[0] if node_data.get('labels') else 'Unknown'
                }
                sql_node_count += 1
        
        logger.info(f"Built SQL resource map for {sql_node_count} nodes")
    
    def detect_all_patterns(self) -> List[DeadlockPattern]:
        """Run all registered detection strategies"""
        all_patterns = []
        
        context = {
            'graph_data': self.graph_data,
            'sql_resources': self.sql_resources,
            'config': self.config
        }
        
        for strategy in self.detection_strategies:
            try:
                logger.info(f"Running strategy: {strategy.get_strategy_name()}")
                patterns = strategy.detect(context)
                all_patterns.extend(patterns)
                logger.info(f"Strategy {strategy.get_strategy_name()} found {len(patterns)} patterns")
            except Exception as e:
                logger.error(f"Error in strategy {strategy.get_strategy_name()}: {e}")
        
        self.detected_patterns = all_patterns
        return all_patterns
    
    def filter_patterns(self, patterns: List[DeadlockPattern]) -> List[DeadlockPattern]:
        """Filter patterns based on configuration"""
        if not self.config.get('enable_filtering', True):
            return patterns
        
        filtered = []
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_threshold = severity_order.get(self.config.get('min_severity_threshold', 'LOW'), 1)
        
        for pattern in patterns:
            pattern_severity = severity_order.get(pattern.severity, 1)
            if pattern_severity >= min_threshold:
                filtered.append(pattern)
        
        logger.info(f"Filtered {len(patterns)} patterns to {len(filtered)} based on severity threshold")
        return filtered
    
    def generate_flexible_report(self) -> Dict:
        """Generate flexible report without hardcoded recommendations"""
        patterns = self.detect_all_patterns()
        filtered_patterns = self.filter_patterns(patterns)
        
        # Group patterns by type
        patterns_by_type = defaultdict(list)
        for pattern in filtered_patterns:
            patterns_by_type[pattern.pattern_type].append(pattern)
        
        # Calculate statistics
        severity_counts = defaultdict(int)
        for pattern in filtered_patterns:
            severity_counts[pattern.severity] += 1
        
        # Get unique resources and gateways
        all_resources = set()
        all_gateways = set()
        for pattern in filtered_patterns:
            all_resources.update(pattern.resources)
            all_gateways.add(pattern.gateway_type)
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_patterns_detected': len(patterns),
                'patterns_after_filtering': len(filtered_patterns),
                'total_sql_nodes': len(self.sql_resources),
                'total_graph_nodes': len(self.graph_data.get('nodes', {})),
                'severity_distribution': dict(severity_counts),
                'pattern_types': list(patterns_by_type.keys()),
                'involved_resources': list(all_resources),
                'involved_gateways': list(all_gateways)
            },
            'patterns_by_type': {
                pattern_type: [self._pattern_to_dict(p) for p in pattern_list]
                for pattern_type, pattern_list in patterns_by_type.items()
            },
            'configuration': self.config,
            'strategies_used': [s.get_strategy_name() for s in self.detection_strategies]
        }
        
        return report
    
    def _pattern_to_dict(self, pattern: DeadlockPattern) -> Dict:
        """Convert pattern to dictionary for serialization"""
        return {
            'pattern_id': pattern.pattern_id,
            'pattern_type': pattern.pattern_type,
            'severity': pattern.severity,
            'nodes': pattern.nodes,
            'resources': list(pattern.resources),
            'gateway_type': pattern.gateway_type,
            'execution_context': pattern.execution_context,
            'metadata': pattern.metadata or {}
        }
    
    def save_results(self, report: Dict, filename: str = None):
        """Save results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"flexible_deadlock_report_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Report saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def configure(self, **kwargs):
        """Update configuration dynamically"""
        self.config.update(kwargs)
        logger.info(f"Configuration updated: {kwargs}")
    
    def get_pattern_statistics(self) -> Dict:
        """Get statistics about detected patterns"""
        if not self.detected_patterns:
            return {}
        
        stats = {
            'total_patterns': len(self.detected_patterns),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'by_gateway': defaultdict(int),
            'resource_frequency': defaultdict(int)
        }
        
        for pattern in self.detected_patterns:
            stats['by_severity'][pattern.severity] += 1
            stats['by_type'][pattern.pattern_type] += 1
            stats['by_gateway'][pattern.gateway_type] += 1
            
            for resource in pattern.resources:
                stats['resource_frequency'][resource] += 1
        
        return dict(stats)

def main():
    """Main function for flexible deadlock detection"""
    print("=== FLEXIBLE DEADLOCK DETECTOR ===")
    
    try:
        # Load configuration
        parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        sys.path.append(parent_dir)
        
        try:
            from config_deadlock import NEO4J_CONFIG
            neo4j_config = NEO4J_CONFIG
        except ImportError:
            neo4j_config = {
                'uri': 'bolt://localhost:7687',
                'user': 'neo4j',
                'password': '12345678',
                'database': 'neo4j'
            }
        
        # Initialize detector
        detector = FlexibleSQLDeadlockDetector(
            neo4j_config['uri'],
            neo4j_config['user'], 
            neo4j_config['password'],
            neo4j_config.get('database', 'neo4j')
        )
        
        # Configure detector
        detector.configure(
            max_path_depth=25,
            min_severity_threshold='MEDIUM',
            enable_filtering=True
        )
        
        # Fetch data and build resources
        print("Fetching graph data...")
        detector.fetch_graph_data()
        
        print("Building SQL resource map...")
        detector.build_sql_resource_map()
        
        # Generate report
        print("Detecting deadlock patterns...")
        report = detector.generate_flexible_report()
        
        # Print summary
        summary = report['summary']
        print(f"\n📊 DETECTION SUMMARY:")
        print(f"   • Total Patterns Detected: {summary['total_patterns_detected']}")
        print(f"   • After Filtering: {summary['patterns_after_filtering']}")
        print(f"   • SQL Nodes Analyzed: {summary['total_sql_nodes']}")
        print(f"   • Pattern Types: {', '.join(summary['pattern_types'])}")
        print(f"   • Severity Distribution: {summary['severity_distribution']}")
        
        # Save results
        detector.save_results(report)
        
        print("\n✅ Flexible deadlock detection completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if 'detector' in locals():
            detector.close()

if __name__ == "__main__":
    main()
