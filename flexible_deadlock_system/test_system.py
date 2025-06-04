"""
Test script for the Flexible SQL Deadlock Detection System.
"""

import json
import sys
from pathlib import Path

# Add the flexible_deadlock_system directory to Python path
sys.path.insert(0, str(Path(__file__).parent))

from config.detection_config import DetectionConfig, StrategyRegistry
from strategies.parallel_strategy import ParallelExecutionStrategy
from strategies.resource_strategy import ResourceContentionStrategy
from strategies.gateway_strategy import GatewaySpecificStrategy
from core.base_detector import DeadlockResult, DeadlockSeverity
from utils.logger import get_logger, set_log_level
from utils.validator import validate_all_inputs, ValidationError


class DeadlockDetectionSystem:
    """
    Main system orchestrator for flexible deadlock detection.
    """
    
    def __init__(self, config_path=None):
        """
        Initialize the detection system.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.logger = get_logger("DeadlockDetectionSystem")
        self.registry = StrategyRegistry()
        self.config = None
        
        # Register default strategies
        self._register_default_strategies()
        
        # Load configuration
        if config_path:
            self.load_config(config_path)
        else:
            self.config = DetectionConfig.create_balanced_config()
    
    def _register_default_strategies(self):
        """Register the default detection strategies."""
        self.registry.register_strategy("parallel_execution", ParallelExecutionStrategy())
        self.registry.register_strategy("resource_contention", ResourceContentionStrategy())
        self.registry.register_strategy("gateway_specific", GatewaySpecificStrategy())
    
    def load_config(self, config_path):
        """
        Load configuration from file.
        
        Args:
            config_path: Path to configuration file
        """
        try:
            with open(config_path, 'r') as f:
                config_data = json.load(f)
            self.config = DetectionConfig(**config_data)
            self.logger.logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            self.logger.log_error(e, f"loading configuration from {config_path}")
            raise
    
    def detect_deadlocks(self, nodes, edges, sql_queries=None):
        """
        Detect deadlocks using configured strategies.
        
        Args:
            nodes: List of workflow nodes
            edges: List of workflow edges
            sql_queries: Optional list of SQL queries to analyze
        
        Returns:
            List of detected deadlocks
        """
        import time
        start_time = time.time()
        all_results = []
        
        try:
            # Validate inputs
            validate_all_inputs(
                sql_queries=sql_queries,
                nodes=nodes,
                edges=edges,
                config=self.config.config
            )
            
            self.logger.log_detection_start("Multi-Strategy", self.config.config)
            
            # Execute each configured strategy
            for strategy_name in self.config.get('enabled_strategies', []):
                if strategy_name not in self.registry.strategies:
                    self.logger.log_warning(f"Strategy '{strategy_name}' not found in registry")
                    continue
                
                strategy = self.registry.strategies[strategy_name]
                strategy_start = time.time()
                
                try:
                    # Prepare graph data
                    graph_data = {
                        'nodes': nodes,
                        'edges': edges,
                        'sql_queries': sql_queries
                    }
                    
                    # Detect using this strategy
                    results = strategy.detect(graph_data, self.config.get_strategy_config(strategy_name))
                    
                    # Filter results based on severity threshold
                    filtered_results = self._filter_by_severity(results)
                    all_results.extend(filtered_results)
                    
                    strategy_time = time.time() - strategy_start
                    self.logger.log_strategy_execution(
                        strategy_name, strategy_time, len(nodes)
                    )
                    
                    # Log each result
                    for result in filtered_results:
                        self.logger.log_detection_result(result)
                
                except Exception as e:
                    self.logger.log_error(e, f"executing strategy '{strategy_name}'")
                    continue
            
            # Remove duplicates and sort by severity
            unique_results = self._deduplicate_results(all_results)
            sorted_results = sorted(
                unique_results, 
                key=lambda x: x.severity.value, 
                reverse=True
            )
            
            total_time = time.time() - start_time
            self.logger.logger.info(
                f"Detection completed in {total_time:.3f}s. "
                f"Found {len(sorted_results)} unique deadlocks"
            )
            
            return sorted_results
        
        except ValidationError as e:
            self.logger.log_error(e, "input validation")
            raise
        except Exception as e:
            self.logger.log_error(e, "deadlock detection")
            raise
    
    def _filter_by_severity(self, results):
        """Filter results based on minimum severity threshold."""
        severity_threshold = self.config.get('severity_threshold', 'MEDIUM')
        if not severity_threshold:
            return results
        
        min_severity = DeadlockSeverity[severity_threshold]
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_order[min_severity.value]
        
        return [r for r in results if severity_order.get(r.severity.value, 0) >= min_level]
    
    def _deduplicate_results(self, results):
        """Remove duplicate detection results."""
        unique_results = []
        seen_descriptions = set()
        
        for result in results:
            # Create a simple hash based on nodes and conflict type
            result_hash = (
                result.node1_id,
                result.node2_id,
                result.conflict_type
            )
            
            if result_hash not in seen_descriptions:
                seen_descriptions.add(result_hash)
                unique_results.append(result)
        
        return unique_results
    
    def save_results(self, results, output_path):
        """
        Save detection results to file.
        
        Args:
            results: List of detection results
            output_path: Path to output file
        """
        import time
        try:
            output_data = {
                'timestamp': time.time(),
                'total_deadlocks': len(results),
                'deadlocks': [
                    {
                        'description': f"{result.conflict_type} between {result.node1_name} and {result.node2_name}",
                        'severity': result.severity.name,
                        'confidence_score': result.confidence_score,
                        'affected_nodes': result.affected_nodes,
                        'details': result.details
                    }
                    for result in results
                ]
            }
            
            with open(output_path, 'w') as f:
                json.dump(output_data, f, indent=2)
            
            self.logger.logger.info(f"Results saved to {output_path}")
        
        except Exception as e:
            self.logger.log_error(e, f"saving results to {output_path}")
            raise


def create_sample_graph():
    """Create a sample workflow graph with potential deadlocks."""
    
    nodes = [
        {
            "id": "start_event",
            "type": "event",
            "name": "Start Process"
        },
        {
            "id": "parallel_gateway",
            "type": "gateway",
            "name": "Parallel Split",
            "gateway_type": "parallel"
        },
        {
            "id": "task_a",
            "type": "task",
            "name": "Process Order",
            "sql_query": "SELECT * FROM orders WHERE status = 'pending' FOR UPDATE"
        },
        {
            "id": "task_b", 
            "type": "task",
            "name": "Update Inventory",
            "sql_query": "UPDATE inventory SET quantity = quantity - 1 WHERE product_id = 123"
        },
        {
            "id": "task_c",
            "type": "task", 
            "name": "Process Payment",
            "sql_query": "INSERT INTO payments (order_id, amount) VALUES (456, 100.00)"
        },
        {
            "id": "task_d",
            "type": "task",
            "name": "Update Order Status", 
            "sql_query": "UPDATE orders SET status = 'completed' WHERE id = 456"
        },
        {
            "id": "join_gateway",
            "type": "gateway",
            "name": "Parallel Join",
            "gateway_type": "parallel"
        },
        {
            "id": "end_event",
            "type": "event", 
            "name": "End Process"
        }
    ]
    
    edges = [
        {"source": "start_event", "target": "parallel_gateway"},
        {"source": "parallel_gateway", "target": "task_a"},
        {"source": "parallel_gateway", "target": "task_b"},
        {"source": "task_a", "target": "task_c"},
        {"source": "task_b", "target": "task_d"},
        {"source": "task_c", "target": "join_gateway"},
        {"source": "task_d", "target": "join_gateway"},
        {"source": "join_gateway", "target": "end_event"}
    ]
    
    return nodes, edges


def run_basic_test():
    """Run basic deadlock detection test."""
    
    print("🔍 Flexible SQL Deadlock Detection System - Basic Test")
    print("=" * 60)
    
    try:
        # Create sample graph
        print("1. Creating sample workflow graph...")
        nodes, edges = create_sample_graph()
        print(f"   Created graph with {len(nodes)} nodes and {len(edges)} edges")
        
        # Initialize detection system
        print("\n2. Initializing detection system...")
        system = DeadlockDetectionSystem()
        print("   Using balanced configuration (default)")
        
        # Perform detection
        print("\n3. Detecting deadlocks...")
        results = system.detect_deadlocks(nodes, edges)
        
        # Display results
        print(f"\n4. Detection Results:")
        if results:
            print(f"   Found {len(results)} potential deadlocks:")
            
            for i, result in enumerate(results, 1):
                severity_icons = {
                    'LOW': '🟡',
                    'MEDIUM': '🟠',
                    'HIGH': '🔴', 
                    'CRITICAL': '💀'
                }
                icon = severity_icons.get(result.severity.name, '❓')
                
                print(f"\n   {i}. {icon} {result.conflict_type} between {result.node1_name} and {result.node2_name}")
                print(f"      Severity: {result.severity.name}")
                if result.confidence_score:
                    print(f"      Confidence: {result.confidence_score:.1%}")
                if result.affected_nodes:
                    print(f"      Affected nodes: {', '.join(result.affected_nodes)}")
                if result.details:
                    print(f"      Details: {result.details}")
        else:
            print("   ✅ No deadlocks detected!")
        
        print("\n✅ Test completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n❌ Error during test: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_basic_test()
    sys.exit(0 if success else 1)
