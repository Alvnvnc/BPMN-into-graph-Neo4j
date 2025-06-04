"""
Main entry point for the Flexible SQL Deadlock Detection System.

This module provides a comprehensive interface for detecting various types of 
deadlocks in SQL execution workflows using configurable strategies.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import time

from config.detection_config import DetectionConfig, StrategyRegistry
from strategies.parallel_strategy import ParallelExecutionStrategy
from strategies.resource_strategy import ResourceContentionStrategy
from strategies.gateway_strategy import GatewaySpecificStrategy
from core.base_detector import DeadlockResult, DeadlockSeverity
from utils.logger import get_logger, set_log_level, log_system_info
from utils.validator import validate_all_inputs, ValidationError


class DeadlockDetectionSystem:
    """
    Main system orchestrator for flexible deadlock detection.
    """
    
    def __init__(self, config_path: Optional[str] = None):
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
    
    def load_config(self, config_path: str):
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
    
    def detect_deadlocks(
        self, 
        nodes: List[Dict[str, Any]], 
        edges: List[Dict[str, Any]],
        sql_queries: Optional[List[str]] = None
    ) -> List[DeadlockResult]:
        """
        Detect deadlocks using configured strategies.
        
        Args:
            nodes: List of workflow nodes
            edges: List of workflow edges
            sql_queries: Optional list of SQL queries to analyze
        
        Returns:
            List of detected deadlocks
        """
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
                        'relationships': [{'source_id': e['source'], 'target_id': e['target'], **e} for e in edges],
                        'edges': edges,
                        'sql_queries': sql_queries or []
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
    
    def _filter_by_severity(self, results: List[DeadlockResult]) -> List[DeadlockResult]:
        """Filter results based on minimum severity threshold."""
        severity_threshold = self.config.get('severity_threshold', 'MEDIUM')
        if not severity_threshold:
            return results
        
        min_severity = DeadlockSeverity[severity_threshold]
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_order[min_severity.value]
        
        return [r for r in results if severity_order.get(r.severity.value, 0) >= min_level]
    
    def _deduplicate_results(self, results: List[DeadlockResult]) -> List[DeadlockResult]:
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
    
    def save_results(self, results: List[DeadlockResult], output_path: str):
        """
        Save detection results to file.
        
        Args:
            results: List of detection results
            output_path: Path to output file
        """
        try:
            output_data = {
                'timestamp': time.time(),
                'total_deadlocks': len(results),
                'deadlocks': [
                    {
                        'description': f"{result.conflict_type} between {result.node1_name} and {result.node2_name}",
                        'severity': result.severity.name,
                        'confidence': result.confidence,
                        'strategy_name': result.strategy_name,
                        'shared_resources': result.shared_resources,
                        'node1_id': result.node1_id,
                        'node2_id': result.node2_id,
                        'node1_name': result.node1_name,
                        'node2_name': result.node2_name,
                        'conflict_type': result.conflict_type,
                        'details': result.details,
                        'recommendations': result.recommendations
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


def load_graph_data(file_path: str) -> tuple[List[Dict], List[Dict]]:
    """
    Load graph data from JSON file.
    
    Args:
        file_path: Path to graph data file
        
    Returns:
        Tuple of (nodes, edges)
    """
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    nodes = data.get('nodes', [])
    edges = data.get('edges', [])
    
    return nodes, edges


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Flexible SQL Deadlock Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic detection with default config
  python -m flexible_deadlock_system.main --graph data.json
  
  # Detection with custom config
  python -m flexible_deadlock_system.main --graph data.json --config config.json
  
  # Detection with SQL queries
  python -m flexible_deadlock_system.main --graph data.json --sql queries.json
  
  # Save results to file
  python -m flexible_deadlock_system.main --graph data.json --output results.json
  
  # Enable debug logging
  python -m flexible_deadlock_system.main --graph data.json --verbose
        """
    )
    
    parser.add_argument(
        '--graph', 
        required=True,
        help='Path to JSON file containing graph data (nodes and edges)'
    )
    
    parser.add_argument(
        '--config',
        help='Path to configuration JSON file'
    )
    
    parser.add_argument(
        '--sql',
        help='Path to JSON file containing SQL queries to analyze'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Path to save detection results'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--preset',
        choices=['aggressive', 'balanced', 'conservative'],
        default='balanced',
        help='Use a preset configuration (default: balanced)'
    )
    
    args = parser.parse_args()
    
    # Set logging level
    if args.verbose:
        set_log_level('DEBUG')
        log_system_info()
    
    try:
        # Initialize detection system
        if args.config:
            system = DeadlockDetectionSystem(args.config)
        else:
            system = DeadlockDetectionSystem()
            
            # Use preset configuration
            if args.preset == 'aggressive':
                system.config = DetectionConfig.create_aggressive_config()
            elif args.preset == 'conservative':
                system.config = DetectionConfig.create_conservative_config()
            # balanced is already default
        
        # Load graph data
        print(f"Loading graph data from {args.graph}...")
        nodes, edges = load_graph_data(args.graph)
        print(f"Loaded {len(nodes)} nodes and {len(edges)} edges")
        
        # Load SQL queries if provided
        sql_queries = None
        if args.sql:
            print(f"Loading SQL queries from {args.sql}...")
            with open(args.sql, 'r') as f:
                sql_data = json.load(f)
            sql_queries = sql_data.get('queries', [])
            print(f"Loaded {len(sql_queries)} SQL queries")
        
        # Perform detection
        print("\n🔍 Starting deadlock detection...")
        results = system.detect_deadlocks(nodes, edges, sql_queries)
        
        # Display results
        if results:
            print(f"\n⚠️  Found {len(results)} potential deadlocks:")
            print("=" * 60)
            
            for i, result in enumerate(results, 1):
                severity_emoji = {
                    'LOW': '🟡',
                    'MEDIUM': '🟠', 
                    'HIGH': '🔴',
                    'CRITICAL': '💀'
                }
                emoji = severity_emoji.get(result.severity.name, '❓')
                
                print(f"{i}. {emoji} {result.conflict_type} between {result.node1_name} and {result.node2_name}")
                print(f"   Severity: {result.severity.name}")
                if result.confidence:
                    print(f"   Confidence: {result.confidence:.1%}")
                if result.shared_resources:
                    print(f"   Shared resources: {', '.join(result.shared_resources)}")
                print()
        else:
            print("\n✅ No deadlocks detected!")
        
        # Save results if requested
        if args.output:
            system.save_results(results, args.output)
            print(f"📄 Results saved to {args.output}")
        
        # Exit with appropriate code
        sys.exit(1 if results else 0)
        
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}", file=sys.stderr)
        sys.exit(1)
    except ValidationError as e:
        print(f"❌ Validation error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
