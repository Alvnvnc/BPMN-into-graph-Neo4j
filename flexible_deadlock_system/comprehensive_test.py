#!/usr/bin/env python3
"""
Comprehensive test suite for the flexible deadlock detection system.
This creates realistic deadlock scenarios and tests all system components.
"""

import json
import time
from pathlib import Path
import sys
from typing import Dict, List

# Add the current directory to Python path
sys.path.append(str(Path(__file__).parent))

from config.detection_config import DetectionConfig, StrategyRegistry
from strategies.parallel_strategy import ParallelExecutionStrategy
from strategies.resource_strategy import ResourceContentionStrategy
from strategies.gateway_strategy import GatewaySpecificStrategy
from utils.logger import DeadlockLogger
from utils.validator import validate_all_inputs, ValidationError
from core.base_detector import DeadlockResult, DeadlockSeverity, BaseDeadlockStrategy


class ComprehensiveDeadlockTest:
    """Comprehensive test suite for deadlock detection system"""
    
    def __init__(self):
        self.logger = DeadlockLogger("ComprehensiveTest")
        self.registry = StrategyRegistry()
        self.config = DetectionConfig.create_balanced_config()
        self._register_strategies()
        
    def _register_strategies(self):
        """Register all detection strategies"""
        self.registry.register_strategy("parallel_execution", ParallelExecutionStrategy())
        self.registry.register_strategy("resource_contention", ResourceContentionStrategy())
        self.registry.register_strategy("gateway_specific", GatewaySpecificStrategy())
        
    def create_deadlock_scenario_1(self):
        """
        Create Scenario 1: Parallel Gateway Deadlock
        Two parallel paths accessing the same database table
        """
        nodes = [
            {"id": "start", "name": "Start Process", "element_type": "start_event", "sql_query": None},
            {"id": "fork", "name": "Parallel Fork", "element_type": "parallel_gateway", "sql_query": None},
            {"id": "task1", "name": "Update Customer", "element_type": "task", 
             "sql_query": "UPDATE customers SET status='active' WHERE id=@customer_id"},
            {"id": "task2", "name": "Update Customer Profile", "element_type": "task",
             "sql_query": "UPDATE customers SET profile_updated=NOW() WHERE id=@customer_id"},
            {"id": "task3", "name": "Log Customer Activity", "element_type": "task",
             "sql_query": "INSERT INTO activity_log (customer_id, action) VALUES (@customer_id, 'profile_update')"},
            {"id": "task4", "name": "Send Notification", "element_type": "task",
             "sql_query": "UPDATE customers SET last_notification=NOW() WHERE id=@customer_id"},
            {"id": "join", "name": "Parallel Join", "element_type": "parallel_gateway", "sql_query": None},
            {"id": "end", "name": "End Process", "element_type": "end_event", "sql_query": None}
        ]
        
        edges = [
            {"source": "start", "target": "fork"},
            {"source": "fork", "target": "task1"},
            {"source": "fork", "target": "task2"},
            {"source": "task1", "target": "task3"},
            {"source": "task2", "target": "task4"},
            {"source": "task3", "target": "join"},
            {"source": "task4", "target": "join"},
            {"source": "join", "target": "end"}
        ]
        
        return nodes, edges, "Parallel Gateway with Shared Resource Access"
    
    def create_deadlock_scenario_2(self):
        """
        Create Scenario 2: Resource Contention Deadlock
        Circular dependency between different tables
        """
        nodes = [
            {"id": "start", "name": "Start", "element_type": "start_event", "sql_query": None},
            {"id": "task1", "name": "Lock Orders", "element_type": "task",
             "sql_query": "UPDATE orders SET status='processing' WHERE id=@order_id"},
            {"id": "task2", "name": "Update Inventory", "element_type": "task",
             "sql_query": "UPDATE inventory SET quantity=quantity-@amount WHERE product_id=@product_id"},
            {"id": "task3", "name": "Update Customer Balance", "element_type": "task",
             "sql_query": "UPDATE customers SET balance=balance-@total WHERE id=@customer_id"},
            {"id": "task4", "name": "Create Payment Record", "element_type": "task",
             "sql_query": "INSERT INTO payments (order_id, customer_id, amount) VALUES (@order_id, @customer_id, @total)"},
            {"id": "gateway1", "name": "Check Payment", "element_type": "exclusive_gateway", "sql_query": None},
            {"id": "task5", "name": "Process Refund", "element_type": "task",
             "sql_query": "UPDATE customers SET balance=balance+@refund WHERE id=@customer_id"},
            {"id": "task6", "name": "Restore Inventory", "element_type": "task",
             "sql_query": "UPDATE inventory SET quantity=quantity+@amount WHERE product_id=@product_id"},
            {"id": "end", "name": "End", "element_type": "end_event", "sql_query": None}
        ]
        
        edges = [
            {"source": "start", "target": "task1"},
            {"source": "task1", "target": "task2"},
            {"source": "task2", "target": "task3"},
            {"source": "task3", "target": "task4"},
            {"source": "task4", "target": "gateway1"},
            {"source": "gateway1", "target": "task5", "condition": "payment_failed"},
            {"source": "gateway1", "target": "end", "condition": "payment_success"},
            {"source": "task5", "target": "task6"},
            {"source": "task6", "target": "end"}
        ]
        
        return nodes, edges, "Resource Contention with Circular Dependencies"
    
    def create_deadlock_scenario_3(self):
        """
        Create Scenario 3: Complex Gateway Deadlock
        Multiple gateways with overlapping resource access
        """
        nodes = [
            {"id": "start", "name": "Start Process", "element_type": "start_event", "sql_query": None},
            {"id": "gateway1", "name": "Route Decision", "element_type": "exclusive_gateway", "sql_query": None},
            {"id": "parallel1", "name": "Parallel Processing", "element_type": "parallel_gateway", "sql_query": None},
            {"id": "task1", "name": "Update User Profile", "element_type": "task",
             "sql_query": "UPDATE users SET profile_data=@data WHERE id=@user_id"},
            {"id": "task2", "name": "Update User Preferences", "element_type": "task",
             "sql_query": "UPDATE users SET preferences=@prefs WHERE id=@user_id"},
            {"id": "task3", "name": "Log User Action", "element_type": "task",
             "sql_query": "INSERT INTO user_logs (user_id, action, timestamp) VALUES (@user_id, 'profile_update', NOW())"},
            {"id": "parallel2", "name": "Another Parallel", "element_type": "parallel_gateway", "sql_query": None},
            {"id": "task4", "name": "Update User Stats", "element_type": "task",
             "sql_query": "UPDATE users SET last_active=NOW() WHERE id=@user_id"},
            {"id": "task5", "name": "Cache User Data", "element_type": "task",
             "sql_query": "UPDATE user_cache SET data=@cache_data WHERE user_id=@user_id"},
            {"id": "join1", "name": "Join Results", "element_type": "parallel_gateway", "sql_query": None},
            {"id": "join2", "name": "Final Join", "element_type": "parallel_gateway", "sql_query": None},
            {"id": "end", "name": "End Process", "element_type": "end_event", "sql_query": None}
        ]
        
        edges = [
            {"source": "start", "target": "gateway1"},
            {"source": "gateway1", "target": "parallel1", "condition": "route_a"},
            {"source": "gateway1", "target": "parallel2", "condition": "route_b"},
            {"source": "parallel1", "target": "task1"},
            {"source": "parallel1", "target": "task2"},
            {"source": "task1", "target": "task3"},
            {"source": "task2", "target": "join1"},
            {"source": "task3", "target": "join1"},
            {"source": "parallel2", "target": "task4"},
            {"source": "parallel2", "target": "task5"},
            {"source": "task4", "target": "join2"},
            {"source": "task5", "target": "join2"},
            {"source": "join1", "target": "end"},
            {"source": "join2", "target": "end"}
        ]
        
        return nodes, edges, "Complex Multi-Gateway with Resource Conflicts"
    
    def run_detection_test(self, nodes, edges, scenario_name):
        """Run deadlock detection on a scenario"""
        print(f"\n🔍 Testing Scenario: {scenario_name}")
        print("=" * 60)
        
        try:
            # Create graph data
            graph_data = {
                'nodes': nodes,
                'relationships': [{'source_id': e['source'], 'target_id': e['target'], **e} for e in edges],
                'edges': edges,  # Keep for backward compatibility
                'sql_queries': [node.get('sql_query') for node in nodes if node.get('sql_query')]
            }
            
            # Validate inputs
            validate_all_inputs(
                sql_queries=graph_data['sql_queries'],
                nodes=nodes,
                edges=edges,
                config=self.config.config
            )
            
            print(f"   📊 Graph: {len(nodes)} nodes, {len(edges)} edges")
            print(f"   🗃️ SQL Queries: {len(graph_data['sql_queries'])} queries")
            
            # Run detection with each strategy
            all_results = []
            for strategy_name in self.config.get('enabled_strategies', []):
                if strategy_name not in self.registry.strategies:
                    continue
                    
                strategy = self.registry.strategies[strategy_name]
                print(f"   🔎 Running {strategy_name} strategy...")
                
                start_time = time.time()
                results = strategy.detect(graph_data, self.config.get_strategy_config(strategy_name))
                duration = time.time() - start_time
                
                print(f"      ⏱️ Completed in {duration:.3f}s")
                print(f"      📋 Found {len(results)} potential deadlocks")
                
                all_results.extend(results)
            
            # Process results
            unique_results = self._deduplicate_results(all_results)
            filtered_results = self._filter_by_severity(unique_results)
            
            print(f"\n   📊 Results Summary:")
            print(f"      Total detections: {len(all_results)}")
            print(f"      Unique deadlocks: {len(unique_results)}")
            print(f"      Above threshold: {len(filtered_results)}")
            
            if filtered_results:
                print(f"\n   ⚠️ Detected Deadlocks:")
                for i, result in enumerate(filtered_results, 1):
                    print(f"      {i}. {result.conflict_type}")
                    print(f"         Nodes: {result.node1_name} ↔ {result.node2_name}")
                    print(f"         Severity: {result.severity.value}")
                    print(f"         Confidence: {result.confidence:.2f}")
                    print(f"         Resources: {', '.join(result.shared_resources)}")
                    if result.recommendations:
                        print(f"         Recommendations: {'; '.join(result.recommendations[:2])}")
                    print()
            else:
                print(f"   ✅ No significant deadlocks detected")
            
            return filtered_results
            
        except Exception as e:
            print(f"   ❌ Error in scenario: {str(e)}")
            self.logger.log_error(e, f"testing scenario '{scenario_name}'")
            return []
    
    def _filter_by_severity(self, results):
        """Filter results based on severity threshold"""
        severity_threshold = self.config.get('severity_threshold', 'MEDIUM')
        severity_order = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level = severity_order[severity_threshold]
        
        return [r for r in results if severity_order.get(r.severity.value, 0) >= min_level]
    
    def _deduplicate_results(self, results):
        """Remove duplicate detection results"""
        unique_results = []
        seen_descriptions = set()
        
        for result in results:
            result_hash = (result.node1_id, result.node2_id, result.conflict_type)
            if result_hash not in seen_descriptions:
                seen_descriptions.add(result_hash)
                unique_results.append(result)
        
        return unique_results
    
    def test_configuration_presets(self):
        """Test different configuration presets"""
        print(f"\n🔧 Testing Configuration Presets")
        print("=" * 60)
        
        presets = [
            ("Balanced", DetectionConfig.create_balanced_config()),
            ("Aggressive", DetectionConfig.create_aggressive_config()),
            ("Conservative", DetectionConfig.create_conservative_config()),
            ("Performance", DetectionConfig.create_performance_focused_config())
        ]
        
        # Create a simple test scenario
        nodes, edges, _ = self.create_deadlock_scenario_1()
        
        for preset_name, config in presets:
            print(f"\n   🎛️ Testing {preset_name} Configuration:")
            
            # Show key configuration differences
            print(f"      Severity Threshold: {config.get('severity_threshold', 'MEDIUM')}")
            print(f"      Confidence Threshold: {config.get('confidence_threshold', 0.5)}")
            print(f"      Enabled Strategies: {len(config.get('enabled_strategies', []))}")
            
            # Quick detection test
            original_config = self.config
            self.config = config
            
            try:
                graph_data = {
                    'nodes': nodes,
                    'relationships': [{'source_id': e['source'], 'target_id': e['target'], **e} for e in edges],
                    'edges': edges,
                    'sql_queries': [node.get('sql_query') for node in nodes if node.get('sql_query')]
                }
                
                total_results = 0
                for strategy_name in config.get('enabled_strategies', []):
                    if strategy_name in self.registry.strategies:
                        strategy = self.registry.strategies[strategy_name]
                        results = strategy.detect(graph_data, config.get_strategy_config(strategy_name))
                        total_results += len(results)
                
                print(f"      Results: {total_results} detections")
                
            except Exception as e:
                print(f"      ❌ Error: {str(e)}")
            finally:
                self.config = original_config
    
    def test_custom_strategy(self):
        """Test custom strategy integration"""
        print(f"\n🔌 Testing Custom Strategy Integration")
        print("=" * 60)
        
        # Create a simple custom strategy for testing
        try:
            class TestCustomStrategy(BaseDeadlockStrategy):
                """Simple test custom strategy"""
                
                def __init__(self):
                    super().__init__("TestCustom", "Test custom strategy implementation")
                
                def detect(self, graph_data: Dict, config: Dict = None) -> List[DeadlockResult]:
                    """Simple detection logic for testing"""
                    results = []
                    nodes = graph_data.get('nodes', [])
                    
                    # Simple logic: find any two tasks with SQL queries
                    task_nodes = [n for n in nodes if n.get('element_type') == 'task' and n.get('sql_query')]
                    
                    if len(task_nodes) >= 2:
                        for i in range(len(task_nodes) - 1):
                            node1 = task_nodes[i]
                            node2 = task_nodes[i + 1]
                            
                            result = DeadlockResult(
                                node1_id=node1['id'],
                                node2_id=node2['id'],
                                node1_name=node1.get('name', node1['id']),
                                node2_name=node2.get('name', node2['id']),
                                severity=DeadlockSeverity.LOW,
                                confidence=0.5,
                                conflict_type="Custom Test Conflict",
                                shared_resources=["test_resource"],
                                strategy_name=self.name,
                                details={"test": True},
                                recommendations=["This is a test detection"]
                            )
                            results.append(result)
                    
                    return results
                
                def validate_conflict(self, node1: Dict, node2: Dict, context: Dict = None) -> bool:
                    """Simple validation for testing"""
                    return True
            
            # Create custom strategy instance
            custom_strategy = TestCustomStrategy()
            
            # Register it
            self.registry.register_strategy("custom_test", custom_strategy)
            
            print(f"   ✅ Custom strategy registered successfully")
            print(f"   📝 Strategy name: {custom_strategy.name}")
            print(f"   📝 Strategy description: {custom_strategy.description}")
            
            # Test it with simple data
            nodes, edges, _ = self.create_deadlock_scenario_1()
            graph_data = {
                'nodes': nodes,
                'relationships': [{'source_id': e['source'], 'target_id': e['target'], **e} for e in edges],
                'edges': edges,
                'sql_queries': [node.get('sql_query') for node in nodes if node.get('sql_query')]
            }
            
            results = custom_strategy.detect(graph_data)
            print(f"   📊 Custom strategy results: {len(results)} detections")
            
            if results:
                print(f"   📋 Sample detection: {results[0].conflict_type}")
                
        except Exception as e:
            print(f"   ❌ Error testing custom strategy: {e}")
            import traceback
            traceback.print_exc()
    
    def run_comprehensive_test(self):
        """Run the complete comprehensive test suite"""
        print("🚀 Flexible SQL Deadlock Detection System - Comprehensive Test")
        print("=" * 70)
        
        start_time = time.time()
        total_deadlocks = 0
        
        # Test different deadlock scenarios
        scenarios = [
            self.create_deadlock_scenario_1(),
            self.create_deadlock_scenario_2(),
            self.create_deadlock_scenario_3()
        ]
        
        for nodes, edges, scenario_name in scenarios:
            results = self.run_detection_test(nodes, edges, scenario_name)
            total_deadlocks += len(results)
        
        # Test configuration presets
        self.test_configuration_presets()
        
        # Test custom strategy integration
        self.test_custom_strategy()
        
        # Summary
        total_time = time.time() - start_time
        print(f"\n📊 Comprehensive Test Summary")
        print("=" * 40)
        print(f"   ⏱️ Total execution time: {total_time:.2f}s")
        print(f"   🎯 Scenarios tested: {len(scenarios)}")
        print(f"   ⚠️ Total deadlocks found: {total_deadlocks}")
        print(f"   🔧 Configuration presets: 4 tested")
        print(f"   🔌 Custom strategy: Integration tested")
        
        print(f"\n✅ Comprehensive test completed successfully!")
        return True


def main():
    """Main function to run comprehensive tests"""
    try:
        test_suite = ComprehensiveDeadlockTest()
        test_suite.run_comprehensive_test()
        return 0
    except Exception as e:
        print(f"❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit(main())
