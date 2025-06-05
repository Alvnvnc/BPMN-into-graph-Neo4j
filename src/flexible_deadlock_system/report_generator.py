#!/usr/bin/env python3
"""
Report Generator Module
Handles formatting and generation of deadlock analysis reports.
Refactored from backup_sql.py for modular architecture.
"""

import json
import logging
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path

logger = logging.getLogger(__name__)

class ReportGenerator:
    """
    Generates comprehensive reports for deadlock analysis results
    """
    
    def __init__(self, output_dir: str = "results"):
        """
        Initialize the report generator
        
        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        logger.debug(f"Initializing ReportGenerator with output directory: {self.output_dir}")
    
    def generate_comprehensive_report(self, analysis_results: Dict, 
                                    parallel_scenarios: List[Dict],
                                    sql_resources: Dict) -> Dict:
        """
        Generate a comprehensive deadlock analysis report
        
        Args:
            analysis_results: Results from deadlock analysis
            parallel_scenarios: Parallel execution scenarios
            sql_resources: SQL resources data
            
        Returns:
            Dict: Generated report data
        """
        logger.info("Generating comprehensive deadlock analysis report...")
        
        report = {
            'metadata': self._generate_metadata(),
            'summary': self._generate_summary(analysis_results, parallel_scenarios, sql_resources),
            'deadlock_analysis': self._format_deadlock_analysis(analysis_results),
            'parallel_scenarios': self._format_parallel_scenarios(parallel_scenarios),
            'sql_resources': self._format_sql_resources(sql_resources),
            'recommendations': self._generate_recommendations(analysis_results)
        }
        
        # Save report to file
        report_file = self.output_dir / f"deadlock_analysis_report_{self.timestamp}.json"
        self._save_json_report(report, report_file)
        
        logger.info(f"Comprehensive report saved to: {report_file}")
        return report
    
    def generate_conflict_report(self, conflict_results: Dict, sql_resources: Dict) -> Dict:
        """
        Generate a conflict-only analysis report
        
        Args:
            conflict_results: Results from conflict analysis
            sql_resources: SQL resources data
            
        Returns:
            Dict: Generated conflict report
        """
        logger.info("Generating conflict analysis report...")
        
        report = {
            'metadata': self._generate_metadata(),
            'summary': self._generate_conflict_summary(conflict_results, sql_resources),
            'conflict_analysis': conflict_results,
            'sql_resources': self._format_sql_resources(sql_resources),
            'recommendations': self._generate_conflict_recommendations(conflict_results)
        }
        
        # Save report to file
        report_file = self.output_dir / f"conflict_analysis_report_{self.timestamp}.json"
        self._save_json_report(report, report_file)
        
        logger.info(f"Conflict report saved to: {report_file}")
        return report
    
    def print_summary(self, analysis_results: Dict, parallel_scenarios: List[Dict], 
                     sql_resources: Dict, analysis_type: str = "full"):
        """
        Print a formatted summary to console
        
        Args:
            analysis_results: Analysis results
            parallel_scenarios: Parallel scenarios (for full analysis)
            sql_resources: SQL resources
            analysis_type: Type of analysis ("full" or "conflict")
        """
        print("\n" + "="*80)
        print(f"DEADLOCK ANALYSIS SUMMARY - {analysis_type.upper()} MODE")
        print("="*80)
        
        if analysis_type == "full":
            self._print_full_summary(analysis_results, parallel_scenarios, sql_resources)
        else:
            self._print_conflict_summary(analysis_results, sql_resources)
        
        print("="*80)
    
    def _generate_metadata(self) -> Dict:
        """
        Generate report metadata
        
        Returns:
            Dict: Metadata information
        """
        return {
            'generated_at': datetime.now().isoformat(),
            'timestamp': self.timestamp,
            'version': '2.0',
            'analysis_tool': 'SQL Deadlock Detector'
        }
    
    def _generate_summary(self, analysis_results: Dict, parallel_scenarios: List[Dict], 
                         sql_resources: Dict) -> Dict:
        """
        Generate analysis summary
        
        Args:
            analysis_results: Analysis results
            parallel_scenarios: Parallel scenarios
            sql_resources: SQL resources
            
        Returns:
            Dict: Summary data
        """
        deadlock_cycles = analysis_results.get('deadlock_cycles', [])
        conflict_analysis = analysis_results.get('conflict_analysis', {})
        
        return {
            'total_sql_nodes': len(sql_resources),
            'total_parallel_scenarios': len(parallel_scenarios),
            'deadlock_cycles_found': len(deadlock_cycles),
            'total_conflicts': conflict_analysis.get('total_conflicts', 0),
            'critical_conflicts': conflict_analysis.get('critical_conflicts', 0),
            'high_severity_conflicts': conflict_analysis.get('high_conflicts', 0),
            'medium_severity_conflicts': conflict_analysis.get('medium_conflicts', 0),
            'low_severity_conflicts': conflict_analysis.get('low_conflicts', 0),
            'risk_level': self._calculate_risk_level(deadlock_cycles, conflict_analysis)
        }
    
    def _generate_conflict_summary(self, conflict_results: Dict, sql_resources: Dict) -> Dict:
        """
        Generate conflict analysis summary
        
        Args:
            conflict_results: Conflict analysis results
            sql_resources: SQL resources
            
        Returns:
            Dict: Conflict summary
        """
        conflict_analysis = conflict_results.get('conflict_analysis', {})
        
        return {
            'total_sql_nodes': len(sql_resources),
            'total_conflicts': conflict_results.get('conflicts_found', 0),
            'critical_conflicts': conflict_analysis.get('severity_distribution', {}).get('CRITICAL', 0),
            'high_severity_conflicts': conflict_analysis.get('severity_distribution', {}).get('HIGH', 0),
            'medium_severity_conflicts': conflict_analysis.get('severity_distribution', {}).get('MEDIUM', 0),
            'low_severity_conflicts': conflict_analysis.get('severity_distribution', {}).get('LOW', 0),
            'tables_involved': conflict_analysis.get('unique_table_conflicts', 0),
            'risk_level': self._calculate_conflict_risk_level(conflict_analysis)
        }
    
    def _format_deadlock_analysis(self, analysis_results: Dict) -> Dict:
        """
        Format deadlock analysis results
        
        Args:
            analysis_results: Raw analysis results
            
        Returns:
            Dict: Formatted deadlock analysis
        """
        return {
            'deadlock_cycles': analysis_results.get('deadlock_cycles', []),
            'deadlock_risks': analysis_results.get('deadlock_risks', []),
            'conflict_analysis': analysis_results.get('conflict_analysis', {}),
            'detected_conflicts': analysis_results.get('detected_conflicts', []),
            'graph_statistics': {
                'resource_graph': analysis_results.get('resource_graph_stats', {}),
                'wait_for_graph': analysis_results.get('wait_for_graph_stats', {})
            }
        }
    
    def _format_parallel_scenarios(self, parallel_scenarios: List[Dict]) -> Dict:
        """
        Format parallel scenarios data
        
        Args:
            parallel_scenarios: List of parallel scenarios
            
        Returns:
            Dict: Formatted scenarios data
        """
        scenario_types = {}
        total_paths = 0
        
        for scenario in parallel_scenarios:
            gateway_type = scenario['gateway_type']
            scenario_types[gateway_type] = scenario_types.get(gateway_type, 0) + 1
            total_paths += len(scenario['paths'])
        
        return {
            'total_scenarios': len(parallel_scenarios),
            'scenario_types': scenario_types,
            'total_paths': total_paths,
            'scenarios': parallel_scenarios
        }
    
    def _format_sql_resources(self, sql_resources: Dict) -> Dict:
        """
        Format SQL resources data
        
        Args:
            sql_resources: SQL resources dictionary
            
        Returns:
            Dict: Formatted SQL resources
        """
        operation_counts = {}
        table_usage = {}
        
        for node_id, resource_data in sql_resources.items():
            logger.debug(f"Formatting node {node_id}, data type: {type(resource_data)}")
            
            # Ensure resource_data is a dictionary
            if not isinstance(resource_data, dict):
                logger.warning(f"Node {node_id} has invalid data type: {type(resource_data)}. Skipping.")
                continue
            
            resources = resource_data.get('resources', {})
            
            # Count operations (handle both sets and lists)
            operations = resources.get('operations', set())
            if isinstance(operations, set):
                operations = list(operations)
            
            for operation in operations:
                operation_counts[operation] = operation_counts.get(operation, 0) + 1
            
            # Count table usage (handle both sets and lists)
            tables = resources.get('tables', set())
            if isinstance(tables, set):
                tables = list(tables)
            
            for table in tables:
                table_usage[table] = table_usage.get(table, 0) + 1
        
        return {
            'total_sql_nodes': len(sql_resources),
            'operation_distribution': operation_counts,
            'table_usage': table_usage,
            'most_used_tables': sorted(table_usage.items(), key=lambda x: x[1], reverse=True)[:5],
            'nodes': sql_resources
        }
    
    def _generate_recommendations(self, analysis_results: Dict) -> List[Dict]:
        """
        Generate recommendations based on analysis results
        
        Args:
            analysis_results: Analysis results
            
        Returns:
            List[Dict]: List of recommendations
        """
        recommendations = []
        
        deadlock_cycles = analysis_results.get('deadlock_cycles', [])
        conflict_analysis = analysis_results.get('conflict_analysis', {})
        
        # Deadlock-specific recommendations
        if deadlock_cycles:
            recommendations.append({
                'type': 'CRITICAL',
                'category': 'DEADLOCK_PREVENTION',
                'title': 'Deadlock Cycles Detected',
                'description': f'Found {len(deadlock_cycles)} potential deadlock cycles. Immediate attention required.',
                'actions': [
                    'Review transaction ordering in parallel paths',
                    'Consider implementing timeout mechanisms',
                    'Analyze resource acquisition patterns',
                    'Implement deadlock detection and recovery'
                ]
            })
        
        # High-severity conflict recommendations
        critical_conflicts = conflict_analysis.get('critical_conflicts', 0)
        if critical_conflicts > 0:
            recommendations.append({
                'type': 'HIGH',
                'category': 'CONFLICT_RESOLUTION',
                'title': 'Critical Resource Conflicts',
                'description': f'Found {critical_conflicts} critical conflicts requiring immediate attention.',
                'actions': [
                    'Implement proper locking mechanisms',
                    'Consider transaction isolation levels',
                    'Review concurrent access patterns',
                    'Add conflict detection logic'
                ]
            })
        
        # General optimization recommendations
        total_conflicts = conflict_analysis.get('total_conflicts', 0)
        if total_conflicts > 0:
            recommendations.append({
                'type': 'MEDIUM',
                'category': 'OPTIMIZATION',
                'title': 'Performance Optimization',
                'description': 'Consider optimizations to reduce resource contention.',
                'actions': [
                    'Optimize SQL query performance',
                    'Review indexing strategies',
                    'Consider read replicas for read-heavy operations',
                    'Implement connection pooling'
                ]
            })
        
        return recommendations
    
    def _generate_conflict_recommendations(self, conflict_results: Dict) -> List[Dict]:
        """
        Generate recommendations for conflict analysis
        
        Args:
            conflict_results: Conflict analysis results
            
        Returns:
            List[Dict]: List of recommendations
        """
        recommendations = []
        conflict_analysis = conflict_results.get('conflict_analysis', {})
        
        critical_conflicts = conflict_analysis.get('severity_distribution', {}).get('CRITICAL', 0)
        high_conflicts = conflict_analysis.get('severity_distribution', {}).get('HIGH', 0)
        
        if critical_conflicts > 0:
            recommendations.append({
                'type': 'CRITICAL',
                'category': 'IMMEDIATE_ACTION',
                'title': 'Critical Conflicts Detected',
                'description': f'Found {critical_conflicts} critical conflicts requiring immediate attention.',
                'actions': [
                    'Review parallel execution paths',
                    'Implement proper synchronization',
                    'Consider sequential execution for critical operations'
                ]
            })
        
        if high_conflicts > 0:
            recommendations.append({
                'type': 'HIGH',
                'category': 'CONFLICT_MITIGATION',
                'title': 'High-Priority Conflicts',
                'description': f'Found {high_conflicts} high-priority conflicts.',
                'actions': [
                    'Implement resource locking strategies',
                    'Review transaction boundaries',
                    'Consider optimistic locking'
                ]
            })
        
        return recommendations
    
    def _calculate_risk_level(self, deadlock_cycles: List, conflict_analysis: Dict) -> str:
        """
        Calculate overall risk level
        
        Args:
            deadlock_cycles: List of deadlock cycles
            conflict_analysis: Conflict analysis data
            
        Returns:
            str: Risk level (CRITICAL, HIGH, MEDIUM, LOW)
        """
        if deadlock_cycles:
            return 'CRITICAL'
        
        critical_conflicts = conflict_analysis.get('critical_conflicts', 0)
        high_conflicts = conflict_analysis.get('high_conflicts', 0)
        
        if critical_conflicts > 0:
            return 'CRITICAL'
        elif high_conflicts > 0:
            return 'HIGH'
        elif conflict_analysis.get('total_conflicts', 0) > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _calculate_conflict_risk_level(self, conflict_analysis: Dict) -> str:
        """
        Calculate risk level for conflict analysis
        
        Args:
            conflict_analysis: Conflict analysis data
            
        Returns:
            str: Risk level
        """
        severity_dist = conflict_analysis.get('severity_distribution', {})
        
        if severity_dist.get('CRITICAL', 0) > 0:
            return 'CRITICAL'
        elif severity_dist.get('HIGH', 0) > 0:
            return 'HIGH'
        elif severity_dist.get('MEDIUM', 0) > 0:
            return 'MEDIUM'
        elif severity_dist.get('LOW', 0) > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def _save_json_report(self, report: Dict, file_path: Path):
        """
        Save report as JSON file
        
        Args:
            report: Report data
            file_path: Output file path
        """
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"Report saved successfully to {file_path}")
        except Exception as e:
            logger.error(f"Error saving report to {file_path}: {e}")
    
    def _print_full_summary(self, analysis_results: Dict, parallel_scenarios: List[Dict], 
                           sql_resources: Dict):
        """
        Print full analysis summary focused on deadlock node combinations
        
        Args:
            analysis_results: Analysis results
            parallel_scenarios: Parallel scenarios
            sql_resources: SQL resources
        """
        deadlock_cycles = analysis_results.get('deadlock_cycles', [])
        conflict_analysis = analysis_results.get('conflict_analysis', {})
        
        print(f"\nSQL Nodes Analyzed: {len(sql_resources)}")
        print(f"Conflicts Found: {conflict_analysis.get('total_conflicts', 0)}")
        print(f"Tables Involved: {conflict_analysis.get('unique_table_conflicts', 0)}")
        
        # Severity breakdown
        severity_dist = conflict_analysis.get('severity_distribution', {})
        print("\nConflict Severity Breakdown:")
        print(f"  Critical: {severity_dist.get('CRITICAL', 0)}")
        print(f"  High: {severity_dist.get('HIGH', 0)}")
        print(f"  Medium: {severity_dist.get('MEDIUM', 0)}")
        print(f"  Low: {severity_dist.get('LOW', 0)}")
        
        # Display detailed node combinations immediately after severity breakdown
        total_conflicts = conflict_analysis.get('total_conflicts', 0)
        if total_conflicts > 0:
            self._print_detailed_conflicts(analysis_results, sql_resources)
        
        # Risk assessment
        risk_level = self._calculate_risk_level(deadlock_cycles, conflict_analysis)
        print(f"Overall Risk Level: {risk_level}")
        
        # Show deadlock cycles if any
        if deadlock_cycles:
            print(f"\nDeadlock Cycles Found: {len(deadlock_cycles)}")
            for i, cycle in enumerate(deadlock_cycles, 1):
                print(f"  Cycle {i}: {' -> '.join(cycle)}")
        else:
            print(f"\n✅ No deadlock cycles detected")
    
    def _print_conflict_summary(self, conflict_results: Dict, sql_resources: Dict):
        """
        Print conflict analysis summary
        
        Args:
            conflict_results: Conflict results
            sql_resources: SQL resources
        """
        conflict_analysis = conflict_results.get('conflict_analysis', {})
        
        print(f"\nSQL Nodes Analyzed: {len(sql_resources)}")
        print(f"Conflicts Found: {conflict_analysis.get('total_conflicts', 0)}")
        print(f"Tables Involved: {conflict_analysis.get('unique_table_conflicts', 0)}")
        
        # Severity breakdown
        severity_dist = conflict_analysis.get('severity_distribution', {})
        print("\nConflict Severity Breakdown:")
        print(f"  Critical: {severity_dist.get('CRITICAL', 0)}")
        print(f"  High: {severity_dist.get('HIGH', 0)}")
        print(f"  Medium: {severity_dist.get('MEDIUM', 0)}")
        print(f"  Low: {severity_dist.get('LOW', 0)}")
        
        # Display detailed node combinations immediately after severity breakdown
        total_conflicts = conflict_analysis.get('total_conflicts', 0)
        if total_conflicts > 0:
            self._print_detailed_conflicts(conflict_results, sql_resources)
        
        # Risk assessment
        risk_level = self._calculate_conflict_risk_level(conflict_analysis)
        print(f"\nOverall Risk Level: {risk_level}")

    def _print_detailed_conflicts(self, conflict_results: Dict, sql_resources: Dict):
        """
        Print detailed information about each conflict including node combinations
        
        Args:
            conflict_results: Conflict results
            sql_resources: SQL resources
        """
        print("\n" + "="*70)
        print("DETAILED CONFLICT NODE COMBINATIONS")
        print("="*70)
        
        # Try to get conflicts from different possible sources
        conflicts = conflict_results.get('conflicts', [])
        if not conflicts:
            conflicts = conflict_results.get('detected_conflicts', [])
        
        if not conflicts:
            print("No detailed conflict information available.")
            return
        
        for i, conflict in enumerate(conflicts, 1):
            severity = conflict.get('severity', 'UNKNOWN')
            conflict_type = conflict.get('conflict_type', 'UNKNOWN')
            
            # Get node information
            node1_id = conflict.get('node1_id', 'Unknown')
            node2_id = conflict.get('node2_id', 'Unknown')
            node1_name = conflict.get('node1_name', 'Unknown')
            node2_name = conflict.get('node2_name', 'Unknown')
            
            # Get additional details from SQL resources if available
            node1_info = sql_resources.get(node1_id, {})
            node2_info = sql_resources.get(node2_id, {})
            
            print(f"\n🔍 CONFLICT #{i} - {severity} SEVERITY")
            print(f"   Conflict Type: {conflict_type}")
            print(f"   Node Combination: '{node1_name}' ↔ '{node2_name}'")
            print(f"   Node IDs: {node1_id} ↔ {node2_id}")
            
            # Show table information
            if 'conflicting_resources' in conflict:
                resources = conflict['conflicting_resources']
                if 'tables' in resources and resources['tables']:
                    print(f"   Tables Involved: {', '.join(resources['tables'])}")
                if 'shared_columns' in resources and resources['shared_columns']:
                    print(f"   Shared Columns: {', '.join(resources['shared_columns'])}")
            
            # Show scenario information
            if 'scenario_type' in conflict:
                print(f"   Scenario Type: {conflict['scenario_type']}")
            
            # Show operations if available
            if node1_info.get('resources'):
                ops1 = node1_info['resources'].get('operations', set())
                if ops1:
                    print(f"   Node 1 Operations: {', '.join(ops1)}")
            
            if node2_info.get('resources'):
                ops2 = node2_info['resources'].get('operations', set())
                if ops2:
                    print(f"   Node 2 Operations: {', '.join(ops2)}")
        
        print("\n" + "="*70)