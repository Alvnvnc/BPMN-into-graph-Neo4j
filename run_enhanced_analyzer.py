#!/usr/bin/env python3
"""
Enhanced SQL Deadlock Analyzer Runner
Runs the enhanced deadlock detector with dynamic configuration
"""
import sys
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.enhanced_sql_deadlock_simple import EnhancedSQLDeadlockDetector
from src.dynamic_config_simple import create_default_config, save_config_template
import logging

def main():
    """Main runner function"""
    print("🔍 Enhanced SQL Deadlock Analyzer")
    print("=" * 50)
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    
    try:
        # Generate configuration template if needed
        config_template_path = "config_template.json"
        if not Path(config_template_path).exists():
            print(f"📄 Generating configuration template: {config_template_path}")
            save_config_template(config_template_path)
        
        # Initialize enhanced detector
        print("🚀 Initializing Enhanced SQL Deadlock Detector...")
        detector = EnhancedSQLDeadlockDetector()
        
        print(f"📡 Connected to Neo4j: {detector.config.database.uri}")
        print(f"🔧 SQL Field: {detector.config.node_fields.sql_field}")
        print(f"📊 Max Cycle Length: {detector.config.deadlock.max_cycle_length}")
        print(f"🔗 BPMN Relationships: {', '.join(detector.config.bpmn.relationship_types)}")
        
        # Run complete analysis
        print("\\n🔄 Running comprehensive deadlock analysis...")
        report_path = detector.run_analysis()
        
        # Display results
        print("\\n" + "=" * 50)
        print("📈 ANALYSIS RESULTS")
        print("=" * 50)
        
        print(f"📊 Total SQL Nodes Analyzed: {len(detector.sql_analysis)}")
        print(f"🔗 BPMN Relationships Found: {len(detector.bpmn_relationships)}")
        print(f"📋 Resources Analyzed: {len(detector.resource_locks)}")
        
        total_paths = sum(len(paths) for paths in detector.execution_paths.values())
        print(f"🛤️  Execution Paths Found: {total_paths}")
        
        if detector.deadlock_cycles:
            print(f"\\n⚠️  DEADLOCK CYCLES DETECTED: {len(detector.deadlock_cycles)}")
            print("-" * 30)
            
            for cycle in detector.deadlock_cycles:
                print(f"\\n🔴 Cycle {cycle.cycle_id}: {cycle.severity} Severity")
                print(f"   📝 Description: {cycle.description}")
                print(f"   📊 Impact: {cycle.potential_impact}")
                print(f"   🗃️  Resources: {', '.join(cycle.resources_involved)}")
                print(f"   🔗 Nodes involved:")
                
                for node in cycle.nodes:
                    print(f"      - {node.name} ({node.node_id})")
                    print(f"        Tables: {', '.join(node.tables)}")
                    print(f"        Operations: {', '.join(node.operations)}")
                    print(f"        Locks: {', '.join(node.lock_types)}")
                    print(f"        Complexity: {node.complexity}")
        else:
            print("\\n✅ NO DEADLOCK CYCLES DETECTED")
            print("   The system appears to be free of SQL deadlock risks")
        
        # Resource conflicts summary
        conflicts = {
            resource: list(locks.keys()) 
            for resource, locks in detector.resource_locks.items() 
            if len(locks) > 1
        }
        
        if conflicts:
            print(f"\\n⚡ RESOURCE CONFLICTS FOUND: {len(conflicts)}")
            print("-" * 30)
            for resource, nodes in conflicts.items():
                print(f"   🗃️  {resource}: {', '.join(nodes)}")
        
        # SQL Analysis Summary
        if detector.sql_analysis:
            print(f"\\n🔍 SQL ANALYSIS SUMMARY")
            print("-" * 30)
            
            complexities = {}
            operations = {}
            
            for node_id, analysis in detector.sql_analysis.items():
                complexity = analysis.get('complexity', 'UNKNOWN')
                complexities[complexity] = complexities.get(complexity, 0) + 1
                
                for op in analysis.get('operations', []):
                    operations[op] = operations.get(op, 0) + 1
            
            print("   📊 Complexity Distribution:")
            for complexity, count in complexities.items():
                print(f"      - {complexity}: {count} nodes")
            
            print("   🔧 Operation Distribution:")
            for operation, count in operations.items():
                print(f"      - {operation}: {count} occurrences")
        
        print(f"\\n📄 Detailed report saved to: {report_path}")
        print("\\n✨ Analysis completed successfully!")
        
        detector.close()
        
    except Exception as e:
        print(f"\\n❌ Analysis failed: {e}")
        logging.error(f"Analysis failed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
