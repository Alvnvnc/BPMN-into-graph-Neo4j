#!/usr/bin/env python3
"""
Main Entry Point for Flexible Deadlock Detection System
Orchestrates the deadlock detection process using modular components.
Refactored from backup_sql.py for improved maintainability and flexibility.
"""

import logging
import sys
import json
from pathlib import Path
from datetime import datetime

# Add the current directory to Python path for imports
sys.path.append(str(Path(__file__).parent))

try:
    from neo4j_connector import Neo4jConnector
    from sql_resource_extractor import SQLResourceExtractor
    from parallel_path_analyzer import ParallelPathAnalyzer
    from deadlock_detector import DeadlockDetector
    from report_generator import ReportGenerator
    # Import from parent directory
    sys.path.append(str(Path(__file__).parent.parent))
    from config import NEO4J_CONFIG, ANALYSIS_CONFIG
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure all required modules are in the same directory.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,  # Changed to INFO to reduce noise
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('deadlock_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def main():
    """
    Main function to orchestrate the deadlock detection process
    """
    logger.info("Starting Flexible Deadlock Detection System...")
    
    neo4j_connector = None
    
    try:
        # Initialize components
        logger.info("Initializing system components...")
        neo4j_connector = Neo4jConnector(NEO4J_CONFIG)
        sql_extractor = SQLResourceExtractor()
        path_analyzer = ParallelPathAnalyzer()
        report_generator = ReportGenerator()
        
        # Test Neo4j connection
        logger.info("Testing Neo4j connection...")
        if not neo4j_connector.test_connection():
            logger.error("Failed to connect to Neo4j. Please check your connection settings.")
            return False
        
        # Fetch graph data
        logger.info("Fetching graph data from Neo4j...")
        graph_data = neo4j_connector.fetch_graph_data()
        
        if not graph_data or not graph_data.get('nodes'):
            logger.warning("No graph data found in Neo4j database.")
            return False
        
        logger.info(f"Found {len(graph_data['nodes'])} nodes and {len(graph_data.get('relationships', []))} relationships")
        
        # Extract SQL resources
        logger.info("Extracting SQL resources from graph data...")
        sql_resources = sql_extractor.extract_from_graph_data(graph_data)
        
        logger.info(f"Extracted SQL resources from {len(sql_resources)} nodes")
        
        if not sql_resources:
            logger.warning("No SQL resources found in the graph data.")
            # Still continue with analysis to generate a report
        
        # Analyze parallel paths
        logger.info("Analyzing parallel execution paths...")
        parallel_scenarios = path_analyzer.identify_parallel_scenarios(graph_data)
        
        logger.info(f"Identified {len(parallel_scenarios)} parallel execution scenarios")
        
        # Initialize deadlock detector
        deadlock_detector = DeadlockDetector(graph_data, sql_resources, neo4j_connector)
          # Determine analysis mode
        analysis_mode = ANALYSIS_CONFIG.get('mode', 'standard')
        logger.info(f"Running analysis in '{analysis_mode}' mode")
        
        if analysis_mode == 'conflict_only':
            # Run conflict-only analysis
            logger.info("Executing conflict-only analysis...")
            results = deadlock_detector.run_conflict_detection_only()
            
            # Generate and print report
            report = report_generator.generate_conflict_report(results, sql_resources)
            report_generator.print_summary(results, [], sql_resources, "conflict")
            
        else:
            # Run standard deadlock analysis only
            logger.info("Executing standard deadlock analysis...")
            results = deadlock_detector.analyze_deadlocks(parallel_scenarios)
            
            # Generate and print report
            report = report_generator.generate_comprehensive_report(results, parallel_scenarios, sql_resources)
            report_generator.print_summary(results, parallel_scenarios, sql_resources, "standard")
        
        logger.info("Deadlock analysis completed successfully.")
        logger.info(f"Reports saved to: {report_generator.output_dir}")
        return True
        
    except Exception as e:
        logger.error(f"Error during deadlock analysis: {e}")
        logger.exception("Full error traceback:")
        return False
    
    finally:
        # Close Neo4j connection
        if neo4j_connector:
            try:
                neo4j_connector.close()
                logger.info("Neo4j connection closed.")
            except Exception as e:
                logger.warning(f"Error closing Neo4j connection: {e}")

def display_results(report):
    """
    Display the analysis results in a formatted manner
    """
    print("\n" + "="*60)
    print("    ANALYSIS RESULTS")
    print("="*60)
    
    summary = report['summary']
    
    print(f"\n[SUMMARY]:")
    print(f"   • Total Nodes: {summary['total_nodes']}")
    print(f"   • SQL Nodes: {summary['sql_nodes']}")
    print(f"   • Parallel Scenarios: {summary['parallel_scenarios']}")
    print(f"   • Potential Deadlocks: {summary['deadlock_conflicts']}")
    
    # Display deadlock details if any
    if summary['deadlock_conflicts'] > 0:
        print(f"\n[WARNING] DEADLOCK CONFLICTS DETECTED:")
        for i, conflict in enumerate(report['deadlock_conflicts'], 1):
            print(f"   {i}. {conflict['conflict_type']} - Severity: {conflict['severity']}")
            print(f"      Tables: {', '.join(conflict['conflicting_resources']['tables'])}")
            print(f"      Path 1: {conflict['path1']['name']}")
            print(f"      Path 2: {conflict['path2']['name']}")
    else:
        print(f"\n[OK] No deadlock conflicts detected")
    
    # Display recommendations
    if report.get('recommendations'):
        print(f"\n[RECOMMENDATIONS]:")
        for i, rec in enumerate(report['recommendations'], 1):
            print(f"   {i}. {rec}")

def run_conflict_only_mode():
    """
    Run analysis in conflict-only mode for faster execution
    """
    print("\n" + "="*60)
    print("    CONFLICT-ONLY DETECTION MODE")
    print("="*60)
    
    # This function can be called separately for quick conflict detection
    # Implementation similar to main() but focused only on conflict detection
    pass

if __name__ == "__main__":
    print("Flexible Deadlock Detection System")
    print("===================================")
    
    success = main()
    
    if success:
        print("\nAnalysis completed successfully!")
    else:
        print("\nAnalysis failed. Check the logs for details.")
    
    sys.exit(0 if success else 1)