#!/usr/bin/env python3
import os
import argparse
import logging

from converter import XPDLToNeo4jConverter
from config import load_config
from flexible_deadlock_system.deadlock_detector import DeadlockDetector
from flexible_deadlock_system.parallel_path_analyzer import ParallelPathAnalyzer
from flexible_deadlock_system.sql_resource_extractor import SQLResourceExtractor
from flexible_deadlock_system.neo4j_connector import Neo4jConnector
from flexible_deadlock_system.report_generator import ReportGenerator
from deadlock_saver import DeadlockSaver

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_arguments():
    parser = argparse.ArgumentParser(description='Convert XPDL to Neo4j Graph and Analyze Deadlocks')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--xpdl', help='Path to XPDL file')
    parser.add_argument('--uri', help='Neo4j URI')
    parser.add_argument('--user', help='Neo4j username')
    parser.add_argument('--password', help='Neo4j password')
    parser.add_argument('--report', help='Directory to save deadlock reports', default='reports')
    return parser.parse_args()

def ensure_directory_exists(directory_path: str):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        logger.info(f"Created directory: {directory_path}")

def main():
    args = parse_arguments()
    config = load_config(args.config)

    # Override config if provided from arguments
    if args.xpdl:
        config['xpdl_file'] = args.xpdl
    if args.uri:
        config['neo4j_uri'] = args.uri
    if args.user:
        config['neo4j_user'] = args.user
    if args.password:
        config['neo4j_password'] = args.password

    ensure_directory_exists(args.report)

    try:
        logger.info(f"Processing XPDL file: {config['xpdl_file']}")
        converter = XPDLToNeo4jConverter(
            config['xpdl_file'],
            config['neo4j_uri'],
            config['neo4j_user'],
            config['neo4j_password']
        )

        results = converter.process()

        if results['status'] == 'success':
            logger.info("Conversion completed successfully!")
            logger.info(f"Imported {results['statistics']['activities']} activities, "
                        f"{results['statistics']['gateways']} gateways")

            # Enhanced Deadlock Detection using flexible_deadlock_system
            logger.info("Starting enhanced deadlock detection...")
            
            # Initialize components
            neo4j_config = {
                'uri': config['neo4j_uri'],
                'user': config['neo4j_user'],
                'password': config['neo4j_password']
            }
            
            connector = Neo4jConnector(neo4j_config)
            graph_data = connector.fetch_graph_data()
            
            if not graph_data or not graph_data.get('nodes'):
                logger.error("❌ No graph data found!")
                return
                
            extractor = SQLResourceExtractor()
            sql_resources = extractor.extract_from_graph_data(graph_data)
            
            analyzer = ParallelPathAnalyzer()
            scenarios = analyzer.identify_parallel_scenarios(graph_data)
            
            # Run enhanced deadlock detection
            detector = DeadlockDetector(graph_data, sql_resources)
            deadlock_results = detector.analyze_deadlocks(scenarios)
            
            logger.info(f"Enhanced deadlock analysis completed!")
            logger.info(f"Found {len(deadlock_results['deadlock_cycles'])} potential deadlock cycles")
            logger.info(f"Detected {len(deadlock_results['detected_conflicts'])} resource conflicts")
            
            # Generate comprehensive report
            report_generator = ReportGenerator()
            report_path = report_generator.generate_comprehensive_report(
                deadlock_results, graph_data, sql_resources, scenarios
            )
            
            logger.info(f"Comprehensive report saved to: {report_path}")
            
            # Legacy deadlock saving (if needed)
            if deadlock_results['detected_conflicts']:
                logger.info("Saving detected conflicts to Neo4j...")
                saver = DeadlockSaver(
                    config['neo4j_uri'],
                    config['neo4j_user'],
                    config['neo4j_password']
                )
                # Convert new format to legacy format for saving
                legacy_deadlocks = [
                    {
                        'type': conflict['conflict_type'],
                        'nodes': [conflict['node1_id'], conflict['node2_id']],
                        'severity': conflict['severity']
                    }
                    for conflict in deadlock_results['detected_conflicts']
                ]
                saver.save_deadlocks(legacy_deadlocks)
                saver.close()
                logger.info("Conflicts successfully saved to Neo4j.")
            
            connector.close()
            logger.info("Enhanced deadlock analysis completed successfully.")

    except Exception as e:
        logger.error(f"Error processing XPDL or analyzing deadlocks: {str(e)}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")

if __name__ == "__main__":
    main()
