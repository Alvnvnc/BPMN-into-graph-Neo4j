import os
import argparse
import logging
from typing import Dict, List, Tuple

# Fix imports to use absolute imports
from converter import XPDLToNeo4jConverter
from config import load_config
from utils import generate_cypher_query_examples, save_query_examples, ensure_directory_exists
from deadlock_analyzer import DeadlockAnalyzer
from sql_deadlock_analyzer import SQLDeadlockAnalyzer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Convert XPDL to Neo4j Graph and Analyze Deadlocks')
    parser.add_argument('--config', help='Path to config file')
    parser.add_argument('--xpdl', help='Path to XPDL file')
    parser.add_argument('--uri', help='Neo4j URI')
    parser.add_argument('--user', help='Neo4j username')
    parser.add_argument('--password', help='Neo4j password')
    parser.add_argument('--output', help='Output directory for query examples', default='examples')
    parser.add_argument('--report', help='Output directory for deadlock reports', default='reports')
    return parser.parse_args()

def main():
    """Main function to process XPDL file, import to Neo4j and analyze deadlocks."""
    # Parse arguments
    args = parse_arguments()
    
    # Load configuration
    config = load_config(args.config)
    
    # Override config with command-line arguments if provided
    if args.xpdl:
        config['xpdl_file'] = args.xpdl
    if args.uri:
        config['neo4j_uri'] = args.uri
    if args.user:
        config['neo4j_user'] = args.user
    if args.password:
        config['neo4j_password'] = args.password
    
    # Ensure output directories exist
    ensure_directory_exists(args.output)
    ensure_directory_exists(args.report)
    
    # Process the XPDL file
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
        logger.info(f"Detected {results['analysis']['paths']} paths through the process")
        
        # Generate example queries
        example_queries = generate_cypher_query_examples(results)
        
        # Save queries to file
        query_file = os.path.join(args.output, 'example_queries.cypher')
        save_query_examples(example_queries, query_file)
        
        # Run comprehensive deadlock analysis
        logger.info("Starting comprehensive deadlock analysis...")
        
        # Initialize default values in case analysis fails
        structural_deadlocks = []
        sql_deadlocks = []
        timing_deadlocks = []
        
        # Initialize the deadlock analyzer
        analyzer = DeadlockAnalyzer(
            config['neo4j_uri'],
            config['neo4j_user'],
            config['neo4j_password']
        )
        
        # Run analysis for different types of deadlocks
        try:
            # Analyze structural deadlocks (Type 1)
            structural_report_file = os.path.join(args.report, 'structural_deadlock_report.txt')
            structural_deadlocks = analyzer.analyze_structural_deadlocks(structural_report_file)
            logger.info(f"Found {len(structural_deadlocks)} structural deadlocks.")
            
            # Analyze SQL deadlocks (Type 2)
            sql_report_file = os.path.join(args.report, 'sql_deadlock_report.txt')
            sql_analyzer = SQLDeadlockAnalyzer(
                config['neo4j_uri'],
                config['neo4j_user'],
                config['neo4j_password']
            )
            sql_deadlocks = sql_analyzer.analyze_from_gateways(sql_report_file)
            logger.info(f"Found {len(sql_deadlocks)} potential SQL deadlocks between tasks.")
            
            # Analyze timing deadlocks (Type 3)
            timing_report_file = os.path.join(args.report, 'timing_deadlock_report.txt')
            timing_deadlocks = analyzer.analyze_timing_deadlocks(timing_report_file)
            logger.info(f"Found {len(timing_deadlocks)} timing-related deadlocks.")
            
            # Generate comprehensive report
            comprehensive_report_file = os.path.join(args.report, 'comprehensive_deadlock_report.txt')
            analyzer.generate_comprehensive_report(
                comprehensive_report_file,
                structural_deadlocks,
                sql_deadlocks,
                timing_deadlocks
            )
            
            logger.info(f"Comprehensive deadlock analysis complete! Report saved to {comprehensive_report_file}")
            
        except Exception as e:
            logger.error(f"Error during deadlock analysis: {e}")
        finally:
            analyzer.close()
            if 'sql_analyzer' in locals():
                sql_analyzer.close()
        
        return {
            'status': 'success',
            'deadlock_analysis': {
                'structural': len(structural_deadlocks),
                'sql': len(sql_deadlocks),
                'timing': len(timing_deadlocks)
            },
            **results
        }
    else:
        logger.error(f"Conversion failed: {results['message']}")
        return results

if __name__ == "__main__":
    main()