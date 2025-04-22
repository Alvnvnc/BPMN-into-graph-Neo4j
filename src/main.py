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
        
if __name__ == "__main__":
    main()