import os
import argparse
import logging

from converter import XPDLToNeo4jConverter
from config import load_config
from deadlock_detector import DeadlockDetector
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

            # Deadlock Detection
            logger.info("Starting deadlock detection...")
            detector = DeadlockDetector(
                converter.activities,
                converter.transitions,
                converter.gateways,
                converter.gateway_patterns
            )

            deadlocks = detector.detect_all_deadlocks()
            predictions = detector.predict_potential_time_deadlocks()

            logger.info(f"Detected {len(deadlocks)} confirmed deadlocks.")
            logger.info(f"Detected {len(predictions)} potential time deadlocks.")

            # Save Deadlocks using DeadlockSaver
            logger.info("Saving detected deadlocks to Neo4j...")
            saver = DeadlockSaver(
                config['neo4j_uri'],
                config['neo4j_user'],
                config['neo4j_password']
            )
            saver.save_deadlocks(deadlocks)
            saver.close()
            logger.info("Deadlocks successfully saved to Neo4j.")

    except Exception as e:
        logger.error(f"Error processing XPDL or importing deadlocks: {str(e)}")

if __name__ == "__main__":
    main()
