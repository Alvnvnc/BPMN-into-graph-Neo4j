#!/usr/bin/env python3

import os
import sys
import logging
import argparse
from datetime import datetime
from typing import List, Dict

from src.sql_deadlock_analyzer import SQLDeadlockAnalyzer
from src.config import load_config

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def format_sql_deadlock_report(deadlocks: List[Dict], transactions_count: int, paths_count: int) -> str:
    """
    Format a detailed report about SQL deadlocks.
    
    Args:
        deadlocks: List of detected deadlocks
        transactions_count: Number of transactions analyzed
        paths_count: Number of execution paths analyzed
        
    Returns:
        Formatted text report
    """
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report = []
    report.append("=" * 80)
    report.append("                       SQL DEADLOCK ANALYSIS REPORT                      ")
    report.append("=" * 80)
    report.append("")
    
    # Summary information
    report.append(f"Report Date: {now}")
    report.append(f"Transactions Analyzed: {transactions_count}")
    report.append(f"Execution Paths Analyzed: {paths_count}")
    report.append(f"Deadlocks Detected: {len(deadlocks)}")
    report.append("")
    
    # Statistics by deadlock type
    deadlock_types = {}
    for d in deadlocks:
        d_type = d['type']
        if d_type not in deadlock_types:
            deadlock_types[d_type] = 0
        deadlock_types[d_type] += 1
    
    report.append("DEADLOCK TYPE SUMMARY:")
    report.append("-" * 40)
    for d_type, count in deadlock_types.items():
        report.append(f"{d_type}: {count}")
    report.append("")
    
    # Critical issues first
    critical_deadlocks = [d for d in deadlocks if d.get('severity') == 'Critical']
    if critical_deadlocks:
        report.append("!" * 80)
        report.append("                         CRITICAL DEADLOCKS                          ")
        report.append("!" * 80)
        report.append(f"Found {len(critical_deadlocks)} critical deadlocks that require immediate attention!")
        report.append("")
    
    # Detailed deadlock information
    report.append("=" * 80)
    report.append("                       DETAILED DEADLOCK ANALYSIS                      ")
    report.append("=" * 80)
    
    for i, deadlock in enumerate(deadlocks, 1):
        report.append(f"\nDEADLOCK #{i}: {deadlock['type']}")
        report.append("-" * 70)
        report.append(f"Severity: {deadlock.get('severity', 'Unknown')}")
        report.append("")
        
        report.append(f"Description:")
        report.append(f"{deadlock['description']}")
        report.append("")
        
        # Transaction information
        if 'transaction1' in deadlock and 'transaction2' in deadlock:
            report.append("Transaction Details:")
            report.append(f"  - Transaction 1: {deadlock['transaction1'].get('name', 'Unknown')}")
            report.append(f"  - Transaction 2: {deadlock['transaction2'].get('name', 'Unknown')}")
            
            if 'tx1_order' in deadlock and 'tx2_order' in deadlock:
                report.append(f"  - Lock Order 1: {deadlock['tx1_order']}")
                report.append(f"  - Lock Order 2: {deadlock['tx2_order']}")
            
        # Tables involved
        if 'tables' in deadlock:
            report.append("Tables Involved:")
            for table in deadlock['tables']:
                report.append(f"  - {table}")
        
        # Solution recommendation
        if 'solution' in deadlock:
            report.append("\nRECOMMENDED SOLUTION:")
            report.append(f"{deadlock['solution']}")
        
        # SQL code blocks
        if 'sql1' in deadlock:
            report.append("\nTransaction 1 SQL Code:")
            report.append("-" * 40)
            report.append(deadlock['sql1'])
            
        if 'sql2' in deadlock:
            report.append("\nTransaction 2 SQL Code:")
            report.append("-" * 40)
            report.append(deadlock['sql2'])
        
        report.append("\n" + "=" * 70)
    
    # Recommendations section
    report.append("\n" + "=" * 80)
    report.append("                   GENERAL RECOMMENDATIONS                   ")
    report.append("=" * 80)
    report.append("\n1. Access tables in a consistent order to avoid circular wait conditions")
    report.append("2. Minimize transaction duration and scope to reduce contention")
    report.append("3. Avoid using WAITFOR DELAY inside transactions")
    report.append("4. Consider using optimistic concurrency instead of pessimistic locking")
    report.append("5. Break complex transactions into smaller units of work")
    report.append("6. Monitor lock escalation thresholds in the database server")
    
    return "\n".join(report)

def analyze_and_generate_report(config_path: str, output_file: str) -> None:
    """
    Analyze SQL deadlocks and generate a comprehensive report.
    
    Args:
        config_path: Path to configuration file
        output_file: Path to output report file
    """
    # Load configuration
    config = load_config(config_path)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Run analysis
    analyzer = SQLDeadlockAnalyzer(
        config['neo4j_uri'],
        config['neo4j_user'],
        config['neo4j_password']
    )
    
    try:
        logger.info("Starting SQL deadlock analysis...")
        
        # Run analysis, getting back the deadlocks
        deadlocks = analyzer.analyze()
        
        # Create a more detailed and formatted report
        report_text = format_sql_deadlock_report(
            deadlocks,
            len(analyzer.transactions),
            len(analyzer.concurrent_paths)
        )
        
        # Write to file
        with open(output_file, 'w') as f:
            f.write(report_text)
        
        logger.info(f"Analysis complete! Detected {len(deadlocks)} potential deadlocks.")
        logger.info(f"Detailed report written to: {output_file}")
        
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        raise
    finally:
        analyzer.close()

def main():
    """Command-line interface for SQL deadlock analysis."""
    parser = argparse.ArgumentParser(description='Analyze SQL deadlocks in BPMN processes')
    parser.add_argument('--config', help='Path to configuration file', default='config.ini')
    parser.add_argument('--output', help='Path for output report file', default='reports/sql_deadlock_report.txt')
    parser.add_argument('--format', choices=['text', 'html', 'pdf'], default='text', 
                      help='Output format (only text is currently supported)')
    
    args = parser.parse_args()
    
    if args.format != 'text':
        logger.warning(f"{args.format} format is not currently supported. Using text format instead.")
    
    try:
        analyze_and_generate_report(args.config, args.output)
        return 0
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
