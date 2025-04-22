import logging
import os
from typing import Dict

logger = logging.getLogger(__name__)

def generate_cypher_query_examples(process_results) -> Dict:
    """
    Generate example Cypher queries that can be used to explore the imported BPMN model.
    
    Args:
        process_results: Results from the processing step
        
    Returns:
        Dictionary containing example queries
    """
    queries = {
        'get_all_tasks': """
            MATCH (t:Task)
            RETURN t.id, t.name, t.type, t.subtype
        """,
        
        'get_process_flow': """
            MATCH path = (start:Event_Start)-[*]->(end:Event_End)
            RETURN path LIMIT 10
        """,
        
        'count_activities_by_lane': """
            MATCH (a)-[:IN_LANE]->(l:Lane)
            RETURN l.name AS lane, count(a) AS activityCount
            ORDER BY activityCount DESC
        """,
        
        'find_parallel_paths': """
            MATCH (a)-[r:PARALLEL_SPLIT]->(b)
            MATCH path = (a)-[*]->(end:Event_End)
            RETURN path LIMIT 10
        """,
        
        'find_exclusive_decisions': """
            MATCH (a)-[r:EXCLUSIVE_SPLIT]->(b)
            RETURN a.name AS sourceActivity, 
                   collect(b.name) AS targetActivities,
                   collect(r.condition) AS conditions
        """,
        
        'find_potential_bottlenecks': """
            MATCH (a)-[*]->(b)
            WITH b, count(a) AS incomingCount
            WHERE incomingCount > 2
            RETURN b.name AS activity, incomingCount
            ORDER BY incomingCount DESC
        """,
        
        'detect_deadlocks': """
            MATCH (a)-[r1]->(b)-[r2*]->(a)
            WHERE NOT a:Event_Start AND NOT a:Event_End
            RETURN a.name AS deadlockStart, 
                   [node in nodes(path) | node.name] AS deadlockCycle
        """,
        
        'detect_structural_deadlocks': """
            // Find missing gateway convergence - structural deadlock
            MATCH (g:Gateway)-[:GATEWAY_SPLIT|INCLUSIVE_SPLIT|PARALLEL_SPLIT]->()
            WITH g, g.subtype AS type
            MATCH path = (g)-[*..20]->()
            WHERE NOT EXISTS {
                MATCH path2 = (g)-[*..20]->(converge:Gateway)
                WHERE converge.subtype = type AND converge.direction = 'Converging'
            }
            RETURN DISTINCT g.id, g.name, g.subtype, g.direction
            LIMIT 5
        """,
        
        'detect_sql_deadlocks': """
            // Find potential SQL deadlocks with conflicting tables
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            RETURN d.type, d.subtype, d.description, 
                   collect(a.name) AS affected_activities,
                   d.tables AS tables
            ORDER BY d.severity DESC
        """,
        
        'detect_task_pairs_with_deadlocks': """
            // Find task pairs that have conflicting SQL access patterns
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            MATCH (d)-[:AFFECTS]->(b:Task)
            WHERE a.id <> b.id 
              AND d.subtype = 'Update Ordering Deadlock'
            RETURN a.name AS task1, b.name AS task2,
                   d.tables AS tables,
                   d.description
        """,
        
        'find_transactions_with_delays': """
            // Find transactions that have WAITFOR delays that can cause deadlocks
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            WHERE d.subtype = 'Transaction With Delay'
            RETURN a.name AS task_name,
                   a.SQL AS sql_code,
                   d.description,
                   d.tables
        """,
        
        'detect_time_deadlocks': """
            // Find activities with excessive processing time
            MATCH (a:Task)
            WHERE exists(a.Time) AND toFloat(a.Time) > 120
            RETURN a.id, a.name, a.Time
            ORDER BY toFloat(a.Time) DESC
        """,
        
        'get_deadlocks': """
            // Get all detected deadlocks
            MATCH (d:Deadlock)-[:AFFECTS]->(a)
            RETURN d.type, d.subtype, d.description, a.name AS affected_activity
            ORDER BY d.severity
        """,
        
        'detect_deadlocks_by_type': """
            // Find all deadlocks grouped by type and subtype
            MATCH (d:Deadlock)
            RETURN d.type AS deadlock_type, d.subtype AS subtype, count(*) AS count
            ORDER BY count DESC
        """,
        
        'sql_deadlock_details': """
            // Examine SQL deadlocks in detail
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            RETURN d.id, d.description, a.name AS affected_task, a.SQL AS sql
        """,
        
        'detect_sql_update_conflicts': """
            // Detect SQL update conflicts between tasks
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            MATCH (d)-[:AFFECTS]->(b:Task)
            WHERE a.id <> b.id AND a.SQL CONTAINS 'UPDATE' AND b.SQL CONTAINS 'UPDATE'
            RETURN d.description, a.name AS task1, b.name AS task2,
                   a.SQL AS sql1, b.SQL AS sql2
        """,
        
        'find_parallel_activities_with_long_time': """
            // Find activities in parallel paths with long processing times
            MATCH (g)-[:PARALLEL_SPLIT]->()-[*]->(a:Task)
            WHERE toFloat(a.Time) > 120
            RETURN g.name AS gateway_name, a.name AS task_name, 
                   a.Time AS processing_time
            ORDER BY toFloat(a.Time) DESC
        """,
        
        'find_structural_gateway_issues': """
            // Find structural issues with gateways (missing convergence)
            MATCH (g:Gateway)
            WHERE g.subtype IN ['Inclusive', 'Parallel'] 
                  AND g.direction = 'Diverging'
            WITH g
            MATCH path = (g)-[*..15]->()
            WHERE NOT EXISTS {
                MATCH (g)-[*..15]->(converge:Gateway)
                WHERE converge.subtype = g.subtype 
                      AND converge.direction = 'Converging'
            }
            RETURN DISTINCT g.name AS gateway_name, g.subtype AS type,
                   [(n) IN nodes(path) WHERE n:Task | n.name] AS path_activities
            LIMIT 10
        """,
        
        'deadlocks_with_affected_nodes': """
            // Find all deadlocks with their affected nodes
            MATCH (d:Deadlock)-[r:AFFECTS]->(n)
            RETURN d.type AS deadlock_type, d.subtype AS subtype, 
                   d.description AS description, 
                   collect(distinct n.name) AS affected_nodes
        """
    }
    
    return queries

def save_query_examples(queries: Dict, output_path: str) -> None:
    """
    Save example queries to a file.
    
    Args:
        queries: Dictionary of queries
        output_path: Path to save the queries
    """
    try:
        with open(output_path, 'w') as f:
            for name, query in queries.items():
                f.write(f"// {name}\n")
                f.write(f"{query}\n\n")
        logger.info(f"Example queries saved to {output_path}")
    except Exception as e:
        logger.error(f"Error saving queries: {str(e)}")

def ensure_directory_exists(directory_path: str) -> None:
    """
    Ensure that a directory exists, create it if it doesn't.
    
    Args:
        directory_path: Path to the directory
    """
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        logger.info(f"Created directory: {directory_path}")

def analyze_sql_deadlocks(session) -> Dict:
    """
    Run analysis queries on the Neo4j database to identify potential SQL deadlocks.
    
    Args:
        session: Active Neo4j session
        
    Returns:
        Dictionary with analysis results
    """
    results = {}
    
    # Find activities with SQL statements
    sql_activities = session.run(
        """
        MATCH (a:Task)
        WHERE a.SQL IS NOT NULL
        RETURN count(a) AS count
        """
    ).single()['count']
    results['sql_activities'] = sql_activities
    
    # Find activities with transactions
    transaction_activities = session.run(
        """
        MATCH (a:Task)
        WHERE a.SQL IS NOT NULL AND a.SQL CONTAINS 'BEGIN TRANSACTION'
        RETURN count(a) AS count
        """
    ).single()['count']
    results['transaction_activities'] = transaction_activities
    
    # Find activities with WAITFOR DELAY
    waitfor_activities = session.run(
        """
        MATCH (a:Task)
        WHERE a.SQL IS NOT NULL AND a.SQL CONTAINS 'WAITFOR DELAY'
        RETURN count(a) AS count
        """
    ).single()['count']
    results['waitfor_activities'] = waitfor_activities
    
    # Find potentially competing transactions
    if transaction_activities > 1:
        # Find activities in the same lane that have transactions
        same_lane_transactions = session.run(
            """
            MATCH (a1:Task)-[:IN_LANE]->(l:Lane)<-[:IN_LANE]-(a2:Task)
            WHERE a1.SQL CONTAINS 'BEGIN TRANSACTION' AND a2.SQL CONTAINS 'BEGIN TRANSACTION'
            AND a1.id <> a2.id
            RETURN count(DISTINCT a1) AS count
            """
        ).single()['count']
        results['same_lane_transactions'] = same_lane_transactions
        
        # Find activities in parallel paths that have transactions
        parallel_transactions = session.run(
            """
            MATCH (g:Gateway)-[r:PARALLEL_SPLIT]->(a)
            MATCH (g)-[s:PARALLEL_SPLIT]->(b)
            WHERE a <> b
            MATCH (a)-[*]->(a1:Task)
            MATCH (b)-[*]->(a2:Task)
            WHERE a1.SQL CONTAINS 'BEGIN TRANSACTION' AND a2.SQL CONTAINS 'BEGIN TRANSACTION'
            RETURN count(DISTINCT a1) AS count
            """
        ).single()['count']
        results['parallel_transactions'] = parallel_transactions
    
    return results

def generate_sql_deadlock_report(analysis_results: Dict) -> str:
    """
    Generate a text report about SQL deadlock analysis.
    
    Args:
        analysis_results: Results from analyze_sql_deadlocks
        
    Returns:
        Formatted report text
    """
    report = []
    report.append("SQL DEADLOCK ANALYSIS SUMMARY")
    report.append("=" * 50)
    report.append(f"Activities with SQL statements: {analysis_results.get('sql_activities', 0)}")
    report.append(f"Activities with transactions: {analysis_results.get('transaction_activities', 0)}")
    report.append(f"Activities with WAITFOR DELAY: {analysis_results.get('waitfor_activities', 0)}")
    
    if 'same_lane_transactions' in analysis_results:
        report.append(f"Activities in same lane with transactions: {analysis_results['same_lane_transactions']}")
    if 'parallel_transactions' in analysis_results:
        report.append(f"Activities in parallel paths with transactions: {analysis_results['parallel_transactions']}")
    
    # Risk assessment
    report.append("\nRISK ASSESSMENT:")
    risk_level = "Low"
    if analysis_results.get('waitfor_activities', 0) > 0:
        risk_level = "High"
    elif analysis_results.get('parallel_transactions', 0) > 0:
        risk_level = "Medium-High"
    elif analysis_results.get('same_lane_transactions', 0) > 0:
        risk_level = "Medium"
    
    report.append(f"Deadlock Risk Level: {risk_level}")
    
    return "\n".join(report)