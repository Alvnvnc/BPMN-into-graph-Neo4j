
from neo4j import GraphDatabase
from typing import Dict, Any
import logging

from config import logger

class BPMNAnalyzer:
    """Analyze BPMN processes in Neo4j for insights and issues"""
    
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def run_analysis(self) -> Dict[str, Any]:
        """
        Run analysis queries on the imported graph to derive insights.
        
        Returns:
            Dictionary with analysis results
        """
        results = {}
        with self.driver.session() as session:
            results['process_count'] = session.run(
                "MATCH (p:Pool) RETURN count(p) AS count"
            ).single()['count']
            
            results['lane_count'] = session.run(
                "MATCH (l:Lane) RETURN count(l) AS count"
            ).single()['count']
            
            results['activity_count'] = session.run(
                "MATCH (a) WHERE a:Task OR a:Event_Start OR a:Event_End OR a:Event_Intermediate RETURN count(a) AS count"
            ).single()['count']
            
            # Detect paths
            results['paths'] = session.run(
                """
                MATCH path = (start:Event_Start)-[*]-(end:Event_End)
                RETURN count(path) AS pathCount
                """
            ).single()['pathCount']
            
            # Detect potential deadlocks (cycles)
            results['potential_deadlocks'] = session.run(
                """
                MATCH (a)-[r1]->(b)-[r2*]->(a)
                WHERE NOT a:Event_Start AND NOT a:Event_End
                RETURN count(DISTINCT a) AS cycleCount
                """
            ).single()['pathCount']
            
            # Detailed deadlock analysis
            if results['potential_deadlocks'] > 0:
                deadlock_paths = session.run(
                    """
                    MATCH path = (a)-[r1]->(b)-[r2*]->(a)
                    WHERE NOT a:Event_Start AND NOT a:Event_End
                    RETURN path, a.name as node_name LIMIT 5
                    """
                )
                results['deadlock_examples'] = [record['node_name'] for record in deadlock_paths]
        
        return results
    
    def close(self) -> None:
        """Close the Neo4j driver connection."""
        self.driver.close()