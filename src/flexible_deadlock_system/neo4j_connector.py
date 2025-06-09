#!/usr/bin/env python3
"""
Neo4j Connector Module
Handles all Neo4j database connections and data fetching operations.
Refactored from backup_sql.py for modular architecture.
"""

import logging
from typing import Dict, List, Optional
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

class Neo4jConnector:
    """
    Handles Neo4j database connections and basic operations
    """
    
    def __init__(self, config: Dict):
        """
        Initialize Neo4j connection
        
        Args:
            config: Dictionary containing Neo4j configuration
                   Expected keys: uri, user, password, database (optional)
        """
        self.uri = config['uri']
        self.user = config['user']
        self.password = config['password']
        self.database = config.get('database', 'neo4j')
        self.driver = None
        
        logger.debug(f"Initializing Neo4jConnector with URI: {self.uri}")
        
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            logger.debug("Neo4j driver initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Neo4j driver: {e}")
            raise
    
    def test_connection(self) -> bool:
        """
        Test the Neo4j connection
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 as test")
                test_result = result.single()
                if test_result and test_result['test'] == 1:
                    logger.info("Neo4j connection test successful")
                    return True
                else:
                    logger.error("Neo4j connection test failed")
                    return False
        except Exception as e:
            logger.error(f"Neo4j connection test failed: {e}")
            return False
    
    def fetch_graph_data(self) -> Dict:
        """
        Fetch complete graph data from Neo4j
        
        Returns:
            Dict: Graph data containing nodes and relationships
        """
        try:
            with self.driver.session(database=self.database) as session:
                # Get all nodes with their properties
                nodes_query = """
                MATCH (n)
                RETURN elementId(n) as id, labels(n) as labels, properties(n) as props
                """
                
                # Get all relationships
                rels_query = """
                MATCH (a)-[r]->(b)
                RETURN elementId(a) as source_id, elementId(b) as target_id, 
                       type(r) as rel_type, properties(r) as props
                """
                
                logger.debug("Fetching nodes from Neo4j...")
                nodes_result = session.run(nodes_query)
                nodes = {record['id']: {
                    'labels': record['labels'],
                    'properties': record['props']
                } for record in nodes_result}
                
                logger.debug("Fetching relationships from Neo4j...")
                rels_result = session.run(rels_query)
                relationships = [{
                    'source_id': record['source_id'],
                    'target_id': record['target_id'],
                    'rel_type': record['rel_type'],
                    'properties': record['props']
                } for record in rels_result]
                
                graph_data = {
                    'nodes': nodes,
                    'relationships': relationships
                }
                
                logger.info(f"Fetched {len(nodes)} nodes and {len(relationships)} relationships")
                return graph_data
                
        except Exception as e:
            logger.error(f"Error fetching graph data: {e}")
            raise
    
    def get_database_info(self) -> Dict:
        """
        Get basic database information
        
        Returns:
            Dict: Database information including node count, relationship count, etc.
        """
        try:
            with self.driver.session(database=self.database) as session:
                # Get node count
                node_count_result = session.run("MATCH (n) RETURN count(n) as node_count")
                node_count = node_count_result.single()["node_count"]
                
                # Get relationship count
                rel_count_result = session.run("MATCH ()-[r]->() RETURN count(r) as rel_count")
                rel_count = rel_count_result.single()["rel_count"]
                
                # Get node labels
                labels_result = session.run("CALL db.labels()")
                labels = [record["label"] for record in labels_result]
                
                # Get relationship types
                rel_types_result = session.run("CALL db.relationshipTypes()")
                rel_types = [record["relationshipType"] for record in rel_types_result]
                
                return {
                    'node_count': node_count,
                    'relationship_count': rel_count,
                    'node_labels': labels,
                    'relationship_types': rel_types
                }
                
        except Exception as e:
            logger.error(f"Error getting database info: {e}")
            raise
    
    def execute_query(self, query: str, parameters: Dict = None) -> List[Dict]:
        """
        Execute a custom Cypher query
        
        Args:
            query: Cypher query string
            parameters: Query parameters (optional)
            
        Returns:
            List[Dict]: Query results
        """
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run(query, parameters or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"Error executing query: {e}")
            raise

    def update_node_deadlock_message(self, node_id, message):
        """
        Update the deadlock message property for a node in Neo4j.
        Args:
            node_id (str): The node id in Neo4j (assume it's unique)
            message (str): The deadlock message
        """
        query = """
        MATCH (n) WHERE n.id = $node_id
        SET n.deadlock_message = $message
        """
        with self.driver.session() as session:
            session.run(query, node_id=node_id, message=message)
    
    def close(self):
        """
        Close the Neo4j connection
        """
        if self.driver:
            self.driver.close()
            logger.debug("Neo4j connection closed")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()