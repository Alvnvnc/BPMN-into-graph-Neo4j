import logging
from typing import List, Dict
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

class DeadlockSaver:
    """
    DeadlockSaver:
    - Save detected deadlocks into Neo4j database.
    - Create :AFFECTS relationships from Deadlock nodes to affected nodes.
    - Uses elementId for Neo4j 5+ compatibility.
    """

    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))

    def save_deadlocks(self, deadlocks: List[Dict]) -> None:
        if not deadlocks:
            logger.info("No deadlocks to save.")
            return

        with self.driver.session() as session:
            for deadlock in deadlocks:
                # Create Deadlock node
                result = session.run(
                    """
                    CREATE (d:Deadlock {
                        type: $type,
                        subtype: $subtype,
                        description: $description,
                        severity: $severity
                    }) RETURN elementId(d) AS deadlock_element_id
                    """,
                    type=deadlock.get('type'),
                    subtype=deadlock.get('subtype'),
                    description=deadlock.get('description'),
                    severity=deadlock.get('severity')
                )
                record = result.single()
                deadlock_element_id = record['deadlock_element_id']

                # Connect Deadlock node to affected nodes
                for node_id in deadlock.get('affected_nodes', []):
                    session.run(
                        """
                        MATCH (d:Deadlock) WHERE elementId(d) = $deadlock_element_id
                        OPTIONAL MATCH (n {id: $node_id})
                        WITH d, n
                        WHERE n IS NOT NULL
                        CREATE (d)-[:AFFECTS]->(n)
                        """,
                        deadlock_element_id=deadlock_element_id,
                        node_id=node_id
                    )

        logger.info(f"Saved {len(deadlocks)} deadlocks into Neo4j.")

    def close(self) -> None:
        if self.driver:
            self.driver.close()
            logger.info("Closed Neo4j driver connection.")
