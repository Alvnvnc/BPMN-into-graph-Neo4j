import logging
import re
import json
from typing import List, Dict, Set
from neo4j import GraphDatabase
from config import load_config

logger = logging.getLogger(__name__)

class SQLDeadlockDetector:
    def __init__(self, config: Dict):
        self.driver = GraphDatabase.driver(
            config['neo4j_uri'], auth=(config['neo4j_user'], config['neo4j_password'])
        )
        self.resource_waits = {}
        self.resource_owners = {}
        self.deadlocks = []
        self.node_details = {}

    def fetch_sql_nodes(self) -> List[Dict]:
        with self.driver.session() as session:
            result = session.run("""
                MATCH (n)
                WHERE n.SQL IS NOT NULL
                RETURN n.id AS node_id, n.SQL AS sql, n.name AS name
            """)
            nodes = [record.data() for record in result]
            for node in nodes:
                self.node_details[node['node_id']] = {
                    'name': node.get('name', 'Unknown'),
                    'sql': node['sql']
                }
            return nodes

    def extract_resources(self, sql_script: str) -> Set[str]:
        patterns = [
            r"UPDATE\s+(\w+)",
            r"INSERT\s+INTO\s+(\w+)",
            r"DELETE\s+FROM\s+(\w+)",
            r"SELECT\s+.+?\s+FROM\s+(\w+)"
        ]
        tables = set()
        for pattern in patterns:
            tables.update(re.findall(pattern, sql_script, re.IGNORECASE))
        return tables

    def build_waits_and_ownerships(self, nodes: List[Dict]) -> None:
        for node in nodes:
            node_id = node['node_id']
            resources = self.extract_resources(node['sql'])
            for res in resources:
                owner = self.resource_owners.get(res)
                if owner is None:
                    self.resource_owners[res] = node_id
                else:
                    self.resource_waits.setdefault(node_id, set()).add(owner)

    def detect_deadlock(self) -> bool:
        visited = set()
        rec_stack = []
        found_deadlock = False

        def dfs(node):
            nonlocal found_deadlock
            if found_deadlock:
                return
            visited.add(node)
            rec_stack.append(node)
            for neighbor in self.resource_waits.get(node, []):
                if neighbor not in visited:
                    dfs(neighbor)
                elif neighbor in rec_stack:
                    cycle_start_index = rec_stack.index(neighbor)
                    self.deadlocks.append(rec_stack[cycle_start_index:] + [neighbor])
                    found_deadlock = True
                    return
            rec_stack.pop()

        for node in self.resource_waits:
            if node not in visited:
                dfs(node)
            if found_deadlock:
                break
        return found_deadlock

    def generate_report(self, output_path: str = "deadlock_report.json") -> None:
        if not self.deadlocks:
            logger.info("No deadlocks to report.")
            return

        detailed_deadlocks = []
        for cycle in self.deadlocks:
            detailed_cycle = [{
                "node_id": node,
                "name": self.node_details.get(node, {}).get('name', 'Unknown')
            } for node in cycle]
            detailed_deadlocks.append(detailed_cycle)

        with open(output_path, "w") as f:
            json.dump({"deadlocks": detailed_deadlocks}, f, indent=4)
        logger.info(f"Deadlock report generated: {output_path}")

    def run_analysis(self, output_path: str = "deadlock_report.json") -> None:
        logger.info("Starting SQL Deadlock Analysis...")
        nodes = self.fetch_sql_nodes()
        if not nodes:
            logger.info("No SQL nodes found in the database.")
            return

        self.build_waits_and_ownerships(nodes)
        if self.detect_deadlock():
            logger.warning("Potential deadlock detected!")
        else:
            logger.info("No deadlocks detected.")
        self.generate_report(output_path)

    def close(self) -> None:
        if self.driver:
            self.driver.close()
            logger.info("Closed Neo4j driver connection.")
