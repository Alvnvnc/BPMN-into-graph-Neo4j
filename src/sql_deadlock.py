import logging
import re
import json
from typing import List, Dict, Set, Optional
from neo4j import GraphDatabase
from config import load_config

logger = logging.getLogger(__name__)

class SQLDeadlockDetector:
    def __init__(self, config: Dict):
        self.driver = GraphDatabase.driver(
            config['neo4j_uri'], 
            auth=(config['neo4j_user'], config['neo4j_password'])
        )
        self.resource_waits: Dict[str, Set[str]] = {}
        self.resource_owners: Dict[str, str] = {}
        self.deadlock_cycles: List[List[str]] = []
        self.node_details: Dict[str, Dict] = {}

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
            r"(?:UPDATE|INSERT\s+INTO|DELETE\s+FROM|FROM|JOIN)\s+([\w\.]+)",
            r"INTO\s+([\w\.]+)"
        ]
        tables = set()
        for pattern in patterns:
            tables.update(re.findall(pattern, sql_script, re.IGNORECASE))
        return tables

    def build_waits_graph(self, nodes: List[Dict]) -> None:
        for node in nodes:
            node_id = node['node_id']
            resources = self.extract_resources(node['sql'])
            for res in resources:
                owner = self.resource_owners.get(res)
                if owner is None:
                    self.resource_owners[res] = node_id
                else:
                    self.resource_waits.setdefault(node_id, set()).add(owner)

    def _tarjans_algorithm(self) -> List[List[str]]:
        index = 0
        indices: Dict[str, Optional[int]] = {}
        lowlink: Dict[str, int] = {}
        on_stack: Dict[str, bool] = {}
        stack: List[str] = []
        sccs: List[List[str]] = []

        def strongconnect(node: str):
            nonlocal index
            indices[node] = index
            lowlink[node] = index
            index += 1
            stack.append(node)
            on_stack[node] = True

            for neighbor in self.resource_waits.get(node, []):
                if indices.get(neighbor) is None:
                    strongconnect(neighbor)
                    lowlink[node] = min(lowlink[node], lowlink[neighbor])
                elif on_stack.get(neighbor, False):
                    lowlink[node] = min(lowlink[node], indices[neighbor])

            if lowlink[node] == indices[node]:
                scc: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    scc.append(w)
                    if w == node:
                        break
                if len(scc) > 1:  # Hanya siklus dengan minimal 2 node
                    sccs.append(scc)

        for node in self.resource_waits:
            if indices.get(node) is None:
                strongconnect(node)
                
        return sccs

    def detect_deadlocks(self) -> bool:
        sccs = self._tarjans_algorithm()
        self.deadlock_cycles = sccs
        return len(sccs) > 0

    def generate_report(self, output_path: str = "deadlock_report.json") -> None:
        if not self.deadlock_cycles:
            logger.info("No deadlocks detected.")
            return

        report = {"deadlocks": []}
        for cycle in self.deadlock_cycles:
            detailed_cycle = []
            for node_id in cycle:
                node_info = {
                    "node_id": node_id,
                    "name": self.node_details.get(node_id, {}).get('name', 'Unknown'),
                    "sql": self.node_details.get(node_id, {}).get('sql', '')
                }
                detailed_cycle.append(node_info)
            report["deadlocks"].append(detailed_cycle)

        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        logger.info(f"Report generated: {output_path}")

    def run_analysis(self, output_path: str = "deadlock_report.json") -> None:
        logger.info("Starting enhanced deadlock analysis...")
        nodes = self.fetch_sql_nodes()
        if not nodes:
            logger.info("No SQL nodes found.")
            return

        self.build_waits_graph(nodes)
        if self.detect_deadlocks():
            logger.warning(f"Found {len(self.deadlock_cycles)} potential deadlock cycles!")
        else:
            logger.info("No deadlocks detected.")
        self.generate_report(output_path)

    def close(self) -> None:
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed.")

if __name__ == "__main__":
    config = load_config()
    detector = SQLDeadlockDetector(config)
    detector.run_analysis()
    detector.close()