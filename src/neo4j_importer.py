from neo4j import GraphDatabase
import logging
from typing import Dict, Any, List, Set

from config import logger
from dump.models import Pool, Lane, Activity, Transition, Gateway, GatewayPattern

class Neo4jImporter:
    """Handle Neo4j database operations for BPMN model import"""
    
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
    
    def import_all(self, 
                  pools: Dict[str, Pool], 
                  lanes: Dict[str, Lane], 
                  activities: Dict[str, Activity],
                  gateways: Dict[str, Gateway],
                  transitions: Dict[str, Transition],
                  gateway_patterns: Dict[str, GatewayPattern]) -> None:
        """Import all extracted data to Neo4j."""
        with self.driver.session() as session:
            self._clear_database(session)
            self._import_pools_and_lanes(session, pools, lanes)
            self._import_activities(session, activities, gateways, lanes)
            self._import_semantic_relationships(session, gateway_patterns, transitions)
            self._import_direct_transitions(session, transitions, gateways)
        
        logger.info("Data successfully imported to Neo4j")
    
    def _clear_database(self, session) -> None:
        """Clear the Neo4j database before importing new data."""
        logger.info("Clearing Neo4j database")
        session.run("MATCH (n) DETACH DELETE n")
    
    def _import_pools_and_lanes(self, session, pools: Dict[str, Pool], lanes: Dict[str, Lane]) -> None:
        """Import pools and lanes (departments) to Neo4j."""
        # Create Pool nodes
        for pool_id, pool in pools.items():
            session.run(
                """
                CREATE (p:Pool {
                    id: $id,
                    name: $name,
                    process: $process
                })
                """,
                id=pool.id,
                name=pool.name,
                process=pool.process
            )
        
        # Create Lane nodes and connect to Pool
        for lane_id, lane in lanes.items():
            session.run(
                """
                MATCH (p:Pool {id: $pool_id})
                CREATE (l:Lane {
                    id: $id,
                    name: $name,
                    performer: $performer
                })
                CREATE (l)-[:BELONGS_TO]->(p)
                """,
                id=lane.id,
                name=lane.name,
                performer=lane.performer,
                pool_id=lane.pool_id
            )
        
        logger.info(f"Imported {len(pools)} pools and {len(lanes)} lanes to Neo4j")
    
    def _import_activities(self, session, activities: Dict[str, Activity], 
                          gateways: Dict[str, Gateway], lanes: Dict[str, Lane]) -> None:
        """Import activities to Neo4j."""
        # Create Activity nodes
        for activity_id, activity in activities.items():
            # Skip gateways as they'll be handled differently
            if activity.type == 'Gateway':
                continue
            
            # Base properties for all activities
            properties = {
                'id': activity.id,
                'name': activity.name,
                'type': activity.type,
                'subtype': activity.subtype,
                'process_id': activity.process_id
            }
            
            # Add extended attributes
            for key, value in activity.properties.items():
                properties[key] = value
            
            # Create node with the right label based on type
            if activity.type == 'Event':
                label = f"Event_{activity.subtype}"
                query = f"""
                CREATE (a:{label} {{
                    id: $id,
                    name: $name,
                    type: $type,
                    subtype: $subtype,
                    process_id: $process_id
                }})
                """
            else:  # Task type
                query = """
                CREATE (a:Task {
                    id: $id,
                    name: $name,
                    type: $type,
                    subtype: $subtype,
                    process_id: $process_id
                })
                """
            
            session.run(query, **properties)
            
            # Connect to Lane if lane_id is available
            if activity.lane_id:
                session.run(
                    """
                    MATCH (a) WHERE a.id = $activity_id
                    MATCH (l:Lane {id: $lane_id})
                    CREATE (a)-[:IN_LANE]->(l)
                    """,
                    activity_id=activity.id,
                    lane_id=activity.lane_id
                )
        
        logger.info(f"Imported {len(activities) - len(gateways)} activities to Neo4j")
    
    def _import_semantic_relationships(self, session, 
                                      gateway_patterns: Dict[str, GatewayPattern], 
                                      transitions: Dict[str, Transition]) -> None:
        """
        Import semantic relationships based on gateway patterns.
        This creates direct relationships between activities connected through gateways.
        """
        # Track splits that need convergence
        split_gateways = {}
        # Track all nodes that are part of gateway flows
        connected_nodes = set()
        # Track unmatched gateway patterns
        unmatched_gateways = []

        # First pass: identify splits and their sources/targets
        for gateway_id, pattern in gateway_patterns.items():
            relationship_type = pattern.relationship_type
            
            if pattern.pattern == 'Split':
                # Store information about the split gateway
                source = pattern.incoming[0]['from_id']
                targets = [outgoing['to_id'] for outgoing in pattern.outgoing]
                split_gateways[gateway_id] = {
                    'source': source,
                    'targets': targets,
                    'gateway_type': pattern.subtype,
                    'matched': False
                }
                connected_nodes.add(source)
                connected_nodes.update(targets)
                
                # Create regular split relationships
                for outgoing in pattern.outgoing:
                    target = outgoing['to_id']
                    properties = {
                        'gateway_id': gateway_id,
                        'gateway_type': pattern.subtype
                    }
                    
                    if outgoing['condition']:
                        properties['condition'] = outgoing['condition']
                    
                    session.run(
                        f"""
                        MATCH (source) WHERE source.id = $source_id
                        MATCH (target) WHERE target.id = $target_id
                        CREATE (source)-[r:{relationship_type} $properties]->(target)
                        """,
                        source_id=source,
                        target_id=target,
                        properties=properties
                    )
            
            elif pattern.pattern == 'Join':
                # Check if this join matches any split
                target = pattern.outgoing[0]['to_id']
                sources = [incoming['from_id'] for incoming in pattern.incoming]
                connected_nodes.add(target)
                connected_nodes.update(sources)
                
                # Try to find matching split gateway
                matched = False
                for split_id, split_data in split_gateways.items():
                    if set(sources).issubset(set(split_data['targets'])):
                        split_gateways[split_id]['matched'] = True
                        matched = True
                
                # Create regular join relationships
                for incoming in pattern.incoming:
                    source = incoming['from_id']
                    
                    session.run(
                        f"""
                        MATCH (source) WHERE source.id = $source_id
                        MATCH (target) WHERE target.id = $target_id
                        CREATE (source)-[r:{relationship_type} {{gateway_id: $gateway_id, gateway_type: $gateway_type}}]->(target)
                        """,
                        source_id=source,
                        target_id=target,
                        gateway_id=gateway_id,
                        gateway_type=pattern.subtype
                    )
                
                if not matched:
                    unmatched_gateways.append({
                        'id': gateway_id,
                        'type': 'Join',
                        'subtype': pattern.subtype,
                        'sources': sources,
                        'target': target
                    })
        
        # Second pass: Fix missing gateway convergence
        self._fix_missing_gateway_convergence(session, split_gateways, unmatched_gateways)
        
        # Third pass: Connect deadlock nodes
        self._connect_deadlock_nodes(session, connected_nodes)
        
        logger.info(f"Created semantic relationships based on {len(gateway_patterns)} gateway patterns")
    
    def _fix_missing_gateway_convergence(self, session, split_gateways, unmatched_gateways):
        """Fix missing gateway convergence by connecting appropriate nodes."""
        # Find split gateways without matching convergence
        for gateway_id, data in split_gateways.items():
            if not data['matched']:
                logger.info(f"Detected missing gateway convergence for gateway {gateway_id}")
                
                # Find potential convergence point
                target_nodes = data['targets']
                
                # Option 1: Connect to an existing unmatched join if available
                join_match = None
                for join in unmatched_gateways:
                    if join['type'] == 'Join' and set(join['sources']).intersection(set(target_nodes)):
                        join_match = join
                        break
                
                if join_match:
                    # Connect missing paths to complete the convergence
                    missing_sources = set(target_nodes) - set(join_match['sources'])
                    for source in missing_sources:
                        session.run(
                            """
                            MATCH (source) WHERE source.id = $source_id
                            MATCH (target) WHERE target.id = $target_id
                            CREATE (source)-[r:FIXED_FLOW {gateway_id: $gateway_id, fixed_type: 'Missing Convergence'}]->(target)
                            """,
                            source_id=source,
                            target_id=join_match['target'],
                            gateway_id=gateway_id
                        )
                    logger.info(f"Fixed missing convergence by connecting to existing join {join_match['id']}")
                else:
                    # Option 2: Connect all divergent paths to a common endpoint
                    # Find endpoint activities reachable from targets
                    endpoint_query = """
                    MATCH (start) WHERE start.id IN $target_ids
                    MATCH path = (start)-[*1..10]->(end)
                    WHERE NOT (end)-->() AND NOT end:Gateway
                    RETURN end.id as endpoint_id, count(*) as path_count
                    ORDER BY path_count DESC
                    LIMIT 1
                    """
                    
                    result = session.run(endpoint_query, target_ids=target_nodes)
                    record = result.single()
                    
                    if record and record.get('endpoint_id'):
                        endpoint_id = record.get('endpoint_id')
                        # Connect all targets to this endpoint
                        for source in target_nodes:
                            session.run(
                                """
                                MATCH (source) WHERE source.id = $source_id
                                MATCH (target) WHERE target.id = $target_id
                                MERGE (source)-[r:FIXED_FLOW {gateway_id: $gateway_id, fixed_type: 'Auto Convergence'}]->(target)
                                """,
                                source_id=source,
                                target_id=endpoint_id,
                                gateway_id=gateway_id
                            )
                        logger.info(f"Fixed missing convergence by connecting to common endpoint {endpoint_id}")
                    else:
                        logger.warning(f"Could not find suitable convergence point for gateway {gateway_id}")
    
    def _connect_deadlock_nodes(self, session, connected_nodes: Set[str]):
        """Connect disconnected nodes that could cause deadlocks."""
        # Find disconnected nodes (nodes not connected to any gateway)
        disconnected_query = """
        MATCH (n) 
        WHERE NOT n:Pool AND NOT n:Lane AND NOT n:Gateway
        AND NOT (n)-[:SEQUENCE_FLOW]->() 
        AND NOT ()-[:SEQUENCE_FLOW]->(n)
        RETURN n.id as node_id, n.type as node_type
        """
        
        result = session.run(disconnected_query)
        disconnected_nodes = [(record['node_id'], record['node_type']) for record in result]
        
        if disconnected_nodes:
            logger.info(f"Found {len(disconnected_nodes)} disconnected nodes that may cause deadlocks")
            
            # Find potential endpoints to connect these nodes to
            endpoint_query = """
            MATCH (n) 
            WHERE NOT (n)-->() AND n.type <> 'Gateway'
            RETURN n.id as endpoint_id
            LIMIT 1
            """
            
            endpoint_result = session.run(endpoint_query)
            endpoint_record = endpoint_result.single()
            
            if endpoint_record:
                endpoint_id = endpoint_record['endpoint_id']
                
                # Connect all disconnected nodes to the endpoint
                for node_id, node_type in disconnected_nodes:
                    if node_id not in connected_nodes:
                        session.run(
                            """
                            MATCH (source) WHERE source.id = $source_id
                            MATCH (target) WHERE target.id = $target_id
                            CREATE (source)-[r:DEADLOCK_RESOLUTION {reason: 'Disconnected Node'}]->(target)
                            """,
                            source_id=node_id,
                            target_id=endpoint_id
                        )
                logger.info(f"Connected {len(disconnected_nodes)} disconnected nodes to prevent deadlocks")
            else:
                logger.warning("No suitable endpoint found to connect disconnected nodes")
                
    def _import_direct_transitions(self, session, 
                                  transitions: Dict[str, Transition], 
                                  gateways: Dict[str, Gateway]) -> None:
        """
        Import direct transitions that don't involve gateways.
        """
        # Get all gateway IDs
        gateway_ids = set(gateways.keys())
        
        # Filter transitions that don't involve gateways or SQL deadlocks
        direct_transitions = [
            t for t_id, t in transitions.items() 
            if t.from_id not in gateway_ids and t.to_id not in gateway_ids
            and not (hasattr(t, 'is_sql_deadlock') and t.is_sql_deadlock)
        ]
        
        # Create direct transition relationships
        for transition in direct_transitions:
            session.run(
                """
                MATCH (source) WHERE source.id = $from_id
                MATCH (target) WHERE target.id = $to_id
                CREATE (source)-[r:SEQUENCE_FLOW {
                    id: $id,
                    name: $name,
                    condition: $condition
                }]->(target)
                """,
                id=transition.id,
                from_id=transition.from_id,
                to_id=transition.to_id,
                name=transition.name or "",
                condition=transition.condition or ""
            )
        
        logger.info(f"Imported {len(direct_transitions)} direct transitions")