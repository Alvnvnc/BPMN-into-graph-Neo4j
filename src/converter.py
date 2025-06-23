import xml.etree.ElementTree as ET
from neo4j import GraphDatabase
import logging
import re
from typing import Dict, List, Optional, Tuple, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class XPDLToNeo4jConverter:
    """
    A comprehensive converter for XPDL files from Bizagi Modeler to Neo4j graphs,
    with special handling for gateways and parallel paths.
    """
    
    # XPDL Namespaces
    NAMESPACES = {
        'xpdl': 'http://www.wfmc.org/2009/XPDL2.2',
        'xsi': 'http://www.w3.org/2001/XMLSchema-instance'
    }
    
    # Gateway types mapping
    GATEWAY_TYPES = {
        'Exclusive': 'XOR',
        'Inclusive': 'OR',
        'Parallel': 'AND',
        'Complex': 'COMPLEX',
        'EventBased': 'EVENT'
    }
    
    def __init__(self, xpdl_file: str, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """
        Initialize the converter with XPDL file and Neo4j credentials.
        
        Args:
            xpdl_file: Path to the XPDL file
            neo4j_uri: URI for the Neo4j database
            neo4j_user: Neo4j username
            neo4j_password: Neo4j password
        """
        self.xpdl_file = xpdl_file
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.tree = None
        self.root = None
        self.pools = {}
        self.lanes = {}
        self.participants = {}
        self.activities = {}
        self.transitions = {}
        self.gateways = {}
        self.gateway_patterns = {}
        
    def load_and_parse(self) -> None:
        """Load and parse the XPDL file."""
        logger.info(f"Loading XPDL file: {self.xpdl_file}")
        try:
            self.tree = ET.parse(self.xpdl_file)
            self.root = self.tree.getroot()
            logger.info("XPDL file loaded successfully")
        except Exception as e:
            logger.error(f"Error loading XPDL file: {str(e)}")
            raise
    
    def extract_all_data(self) -> None:
        """Extract all relevant data from the XPDL file."""
        self.extract_participants()
        self.extract_pools_and_lanes()
        self.extract_all_processes()
    
    def extract_participants(self) -> None:
        """Extract participant information from the XPDL file."""
        participant_elems = self.root.findall(".//xpdl:Participant", self.NAMESPACES)
        for participant in participant_elems:
            participant_id = participant.get('Id')
            participant_name = participant.get('Name', f"Unnamed Participant {participant_id}")
            self.participants[participant_id] = {
                'id': participant_id,
                'name': participant_name
            }
        logger.info(f"Extracted {len(self.participants)} participants")
    
    def extract_pools_and_lanes(self) -> None:
        """Extract pools and lanes information from the XPDL file."""
        pools = self.root.findall(".//xpdl:Pool", self.NAMESPACES)
        for pool in pools:
            pool_id = pool.get('Id')
            pool_name = pool.get('Name', f"Unnamed Pool {pool_id}")
            process_ref = pool.get('Process')
            
            self.pools[pool_id] = {
                'id': pool_id,
                'name': pool_name,
                'process': process_ref,
                'lanes': []
            }
            
            # Extract lanes
            lanes = pool.findall("xpdl:Lanes/xpdl:Lane", self.NAMESPACES)
            for lane in lanes:
                lane_id = lane.get('Id')
                lane_name = lane.get('Name', f"Unnamed Lane {lane_id}")
                performer = lane.get('Performer', '')
                
                self.lanes[lane_id] = {
                    'id': lane_id,
                    'name': lane_name,
                    'performer': performer,
                    'pool_id': pool_id
                }
                self.pools[pool_id]['lanes'].append(lane_id)
        
        logger.info(f"Extracted {len(self.pools)} pools and {len(self.lanes)} lanes")
    
    def extract_all_processes(self) -> None:
        """Extract all processes from the XPDL file."""
        processes = self.root.findall(".//xpdl:WorkflowProcess", self.NAMESPACES)
        for process in processes:
            process_id = process.get('Id')
            logger.info(f"Extracting data for process: {process_id}")
            self.extract_activities(process)
            self.extract_transitions(process)
            self.analyze_gateway_patterns()
    
    def extract_activities(self, process_elem) -> None:
        """
        Extract all activities from a process.
        
        Args:
            process_elem: The process element containing activities
        """
        process_id = process_elem.get('Id')
        activities_elem = process_elem.find('xpdl:Activities', self.NAMESPACES)
        
        if activities_elem is None:
            logger.warning(f"No activities found in process {process_id}")
            return
        
        activities = activities_elem.findall('xpdl:Activity', self.NAMESPACES)
        for activity in activities:
            activity_id = activity.get('Id')
            activity_name = activity.get('Name', f"Unnamed Activity {activity_id}")
            
            # Determine the lane (department)
            lane_id = None
            node_graphics = activity.find(".//xpdl:NodeGraphicsInfo", self.NAMESPACES)
            if node_graphics is not None:
                lane_id = node_graphics.get('LaneId')
            
            # Determine activity type and subtype
            activity_type, activity_subtype = self._determine_activity_type(activity)
            
            # Extract properties
            properties = {
                'id': activity_id,
                'name': activity_name,
                'type': activity_type,
                'subtype': activity_subtype,
                'process_id': process_id,
                'lane_id': lane_id
            }
            
            # Extract extended attributes
            ext_attrs = activity.find('xpdl:ExtendedAttributes', self.NAMESPACES)
            if ext_attrs is not None:
                for attr in ext_attrs.findall('xpdl:ExtendedAttribute', self.NAMESPACES):
                    attr_name = attr.get('Name')
                    attr_value = attr.get('Value')
                    
                    # Special handling for SQL - extract clean SQL from HTML
                    if attr_name == 'SQL' and attr_value:
                        # Store original HTML in a separate property
                        properties['SQL_HTML'] = attr_value
                        
                        # Extract clean SQL from HTML
                        clean_sql = self._extract_sql_from_html(attr_value)
                        properties['SQL'] = clean_sql
                    else:
                        properties[attr_name] = attr_value  # Store directly with original name
            
            # Store activity in dictionary
            self.activities[activity_id] = properties
            
            # If this is a gateway, store additional information
            if activity_type == 'Gateway':
                gateway_info = self._extract_gateway_info(activity, activity_subtype)
                self.gateways[activity_id] = {**properties, **gateway_info}
        
        logger.info(f"Extracted {len(activities)} activities from process {process_id}")
    
    def _extract_sql_from_html(self, html_content: str) -> str:
        """
        Extract clean SQL syntax from HTML-formatted content.
        
        Args:
            html_content: HTML string containing SQL
            
        Returns:
            Clean SQL string without HTML tags
        """
        if not html_content:
            return ""
            
        # Remove HTML tags
        sql = re.sub(r'<[^>]+>', '', html_content)
        
        # Replace HTML entities
        sql = sql.replace('&amp;', '&')
        sql = sql.replace('&lt;', '<')
        sql = sql.replace('&gt;', '>')
        sql = sql.replace('&quot;', '"')
        sql = sql.replace('&#39;', "'")
        sql = sql.replace('&nbsp;', ' ')
        
        # Remove extra whitespace
        sql = re.sub(r'\s+', ' ', sql).strip()
        
        return sql
    
    def _determine_activity_type(self, activity_elem) -> Tuple[str, str]:
        """
        Determine the type and subtype of an activity.
        
        Args:
            activity_elem: The activity element
            
        Returns:
            Tuple containing activity type and subtype
        """
        # Check for events
        if activity_elem.find('xpdl:Event', self.NAMESPACES) is not None:
            event_elem = activity_elem.find('xpdl:Event', self.NAMESPACES)
            
            if event_elem.find('xpdl:StartEvent', self.NAMESPACES) is not None:
                return 'Event', 'Start'
            elif event_elem.find('xpdl:EndEvent', self.NAMESPACES) is not None:
                return 'Event', 'End'
            elif event_elem.find('xpdl:IntermediateEvent', self.NAMESPACES) is not None:
                return 'Event', 'Intermediate'
            else:
                return 'Event', 'Generic'
        
        # Check for gateways
        elif activity_elem.find('xpdl:Route', self.NAMESPACES) is not None:
            route_elem = activity_elem.find('xpdl:Route', self.NAMESPACES)
            gateway_type = route_elem.get('GatewayType', 'Exclusive')
            return 'Gateway', gateway_type
        
        # Check for tasks
        elif activity_elem.find('xpdl:Implementation', self.NAMESPACES) is not None:
            impl_elem = activity_elem.find('xpdl:Implementation', self.NAMESPACES)
            
            if impl_elem.find('xpdl:Task', self.NAMESPACES) is not None:
                task_elem = impl_elem.find('xpdl:Task', self.NAMESPACES)
                task_type = task_elem.get('TaskType', 'Service')
                return 'Task', task_type
            else:
                return 'Task', 'Generic'
        
        # Default case
        else:
            return 'Task', 'Generic'
    
    def _extract_gateway_info(self, activity_elem, gateway_type: str) -> Dict:
        """
        Extract additional information about a gateway.
        
        Args:
            activity_elem: The activity element representing a gateway
            gateway_type: The type of the gateway
            
        Returns:
            Dictionary containing gateway information
        """
        route_elem = activity_elem.find('xpdl:Route', self.NAMESPACES)
        
        gateway_info = {
            'gateway_type': gateway_type,
            'direction': 'Unspecified'
        }
        
        if route_elem is not None:
            gateway_direction = route_elem.get('GatewayDirection', 'Unspecified')
            gateway_info['direction'] = gateway_direction
            
            # Extract any conditions or expressions
            expression_elem = route_elem.find('.//xpdl:Expression', self.NAMESPACES)
            if expression_elem is not None and expression_elem.text:
                gateway_info['expression'] = expression_elem.text
        
        return gateway_info
    
    def extract_transitions(self, process_elem) -> None:
        """
        Extract all transitions from a process.
        
        Args:
            process_elem: The process element containing transitions
        """
        process_id = process_elem.get('Id')
        transitions_elem = process_elem.find('xpdl:Transitions', self.NAMESPACES)
        
        if transitions_elem is None:
            logger.warning(f"No transitions found in process {process_id}")
            return
        
        transitions = transitions_elem.findall('xpdl:Transition', self.NAMESPACES)
        for transition in transitions:
            transition_id = transition.get('Id')
            from_id = transition.get('From')
            to_id = transition.get('To')
            name = transition.get('Name', '')
            
            transition_data = {
                'id': transition_id,
                'from': from_id,
                'to': to_id,
                'name': name,
                'process_id': process_id,
                'condition': None,
                'condition_type': None
            }
            
            # Extract condition if present
            condition_elem = transition.find('xpdl:Condition', self.NAMESPACES)
            if condition_elem is not None:
                condition_type = condition_elem.get('Type', 'None')
                transition_data['condition_type'] = condition_type
                
                expression_elem = condition_elem.find('xpdl:Expression', self.NAMESPACES)
                if expression_elem is not None and expression_elem.text:
                    transition_data['condition'] = expression_elem.text
            
            self.transitions[transition_id] = transition_data
        
        logger.info(f"Extracted {len(transitions)} transitions from process {process_id}")
    
    def analyze_gateway_patterns(self) -> None:
        """
        Analyze gateway patterns to detect splits and joins.
        This helps in determining the relationship types based on gateway semantics.
        """
        # Process each gateway
        for gateway_id, gateway in self.gateways.items():
            # Find incoming transitions
            incoming = [t for t_id, t in self.transitions.items() if t['to'] == gateway_id]
            # Find outgoing transitions
            outgoing = [t for t_id, t in self.transitions.items() if t['from'] == gateway_id]
            
            # Determine pattern type
            if len(incoming) == 1 and len(outgoing) > 1:
                pattern_type = 'Split'
            elif len(incoming) > 1 and len(outgoing) == 1:
                pattern_type = 'Join'
            else:
                pattern_type = 'Other'
            
            # Map gateway type to relationship type
            gateway_subtype = gateway['subtype']
            rel_type = self._map_gateway_to_relationship(gateway_subtype, pattern_type)
            
            self.gateway_patterns[gateway_id] = {
                'id': gateway_id,
                'type': gateway['type'],
                'subtype': gateway_subtype,
                'pattern': pattern_type,
                'relationship_type': rel_type,
                'incoming': incoming,
                'outgoing': outgoing
            }
            
            # Debug logging for gateway patterns
            logger.info(f"Gateway {gateway_id} ({gateway['name']}): {gateway_subtype} {pattern_type} -> {rel_type} (in:{len(incoming)}, out:{len(outgoing)})")
        
        logger.info(f"Analyzed {len(self.gateway_patterns)} gateway patterns")
    
    def _map_gateway_to_relationship(self, gateway_type: str, pattern_type: str) -> str:
        """
        Map gateway type to relationship type.
        
        Args:
            gateway_type: The type of the gateway
            pattern_type: Whether the gateway is a split or join
            
        Returns:
            String representing the relationship type
        """
        if pattern_type == 'Split':
            if gateway_type == 'Exclusive':
                return 'XOR_SPLIT'
            elif gateway_type == 'Inclusive':
                return 'OR_SPLIT'
            elif gateway_type == 'Parallel':
                return 'AND_SPLIT'
            else:
                return 'GATEWAY_SPLIT'
        elif pattern_type == 'Join':
            if gateway_type == 'Exclusive':
                return 'XOR_JOIN'
            elif gateway_type == 'Inclusive':
                return 'OR_JOIN'
            elif gateway_type == 'Parallel':
                return 'AND_JOIN'
            else:
                return 'GATEWAY_JOIN'
        else:
            return 'GATEWAY_CONNECTION'
    
    def _identify_gateway_connections(self) -> Dict[str, Dict]:
        """
        Identify gateways that connect directly to other gateways and create mapping
        for intermediate nodes.
        
        Returns:
            Dictionary mapping transition IDs to information about gateway connections
        """
        gateway_ids = set(self.gateways.keys())
        gateway_connections = {}
        
        # Check all transitions for gateway-to-gateway connections
        for transition_id, transition in self.transitions.items():
            from_id = transition['from']
            to_id = transition['to']
            
            # If both source and target are gateways
            if from_id in gateway_ids and to_id in gateway_ids:
                from_gateway = self.gateways[from_id]
                to_gateway = self.gateways[to_id]
                
                # Generate a unique ID for the intermediate node
                intermediate_id = f"inter_{from_id}_{to_id}"
                intermediate_name = f"Gateway Connection: {from_gateway['name']} to {to_gateway['name']}"
                
                # Store connection info
                gateway_connections[transition_id] = {
                    'transition_id': transition_id,
                    'from_gateway_id': from_id,
                    'to_gateway_id': to_id,
                    'from_gateway_type': from_gateway['subtype'],
                    'to_gateway_type': to_gateway['subtype'],
                    'intermediate_id': intermediate_id,
                    'intermediate_name': intermediate_name,
                    'condition': transition['condition'],
                    'name': transition['name'],
                    'process_id': transition['process_id']
                }
        
        logger.info(f"Identified {len(gateway_connections)} direct gateway-to-gateway connections")
        return gateway_connections

    def _clear_database(self, session) -> None:
        """
        Clear all existing data from the Neo4j database.
        
        Args:
            session: Neo4j session
        """
        logger.info("Clearing existing data from Neo4j database")
        session.run("MATCH (n) DETACH DELETE n")
        logger.info("Database cleared")

    def _import_pools_and_lanes(self, session) -> None:
        """
        Import pools and lanes to Neo4j.
        
        Args:
            session: Neo4j session
        """
        # Import Pools
        for pool_id, pool in self.pools.items():
            session.run(
                """
                CREATE (p:Pool {
                    id: $id,
                    name: $name,
                    process: $process
                })
                """,
                id=pool['id'],
                name=pool['name'],
                process=pool['process']
            )
        
        # Import Lanes
        for lane_id, lane in self.lanes.items():
            session.run(
                """
                CREATE (l:Lane {
                    id: $id,
                    name: $name,
                    performer: $performer
                })
                """,
                id=lane['id'],
                name=lane['name'],
                performer=lane['performer']
            )
            
            # Create relationship between Lane and Pool
            session.run(
                """
                MATCH (l:Lane {id: $lane_id})
                MATCH (p:Pool {id: $pool_id})
                CREATE (l)-[:IN_POOL]->(p)
                """,
                lane_id=lane['id'],
                pool_id=lane['pool_id']
            )
            
        logger.info(f"Imported {len(self.pools)} pools and {len(self.lanes)} lanes to Neo4j")

    def _import_activities(self, session) -> None:
        """
        Import all activities (except gateways) to Neo4j.
        
        Args:
            session: Neo4j session
        """
        # Filter out gateways
        gateway_ids = set(self.gateways.keys())
        activities = {act_id: act for act_id, act in self.activities.items() if act_id not in gateway_ids}
        
        # Import activities
        for activity_id, activity in activities.items():
            # Base properties for activity
            properties = {
                'id': activity['id'],
                'name': activity['name'],
                'type': activity['type'],
                'subtype': activity['subtype'],
                'process_id': activity['process_id']
            }
            
            # Add all extended attributes and other properties
            for key, value in activity.items():
                if key not in properties and key != 'lane_id':
                    properties[key] = value
            
            # Build dynamic properties query part
            props_string = ", ".join([f"{k}: ${k}" for k in properties.keys()])
            
            # Create node with proper label based on type and subtype
            node_label = f"{activity['type']}_{activity['subtype']}"
            query = f"""
            CREATE (a:{node_label} {{
                {props_string}
            }})
            """
            
            session.run(query, **properties)
            
            # Connect to Lane if lane_id is available
            if activity['lane_id']:
                session.run(
                    """
                    MATCH (a) WHERE a.id = $activity_id
                    MATCH (l:Lane {id: $lane_id})
                    CREATE (a)-[:IN_LANE]->(l)
                    """,
                    activity_id=activity['id'],
                    lane_id=activity['lane_id']
                )
        
        logger.info(f"Imported {len(activities)} activities to Neo4j")

    def _import_gateway_nodes(self, session, connected_gateways: Set[str]) -> None:
        """
        Import gateway nodes to Neo4j, but only those that connect to other gateways.
        
        Args:
            session: Neo4j session
            connected_gateways: Set of gateway IDs that should be created as nodes
        """
        # Create Gateway nodes only for gateways that connect to other gateways
        for gateway_id in connected_gateways:
            gateway = self.gateways[gateway_id]
            
            # Base properties for gateway
            properties = {
                'id': gateway['id'],
                'name': gateway['name'],
                'type': gateway['type'],
                'subtype': gateway['subtype'],
                'process_id': gateway['process_id']
            }
            
            # Add all extended attributes and other properties
            for key, value in gateway.items():
                if key not in properties and key != 'lane_id':
                    properties[key] = value
            
            # Build dynamic properties query part
            props_string = ", ".join([f"{k}: ${k}" for k in properties.keys()])
            
            # Create Gateway node with proper label based on subtype
            gateway_label = f"Gateway_{gateway['subtype']}"
            query = f"""
            CREATE (g:{gateway_label} {{
                {props_string}
            }})
            """
            
            session.run(query, **properties)
            
            # Connect to Lane if lane_id is available
            if gateway['lane_id']:
                session.run(
                    """
                    MATCH (g) WHERE g.id = $gateway_id
                    MATCH (l:Lane {id: $lane_id})
                    CREATE (g)-[:IN_LANE]->(l)
                    """,
                    gateway_id=gateway['id'],
                    lane_id=gateway['lane_id']
                )
        
        logger.info(f"Imported {len(connected_gateways)} gateway nodes to Neo4j")

    def _import_gateway_connections(self, session, connected_gateways: Set[str]) -> None:
        """
        Import direct gateway-to-gateway connections.
        
        Args:
            session: Neo4j session
            connected_gateways: Set of gateway IDs that were created as nodes
        """
        # Get transitions between gateways
        gateway_transitions = []
        gateway_ids = set(self.gateways.keys())
        
        for transition_id, transition in self.transitions.items():
            from_id = transition['from']
            to_id = transition['to']
            
            # If both source and target are gateways and both were created as nodes
            if (from_id in gateway_ids and to_id in gateway_ids and 
                from_id in connected_gateways and to_id in connected_gateways):
                gateway_transitions.append(transition)
        
        # Create relationships for gateway-to-gateway transitions
        for transition in gateway_transitions:
            properties = {
                'id': transition['id'],
                'name': transition['name']
            }
            
            if transition['condition']:
                properties['condition'] = transition['condition']
            
            # Create the relationship
            session.run(
                """
                MATCH (source) WHERE source.id = $from_id
                MATCH (target) WHERE target.id = $to_id
                CREATE (source)-[r:GATEWAY_FLOW $properties]->(target)
                """,
                from_id=transition['from'],
                to_id=transition['to'],
                properties=properties
            )
        
        logger.info(f"Created {len(gateway_transitions)} gateway-to-gateway connections")
    
    def import_to_neo4j(self) -> None:
        """Import all extracted data to Neo4j."""
        with self.driver.session() as session:
            self._clear_database(session)
            self._import_pools_and_lanes(session)
            
            # Identify gateway connections
            gateway_connections = self._identify_gateway_connections()
            
            # Import activities (excluding gateways)
            self._import_activities(session)
            
            # Import intermediate nodes for gateway-to-gateway connections
            self._import_intermediate_nodes(session, gateway_connections)
            
            # Import semantic relationships for normal gateway patterns
            # (excluding gateway-to-gateway connections handled through intermediate nodes)
            self._import_semantic_relationships(session)
            
            # Import direct transitions (non-gateway to non-gateway)
            self._import_direct_transitions(session)
        
        logger.info("Data successfully imported to Neo4j")

    def _import_intermediate_nodes(self, session, gateway_connections: Dict[str, Dict]) -> None:
        """
        Import intermediate nodes for gateway-to-gateway connections and create relationships.
        
        Args:
            session: Neo4j session
            gateway_connections: Dictionary of gateway connections info
        """
        if not gateway_connections:
            logger.info("No gateway-to-gateway connections to process")
            return
            
        logger.info(f"Creating {len(gateway_connections)} intermediate nodes for gateway-to-gateway connections")
        
        for transition_id, connection in gateway_connections.items():
            # Create intermediate node
            properties = {
                'id': connection['intermediate_id'],
                'name': connection['intermediate_name'],
                'type': 'IntermediateNode',
                'is_gateway_connector': True,
                'from_gateway': connection['from_gateway_id'],
                'to_gateway': connection['to_gateway_id'],
                'process_id': connection['process_id']
            }
            
            # Create the intermediate node
            session.run(
                """
                CREATE (n:IntermediateNode {
                    id: $id,
                    name: $name,
                    type: $type,
                    is_gateway_connector: $is_gateway_connector,
                    from_gateway: $from_gateway,
                    to_gateway: $to_gateway,
                    process_id: $process_id
                })
                """,
                **properties
            )
            
            # Get the gateway patterns to determine relationship types
            from_gateway_id = connection['from_gateway_id']
            to_gateway_id = connection['to_gateway_id']
            
            # For gateway-to-gateway connections, use the actual gateway patterns
            # instead of assuming roles based on position
            from_rel_type = self._get_gateway_relationship_type(from_gateway_id, 'source')
            to_rel_type = self._get_gateway_relationship_type(to_gateway_id, 'target')
            
            # Debug logging to ensure correct types are used
            from_gateway_pattern = self.gateway_patterns.get(from_gateway_id, {})
            to_gateway_pattern = self.gateway_patterns.get(to_gateway_id, {})
            
            logger.info(f"Gateway-to-Gateway connection: {from_gateway_id} ({from_gateway_pattern.get('pattern', 'Unknown')}-{from_gateway_pattern.get('subtype', 'Unknown')}) -> {to_gateway_id} ({to_gateway_pattern.get('pattern', 'Unknown')}-{to_gateway_pattern.get('subtype', 'Unknown')})")
            logger.info(f"Relationship types: {from_rel_type} -> {to_rel_type}")
            
            # Create relationship from source activity to intermediate node
            self._create_gateway_to_intermediate_relationship(session, from_gateway_id, connection['intermediate_id'], from_rel_type, connection)
            
            # Create relationship from intermediate node to target activity
            self._create_intermediate_to_gateway_relationship(session, connection['intermediate_id'], to_gateway_id, to_rel_type, connection)
        
        logger.info(f"Created {len(gateway_connections)} intermediate nodes with relationships")
    
    def _get_relationship_type_for_gateway(self, gateway_id: str, direction: str) -> str:
        """
        Determine the relationship type for a gateway based on its pattern.
        
        Args:
            gateway_id: ID of the gateway
            direction: Either 'incoming' or 'outgoing'
            
        Returns:
            Relationship type
        """
        if gateway_id not in self.gateway_patterns:
            return 'GATEWAY_CONNECTION'
            
        pattern = self.gateway_patterns[gateway_id]
        gateway_type = self.gateways[gateway_id]['subtype']
        
        # Always use the proper relationship type based on the gateway pattern
        # regardless of direction - this ensures consistency
        return pattern['relationship_type']
    
    def _get_gateway_relationship_type(self, gateway_id: str, role: str) -> str:
        """
        Determine the relationship type for a gateway in gateway-to-gateway connections.
        
        Args:
            gateway_id: ID of the gateway
            role: Either 'source' (outgoing from this gateway) or 'target' (incoming to this gateway)
            
        Returns:
            Relationship type
        """
        if gateway_id not in self.gateway_patterns:
            logger.warning(f"Gateway {gateway_id} not found in gateway_patterns, using default")
            return 'GATEWAY_CONNECTION'
            
        # Use the actual gateway pattern analysis instead of assuming split/join based on role
        pattern = self.gateway_patterns[gateway_id]
        
        # Debug logging
        logger.info(f"Gateway {gateway_id} role={role}: pattern={pattern['pattern']}, subtype={pattern['subtype']}, rel_type={pattern['relationship_type']}")
        
        # Always return the correct relationship type based on the gateway's actual pattern
        # This ensures consistency with the XPDL definition
        return pattern['relationship_type']
    

    
    def _create_gateway_to_intermediate_relationship(self, session, gateway_id: str, intermediate_id: str, 
                                                    rel_type: str, connection: Dict) -> None:
        """
        Create relationship from activities through gateway to intermediate node.
        
        Args:
            session: Neo4j session
            gateway_id: ID of the source gateway
            intermediate_id: ID of the intermediate node
            rel_type: Relationship type based on gateway pattern
            connection: Connection information
        """
        properties = {
            'transition_id': connection['transition_id'],
            'gateway_id': gateway_id,
            'gateway_type': self.gateways[gateway_id]['subtype']
        }
        
        if connection['condition']:
            properties['condition'] = connection['condition']
        
        if connection['name']:
            properties['name'] = connection['name']
        
        # Find the activities connected to the source gateway
        source_activities = []
        for transition in self.transitions.values():
            if transition['to'] == gateway_id and transition['from'] not in self.gateways:
                source_activities.append(transition['from'])
        
        # Create relationship from each source activity to the intermediate node with the appropriate rel_type
        for source_id in source_activities:
            session.run(
                f"""
                MATCH (source) WHERE source.id = $source_id
                MATCH (target:IntermediateNode) WHERE target.id = $intermediate_id
                CREATE (source)-[r:{rel_type} $properties]->(target)
                """,
                source_id=source_id,
                intermediate_id=intermediate_id,
                properties=properties
            )
    
    def _create_intermediate_to_gateway_relationship(self, session, intermediate_id: str, gateway_id: str, 
                                                   rel_type: str, connection: Dict) -> None:
        """
        Create relationship from intermediate node through gateway to target activities.
        
        Args:
            session: Neo4j session
            intermediate_id: ID of the intermediate node
            gateway_id: ID of the target gateway
            rel_type: Relationship type based on gateway pattern
            connection: Connection information
        """
        properties = {
            'transition_id': connection['transition_id'],
            'gateway_id': gateway_id,
            'gateway_type': self.gateways[gateway_id]['subtype']
        }
        
        if connection['condition']:
            properties['condition'] = connection['condition']
        
        if connection['name']:
            properties['name'] = connection['name']
        
        # Find the activities connected from the target gateway
        target_activities = []
        for transition in self.transitions.values():
            if transition['from'] == gateway_id and transition['to'] not in self.gateways:
                target_activities.append(transition['to'])
        
        # Create relationship from intermediate node to each target activity with the appropriate rel_type
        for target_id in target_activities:
            session.run(
                f"""
                MATCH (source:IntermediateNode) WHERE source.id = $intermediate_id
                MATCH (target) WHERE target.id = $target_id
                CREATE (source)-[r:{rel_type} $properties]->(target)
                """,
                intermediate_id=intermediate_id,
                target_id=target_id,
                properties=properties
            )

    def _import_semantic_relationships(self, session) -> None:
        """
        Import semantic relationships based on gateway patterns.
        This creates direct relationships between activities connected through gateways,
        but excludes gateway-to-gateway connections that are handled separately.
        """
        # Get all gateway-to-gateway connections to exclude them
        gateway_ids = set(self.gateways.keys())
        gateway_to_gateway_transitions = set()
        
        for transition_id, transition in self.transitions.items():
            if transition['from'] in gateway_ids and transition['to'] in gateway_ids:
                gateway_to_gateway_transitions.add(transition_id)
        
        for gateway_id, pattern in self.gateway_patterns.items():
            relationship_type = pattern['relationship_type']
            
            if pattern['pattern'] == 'Split':
                # For splits, connect the source to all targets directly
                incoming_transitions = pattern['incoming']
                if not incoming_transitions:
                    continue
                
                source = incoming_transitions[0]['from']
                
                for outgoing in pattern['outgoing']:
                    # Skip if this is a gateway-to-gateway connection
                    if outgoing['id'] in gateway_to_gateway_transitions:
                        continue
                        
                    target = outgoing['to']
                    properties = {
                        'gateway_id': gateway_id,
                        'gateway_type': pattern['subtype']
                    }
                    
                    # Add condition if present
                    if outgoing['condition']:
                        properties['condition'] = outgoing['condition']
                    
                    # Create relationship only if target is not a gateway
                    if target not in gateway_ids:
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
            
            elif pattern['pattern'] == 'Join':
                # For joins, connect all sources to the target directly
                outgoing_transitions = pattern['outgoing']
                if not outgoing_transitions:
                    continue
                
                target = outgoing_transitions[0]['to']
                
                for incoming in pattern['incoming']:
                    # Skip if this is a gateway-to-gateway connection
                    if incoming['id'] in gateway_to_gateway_transitions:
                        continue
                        
                    source = incoming['from']
                    
                    # Create relationship only if source is not a gateway
                    if source not in gateway_ids:
                        session.run(
                            f"""
                            MATCH (source) WHERE source.id = $source_id
                            MATCH (target) WHERE target.id = $target_id
                            CREATE (source)-[r:{relationship_type} {{gateway_id: $gateway_id, gateway_type: $gateway_type}}]->(target)
                            """,
                            source_id=source,
                            target_id=target,
                            gateway_id=gateway_id,
                            gateway_type=pattern['subtype']
                        )
    
    def _import_direct_transitions(self, session) -> None:
        """
        Import direct transitions that don't involve gateways.
        """
        # Get all gateway IDs
        gateway_ids = set(self.gateways.keys())
        
        # Filter transitions that don't involve gateways
        direct_transitions = [
            t for t_id, t in self.transitions.items()
            if t['from'] not in gateway_ids and t['to'] not in gateway_ids
        ]
        
        # Create direct relationships
        for transition in direct_transitions:
            properties = {
                'id': transition['id'],
                'name': transition['name']
            }
            
            if transition['condition']:
                properties['condition'] = transition['condition']
            
            session.run(
                """
                MATCH (source) WHERE source.id = $from_id
                MATCH (target) WHERE target.id = $to_id
                CREATE (source)-[r:SEQUENCE $properties]->(target)
                """,
                from_id=transition['from'],
                to_id=transition['to'],
                properties=properties
            )
        
        logger.info(f"Created {len(direct_transitions)} direct transition relationships")
        
    def close(self) -> None:
        """Close the Neo4j driver connection."""
        self.driver.close()
        logger.info("Neo4j connection closed")
    
    def process(self) -> Dict:
        """
        Process the XPDL file and import to Neo4j.
        
        Returns:
            Dictionary with processing statistics
        """
        try:
            self.load_and_parse()
            self.extract_all_data()
            
            self.import_to_neo4j()
            self.close()
            return {
                'status': 'success',
                'statistics': {
                    'pools': len(self.pools),
                    'lanes': len(self.lanes),
                    'activities': len(self.activities) - len(self.gateways),
                    'gateways': len(self.gateways),
                    'transitions': len(self.transitions)
                },
            }
        except Exception as e:
            logger.error(f"Error processing XPDL: {str(e)}")
            self.close()
            return {
                'status': 'error',
                'message': str(e)
            }