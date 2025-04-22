
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple, Set, Any
import logging

from config import NAMESPACES, GATEWAY_TYPES, logger
from models import Participant, Pool, Lane, Activity, Gateway, Transition, GatewayPattern

class XPDLParser:
    """Parses XPDL files and extracts process data"""
    
    def __init__(self, xpdl_file: str):
        self.xpdl_file = xpdl_file
        self.tree = None
        self.root = None
        
        # Data collections
        self.pools: Dict[str, Pool] = {}
        self.lanes: Dict[str, Lane] = {}
        self.participants: Dict[str, Participant] = {}
        self.activities: Dict[str, Activity] = {}
        self.transitions: Dict[str, Transition] = {}
        self.gateways: Dict[str, Gateway] = {}
        self.gateway_patterns: Dict[str, GatewayPattern] = {}
    
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
        participant_elems = self.root.findall(".//xpdl:Participant", NAMESPACES)
        for participant in participant_elems:
            participant_id = participant.get('Id')
            participant_name = participant.get('Name', f"Unnamed Participant {participant_id}")
            self.participants[participant_id] = Participant(
                id=participant_id,
                name=participant_name
            )
        logger.info(f"Extracted {len(self.participants)} participants")
    
    def extract_pools_and_lanes(self) -> None:
        """Extract pools and lanes information from the XPDL file."""
        pools = self.root.findall(".//xpdl:Pool", NAMESPACES)
        for pool in pools:
            pool_id = pool.get('Id')
            pool_name = pool.get('Name', f"Unnamed Pool {pool_id}")
            process_ref = pool.get('Process')
            
            self.pools[pool_id] = Pool(
                id=pool_id,
                name=pool_name,
                process=process_ref,
                lanes=[]
            )
            
            # Extract lanes
            lanes = pool.findall("xpdl:Lanes/xpdl:Lane", NAMESPACES)
            for lane in lanes:
                lane_id = lane.get('Id')
                lane_name = lane.get('Name', f"Unnamed Lane {lane_id}")
                performer = lane.get('Performer', '')
                
                self.lanes[lane_id] = Lane(
                    id=lane_id,
                    name=lane_name,
                    performer=performer,
                    pool_id=pool_id
                )
                self.pools[pool_id].lanes.append(lane_id)
        
        logger.info(f"Extracted {len(self.pools)} pools and {len(self.lanes)} lanes")
    
    def extract_all_processes(self) -> None:
        """Extract all processes from the XPDL file."""
        processes = self.root.findall(".//xpdl:WorkflowProcess", NAMESPACES)
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
        activities_elem = process_elem.find('xpdl:Activities', NAMESPACES)
        
        if activities_elem is None:
            logger.warning(f"No activities found in process {process_id}")
            return
        
        activities = activities_elem.findall('xpdl:Activity', NAMESPACES)
        for activity in activities:
            activity_id = activity