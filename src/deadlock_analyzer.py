import logging
from typing import Dict, List, Set, Tuple
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

class DeadlockAnalyzer:
    """
    Comprehensive analyzer for detecting different types of deadlocks in BPMN processes.
    
    This analyzer can detect:
    1. Structural deadlocks - Missing convergence gateways
    2. Timing deadlocks - Excessive processing times in parallel paths
    """
    
    def __init__(self, uri: str, user: str, password: str):
        """Initialize deadlock analyzer with Neo4j connection details."""
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        
        # Check property existence
        self.has_processing_time = False
        self.has_waiting_time = False
        self.has_lane = False
        self.has_direction = False
        self._check_property_existence()
    
    def _check_property_existence(self):
        """Check if required properties exist in the database."""
        with self.driver.session() as session:
            # Check processing time
            result = session.run("MATCH (a:Activity) WHERE a.processingTime IS NOT NULL RETURN count(a) AS count")
            record = result.single()
            self.has_processing_time = record and record["count"] > 0
            
            # Try alternate property names for processing time
            if not self.has_processing_time:
                result = session.run("MATCH (a:Activity) WHERE a.processing_time IS NOT NULL RETURN count(a) AS count")
                record = result.single()
                self.has_processing_time = record and record["count"] > 0
            
            # Check waiting time
            result = session.run("MATCH (a:Activity) WHERE a.waitingTime IS NOT NULL RETURN count(a) AS count")
            record = result.single()
            self.has_waiting_time = record and record["count"] > 0
            
            # Check lane property
            result = session.run("MATCH (a:Activity) WHERE a.lane IS NOT NULL RETURN count(a) AS count")
            record = result.single()
            self.has_lane = record and record["count"] > 0
            
            # Check direction property on gateways
            result = session.run("MATCH (g:Gateway) WHERE g.direction IS NOT NULL RETURN count(g) AS count")
            record = result.single()
            self.has_direction = record and record["count"] > 0
            
            logger.info(f"Property existence check: processingTime: {self.has_processing_time}, " +
                      f"waitingTime: {self.has_waiting_time}, lane: {self.has_lane}, " +
                      f"direction: {self.has_direction}")
    
    def close(self):
        """Close the Neo4j driver."""
        self.driver.close()
    
    def analyze_structural_deadlocks(self, report_file: str) -> List[Dict]:
        """
        Analyze structural deadlocks in BPMN processes (Type 1).
        """
        logger.info("Analyzing structural deadlocks...")
        structural_deadlocks = []
        
        with self.driver.session() as session:
            # Modify query to handle potential missing 'direction' property
            direction_filter = "g.direction = 'diverging' OR g.direction IS NULL" if self.has_direction else "true"
            
            # Find inclusive gateways without matching convergence gateways
            query = f"""
                MATCH (g:Gateway {{type: 'inclusive'}})
                WHERE {direction_filter}
                AND NOT EXISTS {{
                    MATCH (g)-[*1..20]->(converge:Gateway {{type: 'inclusive'}})
                    WHERE {self.has_direction and "converge.direction = 'converging'" or "true"}
                }}
                RETURN g.id AS gateway_id, g.name AS gateway_name, 
                       {self.has_lane and "g.lane" or "null"} AS lane_id
            """
            result = session.run(query)
            
            for record in result:
                structural_deadlocks.append({
                    'type': 'Structural',
                    'subtype': 'Missing Convergence Gateway',
                    'gateway_id': record['gateway_id'],
                    'gateway_name': record['gateway_name'],
                    'lane_id': record['lane_id'] or "Unknown",
                    'description': f"Inclusive gateway '{record['gateway_name']}' does not have a matching convergence gateway"
                })
            
            # Find parallel gateways without matching convergence gateways
            query = f"""
                MATCH (g:Gateway {{type: 'parallel'}})
                WHERE {direction_filter}
                AND NOT EXISTS {{
                    MATCH (g)-[*1..20]->(converge:Gateway {{type: 'parallel'}})
                    WHERE {self.has_direction and "converge.direction = 'converging'" or "true"}
                }}
                RETURN g.id AS gateway_id, g.name AS gateway_name, 
                       {self.has_lane and "g.lane" or "null"} AS lane_id
            """
            result = session.run(query)
            
            for record in result:
                structural_deadlocks.append({
                    'type': 'Structural',
                    'subtype': 'Missing Convergence Gateway',
                    'gateway_id': record['gateway_id'],
                    'gateway_name': record['gateway_name'],
                    'lane_id': record['lane_id'] or "Unknown",
                    'description': f"Parallel gateway '{record['gateway_name']}' does not have a matching convergence gateway"
                })
            
            # Only run this if direction property exists
            if self.has_direction:
                # Check for mismatched gateway pairs
                result = session.run("""
                    MATCH (g1:Gateway)-[*1..20]->(g2:Gateway)
                    WHERE g1.direction = 'diverging' AND g2.direction = 'converging'
                    AND g1.type <> g2.type
                    RETURN g1.id AS gateway1_id, g1.name AS gateway1_name, g1.type AS gateway1_type,
                           g2.id AS gateway2_id, g2.name AS gateway2_name, g2.type AS gateway2_type
                """)
                
                for record in result:
                    structural_deadlocks.append({
                        'type': 'Structural',
                        'subtype': 'Mismatched Gateway Types',
                        'gateway_id': record['gateway1_id'],
                        'gateway_name': record['gateway1_name'],
                        'gateway_type': record['gateway1_type'],
                        'converging_gateway_id': record['gateway2_id'],
                        'converging_gateway_name': record['gateway2_name'],
                        'converging_gateway_type': record['gateway2_type'],
                        'description': f"Mismatched gateway pair: {record['gateway1_type']} split gateway '{record['gateway1_name']}' "
                                      f"with {record['gateway2_type']} join gateway '{record['gateway2_name']}'"
                    })
        
        # Write report
        with open(report_file, 'w') as f:
            f.write("=== STRUCTURAL DEADLOCK REPORT ===\n\n")
            if not structural_deadlocks:
                f.write("No structural deadlocks detected.\n")
            else:
                f.write(f"Found {len(structural_deadlocks)} structural deadlocks:\n\n")
                
                for i, deadlock in enumerate(structural_deadlocks, 1):
                    f.write(f"Deadlock #{i}:\n")
                    f.write(f"  Type: {deadlock['subtype']}\n")
                    f.write(f"  Gateway: {deadlock['gateway_name']} (ID: {deadlock['gateway_id']})\n")
                    
                    if 'converging_gateway_name' in deadlock:
                        f.write(f"  Converging Gateway: {deadlock['converging_gateway_name']} "
                               f"(ID: {deadlock['converging_gateway_id']})\n")
                    
                    f.write(f"  Description: {deadlock['description']}\n\n")
        
        return structural_deadlocks
    
    def analyze_timing_deadlocks(self, report_file: str) -> List[Dict]:
        """
        Analyze timing deadlocks in BPMN processes (Type 3).
        """
        logger.info("Analyzing timing deadlocks...")
        timing_deadlocks = []
        
        # Skip this analysis if we don't have timing properties
        if not (self.has_processing_time or self.has_waiting_time):
            logger.warning("No timing properties found. Skipping timing deadlock analysis.")
            with open(report_file, 'w') as f:
                f.write("=== TIMING DEADLOCK REPORT ===\n\n")
                f.write("No timing deadlocks detected.\n")
                f.write("Note: Required timing properties (processingTime, waitingTime) not found in database.\n")
            return timing_deadlocks
        
        # Define thresholds for long-running activities (in minutes)
        long_threshold = 60   # 1 hour
        critical_threshold = 240  # 4 hours
        
        with self.driver.session() as session:
            # Create appropriate conditions based on available properties
            time_conditions = []
            if self.has_processing_time:
                time_conditions.append("a.processingTime > " + str(long_threshold))
            if self.has_waiting_time:
                time_conditions.append("a.waitingTime > " + str(long_threshold))
            
            time_condition = " OR ".join(time_conditions) if time_conditions else "false"
            
            # Check if we have direction property
            direction_condition = "j.direction = 'converging'" if self.has_direction else "true"
            
            # Find activities with long processing times in parallel paths
            query = f"""
                MATCH (g:Gateway {{type: 'parallel'}})-[*1..15]->(a:Activity)-[*1..15]->(j:Gateway {{type: 'parallel'}})
                WHERE {time_condition}
                AND {direction_condition}
                RETURN g.id AS gateway_id, g.name AS gateway_name,
                       a.id AS activity_id, a.name AS activity_name, 
                       {self.has_processing_time and "a.processingTime" or "0"} AS processing_time, 
                       {self.has_waiting_time and "a.waitingTime" or "0"} AS waiting_time,
                       {self.has_lane and "a.lane" or "null"} AS lane_id
            """
            result = session.run(query)
            
            for record in result:
                # Calculate total time
                processing_time = record['processing_time'] if record['processing_time'] is not None else 0
                waiting_time = record['waiting_time'] if record['waiting_time'] is not None else 0
                total_time = processing_time + waiting_time
                
                # Determine severity based on time
                severity = "Critical" if total_time > critical_threshold else "High"
                
                timing_deadlocks.append({
                    'type': 'Timing',
                    'subtype': 'Long Processing Time in Parallel Path',
                    'gateway_id': record['gateway_id'],
                    'gateway_name': record['gateway_name'],
                    'activity_id': record['activity_id'],
                    'activity_name': record['activity_name'],
                    'processing_time': processing_time,
                    'waiting_time': waiting_time,
                    'total_time': total_time,
                    'lane_id': record['lane_id'] or "Unknown",
                    'severity': severity,
                    'description': f"Activity '{record['activity_name']}' with excessive processing time ({total_time} minutes) "
                                  f"in parallel path from gateway '{record['gateway_name']}'"
                })
            
            # For critical threshold with any activity
            critical_conditions = []
            if self.has_processing_time:
                critical_conditions.append("a.processingTime > " + str(critical_threshold))
            if self.has_waiting_time:
                critical_conditions.append("a.waitingTime > " + str(critical_threshold))
            
            critical_condition = " OR ".join(critical_conditions) if critical_conditions else "false"
            
            # Find activities with extremely long processing times anywhere
            query = f"""
                MATCH (a:Activity)
                WHERE {critical_condition}
                RETURN a.id AS activity_id, a.name AS activity_name,
                       {self.has_processing_time and "a.processingTime" or "0"} AS processing_time, 
                       {self.has_waiting_time and "a.waitingTime" or "0"} AS waiting_time,
                       {self.has_lane and "a.lane" or "null"} AS lane_id
            """
            result = session.run(query)
            
            for record in result:
                # Calculate total time
                processing_time = record['processing_time'] if record['processing_time'] is not None else 0
                waiting_time = record['waiting_time'] if record['waiting_time'] is not None else 0
                total_time = processing_time + waiting_time
                
                timing_deadlocks.append({
                    'type': 'Timing',
                    'subtype': 'Excessive Processing Time',
                    'activity_id': record['activity_id'],
                    'activity_name': record['activity_name'],
                    'processing_time': processing_time,
                    'waiting_time': waiting_time,
                    'total_time': total_time,
                    'lane_id': record['lane_id'] or "Unknown",
                    'severity': "Critical",
                    'description': f"Activity '{record['activity_name']}' has excessive processing time ({total_time} minutes), "
                                  f"which could indefinitely block process execution"
                })
        
        # Write report
        with open(report_file, 'w') as f:
            f.write("=== TIMING DEADLOCK REPORT ===\n\n")
            if not timing_deadlocks:
                f.write("No timing deadlocks detected.\n")
            else:
                f.write(f"Found {len(timing_deadlocks)} timing deadlocks:\n\n")
                
                for i, deadlock in enumerate(timing_deadlocks, 1):
                    f.write(f"Deadlock #{i}:\n")
                    f.write(f"  Type: {deadlock['subtype']}\n")
                    f.write(f"  Activity: {deadlock['activity_name']} (ID: {deadlock['activity_id']})\n")
                    f.write(f"  Processing Time: {deadlock['processing_time']} minutes\n")
                    f.write(f"  Waiting Time: {deadlock['waiting_time']} minutes\n")
                    f.write(f"  Severity: {deadlock['severity']}\n")
                    if 'gateway_name' in deadlock:
                        f.write(f"  Gateway: {deadlock['gateway_name']} (ID: {deadlock['gateway_id']})\n")
                    f.write(f"  Description: {deadlock['description']}\n\n")
        
        return timing_deadlocks
    
    def generate_comprehensive_report(self, report_file: str, structural_deadlocks: List[Dict], 
                                     sql_deadlocks: List[Dict], timing_deadlocks: List[Dict]):
        """
        Generate a comprehensive report of all detected deadlocks.
        
        Args:
            report_file: Path to save the report
            structural_deadlocks: List of structural deadlocks
            sql_deadlocks: List of SQL deadlocks
            timing_deadlocks: List of timing deadlocks
        """
        with open(report_file, 'w') as f:
            f.write("=== COMPREHENSIVE DEADLOCK ANALYSIS REPORT ===\n\n")
            
            # Summary
            total_deadlocks = len(structural_deadlocks) + len(sql_deadlocks) + len(timing_deadlocks)
            f.write(f"Total deadlocks detected: {total_deadlocks}\n")
            f.write(f"  - Structural deadlocks: {len(structural_deadlocks)}\n")
            f.write(f"  - SQL deadlocks: {len(sql_deadlocks)}\n")
            f.write(f"  - Timing deadlocks: {len(timing_deadlocks)}\n\n")
            
            # Structural Deadlocks Section
            if structural_deadlocks:
                f.write("=== STRUCTURAL DEADLOCKS ===\n\n")
                for i, deadlock in enumerate(structural_deadlocks, 1):
                    f.write(f"Deadlock #{i}:\n")
                    f.write(f"  Type: {deadlock['subtype']}\n")
                    f.write(f"  Gateway: {deadlock['gateway_name']} (ID: {deadlock['gateway_id']})\n")
                    if 'converging_gateway_name' in deadlock:
                        f.write(f"  Converging Gateway: {deadlock['converging_gateway_name']} "
                               f"(ID: {deadlock['converging_gateway_id']})\n")
                    f.write(f"  Description: {deadlock['description']}\n\n")
            
            # SQL Deadlocks Section
            if sql_deadlocks:
                f.write("=== SQL DEADLOCKS ===\n\n")
                for i, deadlock in enumerate(sql_deadlocks, 1):
                    f.write(f"Deadlock #{i}:\n")
                    f.write(f"  Type: {deadlock['type']}\n")
                    f.write(f"  Gateway: {deadlock['gateway_name']} (ID: {deadlock['gateway_id']})\n")
                    f.write(f"  Task 1: {deadlock['task1_name']} (ID: {deadlock['task1_id']})\n")
                    f.write(f"  Task 2: {deadlock['task2_name']} (ID: {deadlock['task2_id']})\n")
                    f.write(f"  Resources: {', '.join(deadlock['resources'])}\n")
                    f.write(f"  Access Pattern 1: {deadlock['access_pattern1']}\n")
                    f.write(f"  Access Pattern 2: {deadlock['access_pattern2']}\n")
                    f.write(f"  Description: {deadlock['description']}\n\n")
            
            # Timing Deadlocks Section
            if timing_deadlocks:
                f.write("=== TIMING DEADLOCKS ===\n\n")
                for i, deadlock in enumerate(timing_deadlocks, 1):
                    f.write(f"Deadlock #{i}:\n")
                    f.write(f"  Type: {deadlock['subtype']}\n")
                    f.write(f"  Activity: {deadlock['activity_name']} (ID: {deadlock['activity_id']})\n")
                    f.write(f"  Processing Time: {deadlock['processing_time']} minutes\n")
                    f.write(f"  Waiting Time: {deadlock['waiting_time']} minutes\n")
                    f.write(f"  Severity: {deadlock['severity']}\n")
                    if 'gateway_name' in deadlock:
                        f.write(f"  Gateway: {deadlock['gateway_name']} (ID: {deadlock['gateway_id']})\n")
                    f.write(f"  Description: {deadlock['description']}\n\n")
            
            # Recommendations Section
            f.write("=== RECOMMENDATIONS ===\n\n")
            
            if structural_deadlocks:
                f.write("For structural deadlocks:\n")
                f.write("  - Add matching convergence gateways for each diverging gateway\n")
                f.write("  - Ensure gateway types are consistent (parallel with parallel, inclusive with inclusive)\n")
                f.write("  - Review the process flow to ensure all paths can be completed\n\n")
            
            if sql_deadlocks:
                f.write("For SQL deadlocks:\n")
                f.write("  - Standardize the order of table access across all transactions\n")
                f.write("  - Consider using optimistic locking instead of pessimistic locking\n")
                f.write("  - Remove WAITFOR DELAY statements from transactions\n")
                f.write("  - Implement transaction isolation levels and deadlock detection\n")
                f.write("  - Consider shorter transactions or decomposing them into smaller units\n\n")
            
            if timing_deadlocks:
                f.write("For timing deadlocks:\n")
                f.write("  - Add timeouts to long-running activities\n")
                f.write("  - Implement asynchronous processing for activities with unpredictable timing\n")
                f.write("  - Split long-running activities into smaller steps\n")
                f.write("  - Use message events instead of long activity waits\n")
                f.write("  - Consider implementing compensation handlers for timeouts\n")
