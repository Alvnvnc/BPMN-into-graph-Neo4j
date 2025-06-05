#!/usr/bin/env python3
"""
SQL Resource Extractor Module
Handles SQL parsing and database resource extraction from BPMN nodes.
Refactored from backup_sql.py for modular architecture.
"""

import re
import logging
import sqlparse
from typing import Dict, List, Set, Optional

logger = logging.getLogger(__name__)

class SQLResourceExtractor:
    """
    Extracts SQL resources (tables, columns, operations) from SQL queries
    """
    
    def __init__(self):
        """
        Initialize the SQL resource extractor
        """
        logger.debug("Initializing SQLResourceExtractor")
    
    def extract_from_graph_data(self, graph_data: Dict) -> Dict:
        """
        Extract SQL resources from all nodes in graph data
        
        Args:
            graph_data: Graph data containing nodes and relationships
            
        Returns:
            Dict: SQL resources indexed by node ID
        """
        sql_resources = {}
        
        logger.info("Extracting SQL resources from graph data...")
        
        # Handle both dictionary format (nodes as dict) and array format (nodes as list)
        nodes_data = graph_data.get('nodes', [])
        
        if isinstance(nodes_data, dict):
            # Dictionary format: {node_id: node_data}
            nodes_iterator = nodes_data.items()
        elif isinstance(nodes_data, list):
            # Array format: [{id: node_id, properties: {...}}, ...]
            nodes_iterator = [(node.get('id'), node) for node in nodes_data]
        else:
            logger.warning(f"Unexpected nodes data format: {type(nodes_data)}")
            return sql_resources
        
        for node_id, node_data in nodes_iterator:
            if not node_id or not node_data:
                continue
                
            # Extract properties - handle both nested and direct property access
            if 'properties' in node_data:
                props = node_data['properties']
                labels = node_data.get('labels', [])
            else:
                # Direct property access (flat structure)
                props = node_data
                labels = props.get('labels', [])
            
            # Check if node has SQL property
            if 'SQL' in props and props['SQL']:
                sql_property = props['SQL']
                
                # Ensure SQL property is a string
                if isinstance(sql_property, dict):
                    # If it's a dict, try to extract a string value
                    sql_query = str(sql_property.get('value', sql_property.get('text', str(sql_property))))
                elif isinstance(sql_property, (list, tuple)):
                    # If it's a list/tuple, join or take first element
                    sql_query = str(sql_property[0]) if sql_property else ""
                else:
                    # Convert to string
                    sql_query = str(sql_property)
                
                # Skip if empty after conversion
                if not sql_query.strip():
                    logger.debug(f"Skipping node {node_id} - empty SQL after conversion")
                    continue
                
                resources = self.extract_sql_resources(sql_query)
                
                sql_resources[node_id] = {
                    'name': props.get('name', f'Node_{node_id}'),
                    'sql': sql_query,
                    'resources': resources,
                    'labels': labels
                }
                
                logger.debug(f"Extracted resources from {props.get('name', node_id)}: {resources}")
        
        logger.info(f"Found {len(sql_resources)} nodes with SQL operations")
        return sql_resources
    
    def _clean_sql_format(self, sql_query: str) -> str:
        """
        Clean malformed SQL format that may have duplicate prefixes like 'SQL: SQL: UPDATE...'
        
        Args:
            sql_query: Original SQL string
            
        Returns:
            Cleaned SQL string without duplicate prefixes
        """
        if not sql_query:
            return sql_query
            
        # Remove duplicate 'SQL:' prefixes - handle both 'SQL: SQL:' and multiple occurrences
        cleaned = sql_query.strip()
        
        # Keep removing 'SQL:' prefix until we get to the actual SQL statement
        while cleaned.upper().startswith('SQL:'):
            cleaned = cleaned[4:].strip()  # Remove 'SQL:' (4 chars) and strip whitespace
            
        return cleaned

    def extract_sql_resources(self, sql_query: str) -> Dict:
        """
        Extract database resources from SQL query with WHERE clause analysis
        
        Args:
            sql_query: SQL query string
            
        Returns:
            Dict: Extracted resources (tables, columns, operations, where_conditions)
        """
        if not sql_query:
            return {
                'tables': set(), 
                'columns': set(), 
                'operations': set(), 
                'where_conditions': []
            }
            
        try:
            # Clean SQL query - remove duplicate "SQL:" prefixes
            cleaned_sql = self._clean_sql_format(sql_query)
            logger.debug(f"Original SQL: {sql_query}")
            logger.debug(f"Cleaned SQL: {cleaned_sql}")
            
            # Parse SQL using sqlparse
            parsed = sqlparse.parse(cleaned_sql.upper())
            resources = {
                'tables': set(),
                'columns': set(), 
                'operations': set(),
                'where_conditions': []  # Store WHERE clause conditions for mutual exclusion analysis
            }
            
            for statement in parsed:
                # Extract operation type
                first_token = str(statement.tokens[0]).strip()
                if first_token in ['SELECT', 'UPDATE', 'INSERT', 'DELETE']:
                    resources['operations'].add(first_token)
                
                # Extract table names using regex patterns
                sql_text = str(statement)
                
                # Table patterns for different operations
                table_patterns = [
                    r'FROM\s+([\w]+)',
                    r'UPDATE\s+([\w]+)',
                    r'INSERT\s+INTO\s+([\w]+)',
                    r'DELETE\s+FROM\s+([\w]+)',
                    r'JOIN\s+([\w]+)'
                ]
                
                for pattern in table_patterns:
                    matches = re.findall(pattern, sql_text, re.IGNORECASE)
                    resources['tables'].update(matches)
                
                # Extract column names from WHERE clauses
                self._extract_where_columns(sql_text, resources)
                
                # Extract SET clause columns (for UPDATE)
                set_pattern = r'SET\s+([\w]+)\s*='
                set_matches = re.findall(set_pattern, sql_text, re.IGNORECASE)
                resources['columns'].update(set_matches)
                
                # Extract complete WHERE conditions for mutual exclusion analysis
                self._extract_where_conditions(sql_text, resources)
                
            return resources
            
        except Exception as e:
            logger.warning(f"Error parsing SQL: {e}")
            return {
                'tables': set(), 
                'columns': set(), 
                'operations': set(), 
                'where_conditions': []
            }
    
    def _extract_where_columns(self, sql_text: str, resources: Dict):
        """
        Extract column names from WHERE clauses
        
        Args:
            sql_text: SQL query text
            resources: Resources dictionary to update
        """
        # Extract column names from WHERE clauses - enhanced to capture ALL columns
        where_pattern = r'WHERE\s+(.+?)(?:ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|;|$)'
        where_match = re.search(where_pattern, sql_text, re.IGNORECASE | re.DOTALL)
        
        if where_match:
            where_clause = where_match.group(1)
            
            # Extract all column names from WHERE clause conditions
            column_patterns = [
                r'(\w+)\s*[=<>!]',  # column = value
                r'(\w+)\s+(?:IN|LIKE|BETWEEN)',  # column IN/LIKE/BETWEEN
                r'(\w+)\s+IS\s+(?:NULL|NOT\s+NULL)',  # column IS NULL
            ]
            
            for pattern in column_patterns:
                column_matches = re.findall(pattern, where_clause, re.IGNORECASE)
                resources['columns'].update(column_matches)
                
            logger.debug(f"WHERE clause: {where_clause}")
            logger.debug(f"Extracted WHERE columns: {column_matches}")
    
    def _extract_where_conditions(self, sql_text: str, resources: Dict):
        """
        Extract WHERE clause conditions for mutual exclusion analysis
        
        Args:
            sql_text: SQL query text
            resources: Resources dictionary to update
        """
        try:
            # Find WHERE clause using regex
            where_match = re.search(
                r'WHERE\s+(.+?)(?:ORDER\s+BY|GROUP\s+BY|HAVING|LIMIT|$)', 
                sql_text, 
                re.IGNORECASE | re.DOTALL
            )
            
            if where_match:
                where_clause = where_match.group(1).strip()
                
                # Parse equality conditions like "column = 'value'"
                equality_conditions = re.findall(
                    r'(\w+)\s*=\s*[\'"]*([^\s\'"]+)[\'"]*', 
                    where_clause, 
                    re.IGNORECASE
                )
                
                # Store parsed conditions for mutual exclusion checking
                for column, value in equality_conditions:
                    condition = {
                        'column': column.upper(),
                        'operator': '=',
                        'value': value.strip('\'\'"').upper(),
                        'raw_condition': f"{column} = '{value}'"
                    }
                    resources['where_conditions'].append(condition)
                    
                logger.debug(f"Extracted WHERE conditions: {resources['where_conditions']}")
                
        except Exception as e:
            logger.warning(f"Error extracting WHERE conditions: {e}")
    
    def check_mutual_exclusion(self, res1: Dict, res2: Dict) -> bool:
        """
        Check if two SQL resources have mutually exclusive WHERE conditions
        
        Args:
            res1: First SQL resource
            res2: Second SQL resource
            
        Returns:
            bool: True if resources are mutually exclusive
        """
        try:
            conditions1 = res1.get('where_conditions', [])
            conditions2 = res2.get('where_conditions', [])
            
            # Check for mutual exclusion: same column with different values
            for cond1 in conditions1:
                for cond2 in conditions2:
                    if (cond1['column'] == cond2['column'] and 
                        cond1['operator'] == '=' and cond2['operator'] == '=' and
                        cond1['value'] != cond2['value']):
                        
                        logger.info(f"Mutual exclusion detected: {cond1['raw_condition']} vs {cond2['raw_condition']}")
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking mutual exclusion: {e}")
            return False
    
    def analyze_resource_conflicts(self, sql_resources: Dict) -> List[Dict]:
        """
        Analyze potential resource conflicts between SQL operations
        
        Args:
            sql_resources: Dictionary of SQL resources by node ID
            
        Returns:
            List[Dict]: List of potential conflicts
        """
        conflicts = []
        node_ids = list(sql_resources.keys())
        
        logger.info(f"Analyzing resource conflicts between {len(node_ids)} SQL nodes...")
        
        for i in range(len(node_ids)):
            for j in range(i + 1, len(node_ids)):
                node1_id = node_ids[i]
                node2_id = node_ids[j]
                
                res1 = sql_resources[node1_id]['resources']
                res2 = sql_resources[node2_id]['resources']
                
                # Check for table conflicts
                common_tables = res1['tables'].intersection(res2['tables'])
                
                if common_tables:
                    # Check if operations conflict
                    ops1 = res1['operations']
                    ops2 = res2['operations']
                    
                    # Determine conflict type
                    conflict_type = self._determine_conflict_type(ops1, ops2)
                    
                    if conflict_type:
                        # Check for mutual exclusion
                        is_mutually_exclusive = self.check_mutual_exclusion(res1, res2)
                        
                        conflict = {
                            'node1_id': node1_id,
                            'node2_id': node2_id,
                            'node1_name': sql_resources[node1_id]['name'],
                            'node2_name': sql_resources[node2_id]['name'],
                            'conflict_type': conflict_type,
                            'common_tables': list(common_tables),
                            'operations1': list(ops1),
                            'operations2': list(ops2),
                            'is_mutually_exclusive': is_mutually_exclusive,
                            'severity': 'LOW' if is_mutually_exclusive else 'HIGH'
                        }
                        
                        conflicts.append(conflict)
                        logger.debug(f"Found conflict: {conflict['node1_name']} vs {conflict['node2_name']}")
        
        logger.info(f"Found {len(conflicts)} potential resource conflicts")
        return conflicts
    
    def _determine_conflict_type(self, ops1: Set[str], ops2: Set[str]) -> Optional[str]:
        """
        Determine the type of conflict between two sets of operations
        
        Args:
            ops1: First set of operations
            ops2: Second set of operations
            
        Returns:
            Optional[str]: Conflict type or None if no conflict
        """
        # Write-Write conflict
        if ('UPDATE' in ops1 or 'INSERT' in ops1 or 'DELETE' in ops1) and \
           ('UPDATE' in ops2 or 'INSERT' in ops2 or 'DELETE' in ops2):
            return 'WRITE_WRITE'
        
        # Read-Write conflict
        if ('SELECT' in ops1 and ('UPDATE' in ops2 or 'INSERT' in ops2 or 'DELETE' in ops2)) or \
           ('SELECT' in ops2 and ('UPDATE' in ops1 or 'INSERT' in ops1 or 'DELETE' in ops1)):
            return 'READ_WRITE'
        
        return None