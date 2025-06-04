import re
from typing import Dict, Set, List, Tuple, Optional
from dataclasses import dataclass

@dataclass
class SQLResource:
    """Represents SQL resources extracted from a query"""
    tables: Set[str]
    columns: Set[str]
    operations: Set[str]
    where_conditions: List[Dict]
    raw_sql: str

class SQLResourceExtractor:
    """Enhanced SQL resource extraction with flexible parsing"""
    
    def __init__(self):
        # SQL operation patterns
        self.operation_patterns = {
            'SELECT': r'\bSELECT\b',
            'INSERT': r'\bINSERT\s+INTO\b',
            'UPDATE': r'\bUPDATE\b',
            'DELETE': r'\bDELETE\s+FROM\b',
            'MERGE': r'\bMERGE\b',
            'UPSERT': r'\bUPSERT\b'
        }
        
        # Table extraction patterns
        self.table_patterns = [
            r'\bFROM\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'\bINTO\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'\bUPDATE\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'\bJOIN\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'\bMERGE\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        ]
        
        # Column extraction patterns
        self.column_patterns = [
            r'\bSET\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=',
            r'\bWHERE\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=<>!]',
            r'\bAND\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=<>!]',
            r'\bOR\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[=<>!]',
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*@[a-zA-Z_][a-zA-Z0-9_]*'
        ]
    
    def extract_resources(self, sql_query: str) -> SQLResource:
        """
        Extract SQL resources from query with enhanced parsing
        
        Args:
            sql_query: SQL query string
            
        Returns:
            SQLResource object containing extracted information
        """
        if not sql_query:
            return SQLResource(
                tables=set(),
                columns=set(),
                operations=set(),
                where_conditions=[],
                raw_sql=""
            )
            
        # Clean and normalize SQL
        cleaned_sql = self._clean_sql(sql_query)
        
        # Extract operations
        operations = self._extract_operations(cleaned_sql)
        
        # Extract tables
        tables = self._extract_tables(cleaned_sql)
        
        # Extract columns
        columns = self._extract_columns(cleaned_sql)
        
        # Extract WHERE conditions
        where_conditions = self._extract_where_conditions(cleaned_sql)
        
        return SQLResource(
            tables=tables,
            columns=columns,
            operations=operations,
            where_conditions=where_conditions,
            raw_sql=sql_query
        )
    
    def _clean_sql(self, sql: str) -> str:
        """Clean and normalize SQL query"""
        # Remove HTML encoding if present
        sql = re.sub(r'&#39;', "'", sql)
        sql = re.sub(r'&lt;', "<", sql)
        sql = re.sub(r'&gt;', ">", sql)
        
        # Remove extra whitespace
        sql = re.sub(r'\s+', ' ', sql.strip())
        
        return sql
    
    def _extract_operations(self, sql: str) -> Set[str]:
        """Extract SQL operations from query"""
        operations = set()
        sql_upper = sql.upper()
        
        for operation, pattern in self.operation_patterns.items():
            if re.search(pattern, sql_upper, re.IGNORECASE):
                operations.add(operation)
                
        return operations
    
    def _extract_tables(self, sql: str) -> Set[str]:
        """Extract table names from SQL query"""
        tables = set()
        
        for pattern in self.table_patterns:
            matches = re.findall(pattern, sql, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    tables.add(match[0])
                else:
                    tables.add(match)
                    
        return tables
    
    def _extract_columns(self, sql: str) -> Set[str]:
        """Extract column names from SQL query"""
        columns = set()
        
        for pattern in self.column_patterns:
            matches = re.findall(pattern, sql, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    columns.add(match[0])
                else:
                    columns.add(match)
                    
        return columns
    
    def _extract_where_conditions(self, sql: str) -> List[Dict]:
        """Extract WHERE clause conditions"""
        conditions = []
        
        # Find WHERE clause
        where_match = re.search(r'\bWHERE\s+(.+?)(?:\s+ORDER\s+BY|\s+GROUP\s+BY|\s*$)', 
                               sql, re.IGNORECASE | re.DOTALL)
        
        if not where_match:
            return conditions
            
        where_clause = where_match.group(1).strip()
        
        # Parse individual conditions
        condition_patterns = [
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(=|!=|<>|<|>|<=|>=)\s*([^,\s]+)',
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s+IN\s*\(([^)]+)\)',
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s+LIKE\s+([^,\s]+)'
        ]
        
        for pattern in condition_patterns:
            matches = re.findall(pattern, where_clause, re.IGNORECASE)
            for match in matches:
                if len(match) >= 3:
                    conditions.append({
                        'column': match[0],
                        'operator': match[1],
                        'value': match[2].strip("'\""),
                        'raw_condition': f"{match[0]} {match[1]} {match[2]}"
                    })
                elif len(match) == 2:  # LIKE or IN
                    op = 'LIKE' if 'LIKE' in where_clause.upper() else 'IN'
                    conditions.append({
                        'column': match[0],
                        'operator': op,
                        'value': match[1].strip("'\""),
                        'raw_condition': f"{match[0]} {op} {match[1]}"
                    })
                    
        return conditions
    
    def check_resource_conflict(self, resource1: SQLResource, resource2: SQLResource) -> Dict:
        """
        Check for resource conflicts between two SQL resources
        
        Args:
            resource1: First SQL resource
            resource2: Second SQL resource
            
        Returns:
            Dictionary containing conflict information
        """
        # Check table overlap
        table_overlap = resource1.tables.intersection(resource2.tables)
        
        # Check column overlap
        column_overlap = resource1.columns.intersection(resource2.columns)
        
        # Check operation conflicts
        write_ops = {'INSERT', 'UPDATE', 'DELETE', 'MERGE', 'UPSERT'}
        ops1_write = resource1.operations.intersection(write_ops)
        ops2_write = resource2.operations.intersection(write_ops)
        
        has_write_write = bool(ops1_write and ops2_write)
        has_write_read = bool(
            (ops1_write and 'SELECT' in resource2.operations) or
            ('SELECT' in resource1.operations and ops2_write)
        )
        
        # Check mutual exclusion
        is_mutually_exclusive = self._check_mutual_exclusion(resource1, resource2)
        
        return {
            'table_conflicts': table_overlap,
            'column_conflicts': column_overlap,
            'write_write_conflict': has_write_write,
            'write_read_conflict': has_write_read,
            'mutually_exclusive': is_mutually_exclusive,
            'has_resource_overlap': bool(table_overlap or column_overlap),
            'has_operation_conflict': bool(has_write_write or has_write_read),
            'conflict_score': self._calculate_conflict_score(
                table_overlap, column_overlap, has_write_write, has_write_read
            )
        }
    
    def _check_mutual_exclusion(self, resource1: SQLResource, resource2: SQLResource) -> bool:
        """Check if two resources have mutually exclusive conditions"""
        try:
            for cond1 in resource1.where_conditions:
                for cond2 in resource2.where_conditions:
                    if (cond1['column'] == cond2['column'] and 
                        cond1['operator'] == '=' and cond2['operator'] == '=' and
                        cond1['value'] != cond2['value']):
                        
                        # Special cases where conditions might not be mutually exclusive
                        column_name = cond1['column'].upper()
                        if column_name in ['ORDERTYPE', 'STATUS', 'CATEGORY']:
                            # These might be processed concurrently
                            continue
                            
                        return True
                        
            return False
            
        except Exception:
            return False
    
    def _calculate_conflict_score(self, table_overlap: Set, column_overlap: Set, 
                                write_write: bool, write_read: bool) -> float:
        """Calculate a conflict score (0.0 - 1.0)"""
        score = 0.0
        
        if table_overlap:
            score += 0.4
        if column_overlap:
            score += 0.2
        if write_write:
            score += 0.3
        if write_read:
            score += 0.1
            
        return min(1.0, score)
