import logging
import re
from typing import Dict, List, Set, Tuple, Any
from neo4j import GraphDatabase

logger = logging.getLogger(__name__)

class SQLDeadlockAnalyzer:
    """
    Specialized analyzer for detecting SQL deadlocks in BPMN processes.
    This analyzer focuses on finding conflicting SQL access patterns between
    activities that can run concurrently from the same gateway.
    """
    
    def __init__(self, uri: str, user: str, password: str):
        """Initialize SQL deadlock analyzer with Neo4j connection details."""
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        # Check for property existence - initialize to False
        self.has_sql_property = False
        self._check_property_existence()
    
    def _check_property_existence(self):
        """Check if the SQL property exists in the database."""
        with self.driver.session() as session:
            # Try to find any activity with SQL property
            result = session.run("""
                MATCH (a:Activity) 
                WHERE exists(a.SQL) 
                RETURN count(a) AS count
            """)
            record = result.single()
            if record and record["count"] > 0:
                self.has_sql_property = True
                logger.info("SQL property exists in the database")
            else:
                logger.warning("SQL property not found in the database - SQL deadlock detection will be limited")
    
    def close(self):
        """Close the Neo4j driver."""
        self.driver.close()
    
    def analyze(self, report_file: str) -> List[Dict]:
        """
        Legacy method for backward compatibility.
        
        Args:
            report_file: Path to save the report
        
        Returns:
            List of detected SQL deadlocks
        """
        # Call the enhanced analysis method
        return self.analyze_from_gateways(report_file)
    
    def analyze_from_gateways(self, report_file: str) -> List[Dict]:
        """
        Enhanced analysis that detects SQL deadlocks by examining activities originating 
        from the same gateway that might run concurrently.
        
        Args:
            report_file: Path to save the report
        
        Returns:
            List of detected SQL deadlocks
        """
        logger.info("Analyzing SQL deadlocks from gateways...")
        
        # List to store found deadlocks
        deadlocks = []
        
        # If SQL property doesn't exist, we can't do much
        if not self.has_sql_property:
            logger.warning("SQL property not found in database. SQL deadlock detection skipped.")
            with open(report_file, 'w') as f:
                f.write("=== SQL DEADLOCK DETECTION REPORT ===\n\n")
                f.write("No SQL deadlocks detected. SQL property not found in the database.\n")
                f.write("To enable SQL deadlock detection, ensure activities have SQL properties.\n")
            return deadlocks
        
        with self.driver.session() as session:
            # Find activities from parallel gateways that might cause SQL deadlocks
            deadlocks.extend(self._find_deadlocks_from_parallel_gateways(session))
            
            # Find activities from inclusive gateways that might cause SQL deadlocks
            deadlocks.extend(self._find_deadlocks_from_inclusive_gateways(session))
            
            # Find activities across parallel sequences that might cause SQL deadlocks
            deadlocks.extend(self._find_deadlocks_across_parallel_sequences(session))
        
        # Write report
        with open(report_file, 'w') as f:
            f.write("=== SQL DEADLOCK DETECTION REPORT ===\n\n")
            
            if not deadlocks:
                f.write("No SQL deadlocks detected.\n")
            else:
                f.write(f"Found {len(deadlocks)} potential SQL deadlocks:\n\n")
                
                for i, deadlock in enumerate(deadlocks, 1):
                    f.write(f"Deadlock #{i}:\n")
                    f.write(f"  Gateway: {deadlock['gateway_name']} (ID: {deadlock['gateway_id']})\n")
                    f.write(f"  Type: {deadlock['type']}\n")
                    f.write(f"  Task 1: {deadlock['task1_name']} (ID: {deadlock['task1_id']})\n")
                    f.write(f"  Task 2: {deadlock['task2_name']} (ID: {deadlock['task2_id']})\n")
                    f.write(f"  Shared Resources: {', '.join(deadlock['resources'])}\n")
                    f.write(f"  Access Pattern 1: {deadlock['access_pattern1']}\n")
                    f.write(f"  Access Pattern 2: {deadlock['access_pattern2']}\n")
                    f.write(f"  Description: {deadlock['description']}\n\n")
        
        return deadlocks
    
    def _find_deadlocks_from_parallel_gateways(self, session) -> List[Dict]:
        """
        Find potential SQL deadlocks between activities that originate from parallel gateways.
        These activities can execute truly concurrently, presenting highest deadlock risk.
        """
        logger.info("Analyzing activities from parallel gateways...")
        deadlocks = []
        
        # Get activities from parallel gateways using the proper property name (SQL instead of sql)
        result = session.run("""
            MATCH (g:Gateway {type: 'parallel'})-[p1:FLOW*]->(a1:Activity),
                  (g)-[p2:FLOW*]->(a2:Activity)
            WHERE a1.id <> a2.id
                  AND all(r1 in p1 WHERE type(r1) = 'FLOW')
                  AND all(r2 in p2 WHERE type(r2) = 'FLOW')
                  AND exists(a1.SQL)
                  AND exists(a2.SQL)
            RETURN g.id AS gateway_id, g.name AS gateway_name,
                   a1.id AS task1_id, a1.name AS task1_name, a1.SQL AS sql1,
                   a2.id AS task2_id, a2.name AS task2_name, a2.SQL AS sql2
        """)
        
        for record in result:
            # Check for SQL deadlocks between these activities
            deadlock = self._check_sql_deadlock(
                record['gateway_id'], record['gateway_name'],
                record['task1_id'], record['task1_name'], record['sql1'], None,
                record['task2_id'], record['task2_name'], record['sql2'], None,
                "Parallel Gateway"
            )
            
            if deadlock:
                deadlocks.append(deadlock)
        
        return deadlocks
    
    def _find_deadlocks_from_inclusive_gateways(self, session) -> List[Dict]:
        """
        Find potential SQL deadlocks between activities that originate from inclusive gateways.
        These activities can sometimes execute concurrently, presenting moderate deadlock risk.
        """
        logger.info("Analyzing activities from inclusive gateways...")
        deadlocks = []
        
        # Get activities from inclusive gateways using the proper property name (SQL instead of sql)
        result = session.run("""
            MATCH (g:Gateway {type: 'inclusive'})-[p1:FLOW*]->(a1:Activity),
                  (g)-[p2:FLOW*]->(a2:Activity)
            WHERE a1.id <> a2.id
                  AND all(r1 in p1 WHERE type(r1) = 'FLOW')
                  AND all(r2 in p2 WHERE type(r2) = 'FLOW')
                  AND exists(a1.SQL)
                  AND exists(a2.SQL)
            RETURN g.id AS gateway_id, g.name AS gateway_name,
                   a1.id AS task1_id, a1.name AS task1_name, a1.SQL AS sql1,
                   a2.id AS task2_id, a2.name AS task2_name, a2.SQL AS sql2
        """)
        
        for record in result:
            # Check for SQL deadlocks between these activities
            deadlock = self._check_sql_deadlock(
                record['gateway_id'], record['gateway_name'],
                record['task1_id'], record['task1_name'], record['sql1'], None,
                record['task2_id'], record['task2_name'], record['sql2'], None,
                "Inclusive Gateway"
            )
            
            if deadlock:
                deadlocks.append(deadlock)
        
        return deadlocks
    
    def _find_deadlocks_across_parallel_sequences(self, session) -> List[Dict]:
        """
        Find potential SQL deadlocks between activities in different parallel sequences.
        This detects deadlocks across different parts of the process that can run in parallel.
        """
        logger.info("Analyzing activities across parallel process segments...")
        deadlocks = []
        
        # Get parallel sequences that might run concurrently - using exists() for property checks
        result = session.run("""
            MATCH (a1:Activity), (a2:Activity)
            WHERE a1.id <> a2.id
                AND exists(a1.SQL)
                AND exists(a2.SQL)
                AND NOT (a1)-[:FLOW*]->(a2)
                AND NOT (a2)-[:FLOW*]->(a1)
            RETURN a1.id AS task1_id, a1.name AS task1_name, a1.SQL AS sql1,
                   a2.id AS task2_id, a2.name AS task2_name, a2.SQL AS sql2
        """)
        
        for record in result:
            # Check for SQL deadlocks between these activities
            deadlock = self._check_sql_deadlock(
                "process", "Process-wide",
                record['task1_id'], record['task1_name'], record['sql1'], None,
                record['task2_id'], record['task2_name'], record['sql2'], None,
                "Parallel Process Segments"
            )
            
            if deadlock:
                deadlocks.append(deadlock)
        
        return deadlocks
    
    def _check_sql_deadlock(self, gateway_id: str, gateway_name: str,
                           task1_id: str, task1_name: str, sql1: str, script1: str,
                           task2_id: str, task2_name: str, sql2: str, script2: str,
                           deadlock_type: str) -> Dict:
        """
        Check if two activities with SQL operations can cause a deadlock.
        
        This focuses on detecting the classic deadlock pattern where:
        - Task1: Locks resource A, then tries to lock resource B
        - Task2: Locks resource B, then tries to lock resource A
        
        Args:
            gateway_id: ID of the gateway from which activities originate
            gateway_name: Name of the gateway
            task1_id, task1_name, sql1, script1: Details of first task
            task2_id, task2_name, sql2, script2: Details of second task
            deadlock_type: Type of deadlock to report
            
        Returns:
            Dictionary with deadlock details if found, None otherwise
        """
        # Extract SQL statements and transactions from both activities
        sql_statements1 = self._extract_sql_statements(sql1, script1)
        sql_statements2 = self._extract_sql_statements(sql2, script2)
        
        # Extract tables and their access order from SQL statements
        tables1, access_order1 = self._extract_table_access_patterns(sql_statements1)
        tables2, access_order2 = self._extract_table_access_patterns(sql_statements2)
        
        # Find shared resources (tables)
        shared_tables = set(tables1.keys()) & set(tables2.keys())
        
        # Not enough shared resources for deadlock
        if len(shared_tables) < 2:
            return None
        
        # Check for conflicting access patterns
        conflicting_tables = []
        for table_a in shared_tables:
            for table_b in shared_tables:
                if table_a == table_b:
                    continue
                
                # Check if tables are accessed in opposite orders - classic deadlock pattern
                order_a_b_in_1 = self._check_access_order(access_order1, table_a, table_b)
                order_b_a_in_2 = self._check_access_order(access_order2, table_b, table_a)
                
                if order_a_b_in_1 and order_b_a_in_2:
                    conflicting_tables.append((table_a, table_b))
                    
        if conflicting_tables:
            # Create deadlock report
            conflict = conflicting_tables[0]  # Use first conflict found
            
            # Detailed description of the conflicting access pattern
            access_pattern1 = f"{conflict[0]} → {conflict[1]}"
            access_pattern2 = f"{conflict[1]} → {conflict[0]}"
            
            # Analyze lock types for more detailed information
            lock_type1_a = tables1[conflict[0]]
            lock_type1_b = tables1[conflict[1]]
            lock_type2_a = tables2[conflict[0]]
            lock_type2_b = tables2[conflict[1]]
            
            # Create a description based on the example in catatan.txt
            description = (
                f"Deadlock risk detected between tasks '{task1_name}' and '{task2_name}' "
                f"from {gateway_name}. Task '{task1_name}' accesses {conflict[0]} "
                f"({lock_type1_a}) then {conflict[1]} ({lock_type1_b}), while "
                f"Task '{task2_name}' accesses {conflict[1]} ({lock_type2_b}) "
                f"then {conflict[0]} ({lock_type2_a}). This is the classic "
                f"deadlock pattern where tasks wait for resources held by each other."
            )
            
            return {
                'gateway_id': gateway_id,
                'gateway_name': gateway_name,
                'task1_id': task1_id,
                'task1_name': task1_name,
                'task2_id': task2_id,
                'task2_name': task2_name,
                'type': deadlock_type,
                'resources': list(shared_tables),
                'conflicting_pairs': conflicting_tables,
                'access_pattern1': access_pattern1,
                'access_pattern2': access_pattern2,
                'description': description
            }
            
        return None
    
    def _extract_sql_statements(self, sql: str, script: str) -> List[str]:
        """
        Extract SQL statements from SQL content and script content.
        
        Args:
            sql: Direct SQL content
            script: Script content that might contain SQL
            
        Returns:
            List of SQL statements
        """
        statements = []
        
        # Process direct SQL content if available
        if sql:
            statements.extend(self._parse_sql_content(sql))
        
        # Process script content if available - but likely will be None since property doesn't exist
        if script:
            # Look for SQL transaction blocks in script
            sql_blocks = re.findall(
                r'(?:BEGIN\s+TRANSACTION|BEGIN\s+TRAN|UPDATE|INSERT|DELETE|SELECT).*?(?:COMMIT|ROLLBACK|;)',
                script, 
                re.DOTALL | re.IGNORECASE
            )
            
            for block in sql_blocks:
                statements.extend(self._parse_sql_content(block))
        
        return statements
    
    def _parse_sql_content(self, content: str) -> List[str]:
        """
        Parse SQL content into individual statements.
        
        Args:
            content: SQL content string
            
        Returns:
            List of SQL statements
        """
        if not content:
            return []
        
        # Split by semicolons but handle quoted strings properly
        statements = []
        current_statement = []
        in_quote = False
        quote_char = None
        
        for char in content:
            if char in ['"', "'"]:
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif quote_char == char:
                    in_quote = False
                    quote_char = None
            
            if char == ';' and not in_quote:
                current_statement.append(char)
                statements.append(''.join(current_statement).strip())
                current_statement = []
            else:
                current_statement.append(char)
        
        # Add the last statement if it doesn't end with a semicolon
        if current_statement:
            statements.append(''.join(current_statement).strip())
        
        return [stmt for stmt in statements if stmt.strip()]
    
    def _extract_table_access_patterns(self, statements: List[str]) -> Tuple[Dict[str, str], List[str]]:
        """
        Extract tables and their access patterns from SQL statements.
        
        Args:
            statements: List of SQL statements
            
        Returns:
            Tuple containing:
              - Dictionary mapping table names to operation types
              - List of tables in the order they are accessed
        """
        tables = {}  # {table_name: operation_type}
        access_order = []  # List of tables in order of access
        
        for statement in statements:
            stmt_upper = statement.upper()
            
            # Check for different SQL operations and their table targets
            
            # UPDATE operations
            update_matches = re.findall(r'UPDATE\s+([A-Za-z0-9_]+)', stmt_upper)
            for table in update_matches:
                table_name = table.lower()
                if table_name not in tables:
                    tables[table_name] = 'UPDATE'
                access_order.append(table_name)
            
            # INSERT operations
            insert_matches = re.findall(r'INSERT\s+INTO\s+([A-Za-z0-9_]+)', stmt_upper)
            for table in insert_matches:
                table_name = table.lower()
                if table_name not in tables:
                    tables[table_name] = 'INSERT'
                access_order.append(table_name)
            
            # DELETE operations
            delete_matches = re.findall(r'DELETE\s+FROM\s+([A-Za-z0-9_]+)', stmt_upper)
            for table in delete_matches:
                table_name = table.lower()
                if table_name not in tables:
                    tables[table_name] = 'DELETE'
                access_order.append(table_name)
            
            # SELECT operations (incl. joins)
            select_patterns = [
                r'FROM\s+([A-Za-z0-9_]+)',
                r'JOIN\s+([A-Za-z0-9_]+)'
            ]
            
            for pattern in select_patterns:
                matches = re.findall(pattern, stmt_upper)
                for table in matches:
                    table_name = table.lower()
                    # Only set if not already set (writes take precedence over reads)
                    if table_name not in tables:
                        tables[table_name] = 'SELECT'
                    access_order.append(table_name)
        
        return tables, access_order
    
    def _check_access_order(self, access_order: List[str], table_a: str, table_b: str) -> bool:
        """
        Check if table_a is accessed before table_b in the given access order.
        
        Args:
            access_order: List of tables in order of access
            table_a: First table
            table_b: Second table
            
        Returns:
            True if table_a is accessed before table_b, False otherwise
        """
        # Find indices of first occurrence of each table
        try:
            idx_a = access_order.index(table_a)
            idx_b = access_order.index(table_b)
            return idx_a < idx_b
        except ValueError:
            # One or both tables not found
            return False
