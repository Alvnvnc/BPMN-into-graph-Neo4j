# BPMN SQL Deadlock Detector

Advanced deadlock detection system for BPMN processes stored in Neo4j using graph theory algorithms.

## Features

### 🔍 **Comprehensive Deadlock Detection**
- **Structural Deadlocks**: Gateway combination analysis (AND/OR/XOR splits and joins)
- **SQL Resource Deadlocks**: Database resource conflict detection using Tarjan's algorithm
- **Automated Analysis**: No hardcoded patterns - fully dynamic graph analysis

### 🧮 **Advanced Algorithms**
- **Tarjan's Strongly Connected Components**: Detects circular dependencies in resource access
- **Topological Sorting**: Analyzes execution flow dependencies
- **Graph Traversal**: Identifies parallel execution paths and resource conflicts
- **SQL Parsing**: Automated extraction of database resources from SQL queries

### 📊 **Analysis Methods**
1. **Structural Analysis**: Gateway combination pattern matching
2. **SQL Analysis**: Tarjan's strongly connected components algorithm
3. **Resource Extraction**: Automated SQL parsing and resource identification
4. **Topology Analysis**: Graph traversal and dependency mapping

## Installation

### Prerequisites
```bash
pip install neo4j networkx sqlparse
```

### Required Dependencies
- `neo4j`: Neo4j Python driver
- `networkx`: Graph analysis library
- `sqlparse`: SQL parsing library
- `logging`: Built-in Python logging

## Configuration

### Neo4j Setup
Update the configuration in `sql_deadlock.py`:

```python
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "your_password"
```

## Usage

### Basic Usage
```python
from sql_deadlock import SQLDeadlockDetector

# Initialize detector
detector = SQLDeadlockDetector(
    neo4j_uri="bolt://localhost:7687",
    neo4j_user="neo4j",
    neo4j_password="password"
)

try:
    # Generate comprehensive report
    report = detector.generate_report()
    
    # Access different types of deadlocks
    structural_deadlocks = report['structural_deadlocks']
    sql_deadlocks = report['sql_resource_deadlocks']
    
finally:
    detector.close()
```

### Command Line Usage
```bash
python sql_deadlock.py
```

## Deadlock Types Detected

### 1. Structural Deadlocks
Problematic gateway combinations that cause process flow deadlocks:

| Split Type | Join Type | Status | Description |
|------------|-----------|--------|--------------|
| AND_SPLIT | OR_JOIN | ❌ CRITICAL | All paths activated, but join continues after first arrival |
| AND_SPLIT | XOR_JOIN | ❌ CRITICAL | All paths activated, but join accepts only one token |
| OR_SPLIT | AND_JOIN | ❌ CRITICAL | May not activate all paths, but join waits for all |
| XOR_SPLIT | AND_JOIN | ❌ CRITICAL | Only one path activated, but join waits for all |
| OR_SPLIT | XOR_JOIN | ⚠️ MEDIUM | Multiple paths may activate, but join accepts first only |
| AND_SPLIT | AND_JOIN | ✅ SAFE | All paths activated and join waits for all |
| XOR_SPLIT | XOR_JOIN | ✅ SAFE | One path activated and join continues after completion |
| OR_SPLIT | OR_JOIN | ✅ SAFE | Paths activated and join continues when active paths complete |

### 2. SQL Resource Deadlocks
Database resource conflicts detected through:
- **Table Access Conflicts**: Multiple tasks accessing same tables
- **Operation Conflicts**: Read-write and write-write conflicts
- **Circular Dependencies**: Tasks waiting for each other's resources

## Algorithm Details

### Tarjan's Strongly Connected Components
```python
def tarjan_scc(self) -> List[List[str]]:
    """Find strongly connected components indicating circular dependencies"""
    # Implementation uses depth-first search with low-link values
    # to identify cycles in the wait-for graph
```

### Resource Conflict Detection
```python
def _check_resource_conflicts(self, path1: List[str], path2: List[str]) -> Dict:
    """Analyze resource conflicts between parallel execution paths"""
    # Checks for:
    # - Table overlaps
    # - Column conflicts  
    # - Operation type conflicts (read-write, write-write)
```

### Gateway Analysis
```python
def _find_split_join_pairs(self) -> List[Dict]:
    """Identify all split-join gateway pairs for structural analysis"""
    # Traverses graph to find gateway combinations
    # Analyzes paths between splits and joins
```

## Output Format

### Report Structure
```json
{
  "summary": {
    "total_nodes_analyzed": 45,
    "total_sql_nodes": 12,
    "total_deadlocks": 3,
    "structural_deadlocks": 2,
    "sql_resource_deadlocks": 1,
    "severity_breakdown": {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 1, "LOW": 0}
  },
  "structural_deadlocks": [...],
  "sql_resource_deadlocks": [...],
  "graph_statistics": {...},
  "analysis_methods": {...}
}
```

### Deadlock Information
Each deadlock includes:
- **Type**: Structural Deadlock / SQL Resource Deadlock / Potential Race Condition
- **Severity**: CRITICAL / HIGH / MEDIUM / LOW
- **Description**: Detailed explanation of the deadlock scenario
- **Recommendation**: Specific steps to resolve the deadlock
- **Involved Components**: Nodes, gateways, tables, operations

## Example Output

```
================================================================================
    COMPREHENSIVE BPMN DEADLOCK DETECTION REPORT
    Using Tarjan's Algorithm + Structural Analysis
================================================================================

📊 ANALYSIS SUMMARY:
   • Total Nodes Analyzed: 45
   • SQL-Enabled Nodes: 12
   • Total Deadlocks Found: 3
   • Structural Deadlocks: 2
   • SQL Resource Deadlocks: 1
   • Severity Breakdown: {'CRITICAL': 2, 'MEDIUM': 1}

🚨 STRUCTURAL DEADLOCKS (2)
------------------------------------------------------------

[1] Structural Deadlock - CRITICAL
    Split Gateway: Process Orders (AND_SPLIT)
    Join Gateway: Complete Processing (XOR_JOIN)
    Description: Structural deadlock: AND-split activates all paths, but XOR-join only accepts one token
    Recommendation: Replace XOR-join with AND-join to accept all parallel tokens

💾 SQL RESOURCE DEADLOCKS (1)
------------------------------------------------------------

[1] SQL Resource Deadlock - HIGH
    Nodes: Update Inventory, Process Payment
    Tables: Orders, Inventory
    Operations: UPDATE, SELECT
    Description: Circular dependency detected among 2 SQL tasks involving tables: Orders, Inventory
    Recommendation: Implement consistent resource ordering; Use explicit locking with UPDLOCK hints
```

## Advanced Features

### Custom Analysis
```python
# Detect only structural deadlocks
structural_deadlocks = detector.detect_structural_deadlocks()

# Build custom resource dependency graph
detector.build_resource_dependency_graph()
resource_conflicts = detector.sql_resources

# Access wait-for graph for custom analysis
wait_for_graph = detector.wait_for_graph
```

### Severity Calculation
Severity is calculated based on:
- Number of nodes in deadlock cycle
- Type of SQL operations (write operations increase severity)
- Number of resource conflicts
- Table vs column level conflicts

## Troubleshooting

### Common Issues
1. **Neo4j Connection Error**: Verify Neo4j is running and credentials are correct
2. **No SQL Nodes Found**: Ensure BPMN tasks have 'SQL' properties in Neo4j
3. **Empty Graph Data**: Check if BPMN data is properly loaded in Neo4j

### Debugging
Enable detailed logging:
```python
import logging
logging.basicConfig(level=logging.INFO)
```

## Integration with Existing Systems

### With BPMN Converter
```python
# After converting BPMN to Neo4j
from converter import BPMNConverter
from sql_deadlock import SQLDeadlockDetector

# Convert BPMN
converter = BPMNConverter()
converter.convert_bpmn_to_neo4j("process.bpmn")

# Analyze deadlocks
detector = SQLDeadlockDetector(neo4j_uri, neo4j_user, neo4j_password)
report = detector.generate_report()
```

### API Integration
```python
class DeadlockAnalysisAPI:
    def analyze_process(self, process_id: str) -> Dict:
        detector = SQLDeadlockDetector(uri, user, password)
        try:
            return detector.generate_report()
        finally:
            detector.close()
```

## Performance Considerations

- **Graph Size**: Algorithm complexity is O(V + E) for Tarjan's SCC
- **Memory Usage**: Proportional to graph size and number of SQL queries
- **Neo4j Queries**: Optimized to fetch all data in minimal queries
- **Caching**: Graph data is cached for multiple analysis runs

## Contributing

To extend the deadlock detector:

1. **Add New Deadlock Types**: Extend detection methods
2. **Improve SQL Parsing**: Enhance resource extraction
3. **Custom Severity Calculation**: Modify severity scoring
4. **Additional Graph Algorithms**: Implement new analysis methods

## License

This project is part of the BPMN-into-graph-Neo4j system for academic and research purposes.