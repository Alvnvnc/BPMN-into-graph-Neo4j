# XPDL to Neo4j Converter

This tool converts XPDL (XML Process Definition Language) files, typically exported from Bizagi Modeler, 
to Neo4j graph databases. This enables advanced analysis of business processes, including detection of 
potential deadlocks.

## Features

- Import XPDL files from Bizagi Modeler into Neo4j
- Handle complex gateway patterns (AND, OR, XOR)
- Detect potential deadlocks in business processes
- Generate semantic relationships between activities
- Provide example Cypher queries for business process analysis

## Installation

1. Clone the repository:
   ```
   https://github.com/Alvnvnc/BPMN-into-graph-Neo4j
   cd xpdl-to-neo4j
   ```

2. Install required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Prerequisites

1. **Python 3.7+**
   - Ensure Python 3.7 or newer is installed on your system
   
2. **Neo4j Database**
   - Install [Neo4j Desktop](https://neo4j.com/download/) or use Neo4j Aura cloud service
   - Create a new database with password authentication

3. **Bizagi Modeler**
   - Required only if you need to create or modify XPDL files
   - Export your process models as XPDL files

## Configuration

Before using the tool, you need to configure your database connection and other settings:

1. Create a copy of `src/config.example.py` as `src/config.py`
   ```
   cp src/config.example.py src/config.py
   ```

2. Edit `src/config.py` with your specific settings:
   ```python
   # Neo4j Database Configuration
   NEO4J_URI = "bolt://localhost:7687"  # Change to your Neo4j instance URI
   NEO4J_USER = "neo4j"                 # Your Neo4j username
   NEO4J_PASSWORD = "password"          # Your Neo4j password

   # XPDL Processing Settings
   DEFAULT_XPDL_DIRECTORY = "data/xpdl"  # Directory containing XPDL files
   
   # Analysis Configuration
   DEADLOCK_DETECTION_LEVEL = "advanced"  # basic, standard, or advanced
   ```

3. Note: `src/config.py` is ignored by git to protect your credentials

## Usage

1. Place your XPDL files in the configured directory

2. Run the converter:
   ```
   python src/main.py
   ```

3. To detect deadlocks in the imported processes:
   ```
   python src/detect_deadlocks.py
   ```

## Example Queries

After importing your BPMN processes, you can analyze them using Cypher queries:

```cypher
// Find all potential deadlock patterns
MATCH path = (start:Activity)-[:LEADS_TO*]->(gateway1:Gateway)-[:LEADS_TO*]->(gateway2:Gateway)-[:LEADS_TO*]->(start)
WHERE gateway1.type = 'AND' AND gateway2.type = 'AND'
RETURN path
```

## Troubleshooting

- **Connection Issues**: Ensure your Neo4j database is running and accessible
- **Import Failures**: Check that your XPDL files follow the expected format
- **Missing Configuration**: Verify your `src/config.py` file exists and has correct settings

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
