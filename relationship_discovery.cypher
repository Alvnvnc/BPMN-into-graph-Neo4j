// Complete Relationship Discovery and Analysis

// 1. Basic Relationship Type Discovery
CALL db.relationshipTypes() YIELD relationshipType
RETURN relationshipType 
ORDER BY relationshipType;

// 2. Relationship Count and Distribution
CALL db.relationshipTypes() YIELD relationshipType
MATCH ()-[r]->() WHERE TYPE(r) = relationshipType
WITH relationshipType, COUNT(r) AS count
RETURN relationshipType, count
ORDER BY count DESC;

// 3. Detailed Relationship Analysis
CALL db.relationshipTypes() YIELD relationshipType
MATCH (start)-[r]->(end) WHERE TYPE(r) = relationshipType
WITH relationshipType, 
     COUNT(r) AS relationship_count,
     COLLECT(DISTINCT LABELS(start))[0..5] AS start_node_labels,
     COLLECT(DISTINCT LABELS(end))[0..5] AS end_node_labels,
     COUNT(DISTINCT start) AS unique_start_nodes,
     COUNT(DISTINCT end) AS unique_end_nodes
RETURN relationshipType, 
       relationship_count,
       start_node_labels,
       end_node_labels,
       unique_start_nodes,
       unique_end_nodes
ORDER BY relationship_count DESC;

// 4. Relationship Property Analysis
CALL db.relationshipTypes() YIELD relationshipType
MATCH ()-[r]->() WHERE TYPE(r) = relationshipType
WITH relationshipType, r, KEYS(r) AS property_keys
UNWIND property_keys AS property_key
WITH relationshipType, property_key, COUNT(*) AS property_occurrence
RETURN relationshipType, 
       COLLECT({key: property_key, count: property_occurrence}) AS properties,
       SIZE(COLLECT(DISTINCT property_key)) AS unique_property_count
ORDER BY unique_property_count DESC;

// 5. Relationship Examples
CALL db.relationshipTypes() YIELD relationshipType
MATCH (start)-[r]->(end) WHERE TYPE(r) = relationshipType
WITH relationshipType, start, r, end
LIMIT 5
RETURN relationshipType,
       start.name AS from_node,
       LABELS(start) AS from_labels,
       end.name AS to_node,
       LABELS(end) AS to_labels,
       PROPERTIES(r) AS relationship_properties;

// 6. Gateway-specific Relationship Analysis
MATCH (g:Gateway)-[r]->()
WITH TYPE(r) AS relationship_type, COUNT(r) AS count, COLLECT(DISTINCT g.name)[0..5] AS gateway_samples
RETURN relationship_type, count, gateway_samples
ORDER BY count DESC;

// 7. Network Analysis: Relationship Path Patterns
MATCH path = ()-[r1]->()-[r2]->()
WHERE TYPE(r1) < TYPE(r2)  // Avoid duplicating reversed paths
WITH TYPE(r1) + '->' + TYPE(r2) AS path_pattern, COUNT(*) AS frequency
RETURN path_pattern, frequency
ORDER BY frequency DESC
LIMIT 20;
