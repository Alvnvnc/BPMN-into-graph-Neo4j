MATCH (splitNode)-[outRel]->(nextNode)
WHERE type(outRel) CONTAINS "_SPLIT" AND NOT splitNode.name = "Start"
WITH splitNode, count(outRel) AS outgoingFlows

MATCH path = (splitNode)-[firstRel]->(midNode)-[*0..13]->(endNode)-[lastRel]->(joinNode)
WHERE 
  type(firstRel) CONTAINS "_SPLIT" AND
  type(lastRel) CONTAINS "_JOIN" AND
  joinNode.name <> "End" AND
  size([r IN relationships(path)[1..-1] WHERE type(r) CONTAINS "_SPLIT"]) = size([r IN relationships(path)[1..-1] WHERE type(r) CONTAINS "_JOIN"]) AND
  NONE(n IN nodes(path) WHERE n.name CONTAINS "Gateway Connection:" OR n.name = "Start" OR n.name = "End")

// First pass to identify split and join relationships and their types
WITH 
  splitNode,
  joinNode,
  path,
  firstRel,
  lastRel,
  CASE 
    WHEN type(firstRel) CONTAINS "XOR_SPLIT" THEN "XOR_SPLIT"
    WHEN type(firstRel) CONTAINS "OR_SPLIT" THEN "OR_SPLIT"
    WHEN type(firstRel) CONTAINS "AND_SPLIT" THEN "AND_SPLIT"
    ELSE type(firstRel)
  END AS actualSplitType,
  CASE 
    WHEN type(lastRel) CONTAINS "XOR_JOIN" THEN "XOR_JOIN"
    WHEN type(lastRel) CONTAINS "OR_JOIN" THEN "OR_JOIN"
    WHEN type(lastRel) CONTAINS "AND_JOIN" THEN "AND_JOIN"
    ELSE type(lastRel)
  END AS actualJoinType,
  outgoingFlows,
  relationships(path) AS allRels

// Create deadlock type and message based on actual gateway types
WITH 
  splitNode,
  joinNode,
  path,
  firstRel,
  lastRel,
  actualSplitType,
  actualJoinType,
  outgoingFlows,
  allRels,
  CASE
    // Problematic combinations (structural deadlocks)
    WHEN actualSplitType = "AND_SPLIT" AND actualJoinType = "OR_JOIN" 
      THEN "AND-split to OR-join"
    WHEN actualSplitType = "AND_SPLIT" AND actualJoinType = "XOR_JOIN" 
      THEN "AND-split to XOR-join"
    WHEN actualSplitType = "OR_SPLIT" AND actualJoinType = "AND_JOIN" 
      THEN "OR-split to AND-join"
    WHEN actualSplitType = "XOR_SPLIT" AND actualJoinType = "AND_JOIN" 
      THEN "XOR-split to AND-join"
      
    // Safe combinations
    WHEN actualSplitType = "AND_SPLIT" AND actualJoinType = "AND_JOIN" 
      THEN "AND-split to AND-join (Safe)"
    WHEN actualSplitType = "XOR_SPLIT" AND actualJoinType = "XOR_JOIN" 
      THEN "XOR-split to XOR-join (Safe)"
    WHEN actualSplitType = "OR_SPLIT" AND actualJoinType = "OR_JOIN" 
      THEN "OR-split to OR-join (Safe)"
    WHEN actualSplitType = "XOR_SPLIT" AND actualJoinType = "OR_JOIN" 
      THEN "XOR-split to OR-join (Safe)"
    
    // Potential issues but not structural deadlocks
    WHEN actualSplitType = "OR_SPLIT" AND actualJoinType = "XOR_JOIN" 
      THEN "OR-split to XOR-join (Potential race condition)"
    
    // Default case for any unexpected combinations
    ELSE "Unknown combination: " + actualSplitType + " to " + actualJoinType
  END AS deadlockType

WHERE deadlockType <> "Safe combination"

// Create detailed description and mark relationship
WITH 
  splitNode,
  joinNode,
  path,
  firstRel,
  lastRel,
  actualSplitType,
  actualJoinType,
  outgoingFlows,
  allRels,
  deadlockType,
  CASE
    // Problematic combinations (structural deadlocks)
    WHEN actualSplitType = "AND_SPLIT" AND actualJoinType = "OR_JOIN" 
      THEN "Structural deadlock: " + splitNode.name + " (AND-split) activates all paths, but " + joinNode.name + " (OR-join) continues after first arrival, leaving active paths abandoned"
    WHEN actualSplitType = "AND_SPLIT" AND actualJoinType = "XOR_JOIN" 
      THEN "Structural deadlock: " + splitNode.name + " (AND-split) activates all paths, but " + joinNode.name + " (XOR-join) only accepts one token and blocks others"
    WHEN actualSplitType = "OR_SPLIT" AND actualJoinType = "AND_JOIN" 
      THEN "Structural deadlock: " + splitNode.name + " (OR-split) may not activate all paths, but " + joinNode.name + " (AND-join) requires all paths to be active"
    WHEN actualSplitType = "XOR_SPLIT" AND actualJoinType = "AND_JOIN" 
      THEN "Structural deadlock: " + splitNode.name + " (XOR-split) activates only one path, but " + joinNode.name + " (AND-join) waits for all paths indefinitely"
      
    // Safe combinations with explanations
    WHEN actualSplitType = "AND_SPLIT" AND actualJoinType = "AND_JOIN" 
      THEN "Safe combination: " + splitNode.name + " (AND-split) activates all paths and " + joinNode.name + " (AND-join) waits for all paths"
    WHEN actualSplitType = "XOR_SPLIT" AND actualJoinType = "XOR_JOIN" 
      THEN "Safe combination: " + splitNode.name + " (XOR-split) activates one path and " + joinNode.name + " (XOR-join) continues after one path completes"
    WHEN actualSplitType = "OR_SPLIT" AND actualJoinType = "OR_JOIN" 
      THEN "Safe combination: " + splitNode.name + " (OR-split) activates one or more paths and " + joinNode.name + " (OR-join) continues when each active path completes"
    WHEN actualSplitType = "XOR_SPLIT" AND actualJoinType = "OR_JOIN" 
      THEN "Safe combination: " + splitNode.name + " (XOR-split) activates one path and " + joinNode.name + " (OR-join) continues after that path completes"
    WHEN actualSplitType = "OR_SPLIT" AND actualJoinType = "XOR_JOIN" 
      THEN "Potential race condition: " + splitNode.name + " (OR-split) may activate multiple paths but " + joinNode.name + " (XOR-join) only accepts first arrival"
    
    // Default case for any other combinations
    ELSE "Unknown gateway combination: " + actualSplitType + " to " + actualJoinType
  END AS deadlockDescription

// Mark the split relationship with deadlock information
SET firstRel.structural_deadlock = true,
    firstRel.deadlock_type = deadlockType,
    firstRel.deadlock_description = deadlockDescription

// Prepare for return
WITH 
  splitNode.name AS startGateway,
  joinNode.name AS endGateway,
  actualSplitType AS splitType,
  actualJoinType AS joinType,
  [n IN nodes(path) | n.name] AS nodeSequence,
  [n IN nodes(path) WHERE labels(n)[0] = 'Task' | n.name] AS tasksInPath,
  length(path) + 1 AS pathLength,
  outgoingFlows,
  deadlockType,
  deadlockDescription

WITH startGateway, outgoingFlows,
     collect({
       end_gateway: endGateway,
       split_type: splitType,
       join_type: joinType,
       node_sequence: nodeSequence,
       tasks: tasksInPath,
       path_length: pathLength,
       deadlock_type: deadlockType,
       deadlock_description: deadlockDescription,
       is_deadlock: true
     }) AS deadlock_paths
WHERE size(deadlock_paths) > 0

RETURN 
  startGateway,
  outgoingFlows AS potential_paths_count,
  deadlock_paths AS all_paths
ORDER BY startGateway, outgoingFlows DESC;