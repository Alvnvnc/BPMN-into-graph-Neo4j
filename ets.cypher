//no. 3
MATCH path = (s)-[r1]->(mid)-[r2]->(e)
WHERE r1.gateway_id IS NOT NULL AND r2.gateway_id IS NOT NULL
  AND type(r1) ENDS WITH "_SPLIT"
  AND type(r2) ENDS WITH "_JOIN"
  AND r1.gateway_type <> r2.gateway_type
RETURN
  r1.gateway_type AS split_type,
  type(r1) AS split_relation,
  s.name AS split_from,
  mid.name AS via,
  r2.gateway_type AS join_type,
  type(r2) AS join_relation,
  e.name AS join_to,
  [n IN nodes(path) | n.name] AS path_names

//no. 4
// Match paths through intermediate nodes
MATCH path = (split)-[r1]->(mid:IntermediateNode)-[r2]->(join)
WHERE mid.is_gateway_connector = true

// Calculate deadlock explanation
WITH split, r1, mid, r2, join,
CASE
  WHEN split.subtype = 'Parallel' AND join.subtype = 'Exclusive'
    THEN 'Potential deadlock: AND Split to XOR Join'
  WHEN split.subtype = 'Inclusive' AND join.subtype = 'Exclusive'
    THEN 'Potential deadlock: OR Split to XOR Join'
  ELSE 'No deadlock pattern detected'
END AS deadlockExplanation

// Set deadlock explanation property on all relationships
SET r1.deadlockExplanation = deadlockExplanation,
    r2.deadlockExplanation = deadlockExplanation

// Return the information
RETURN
  split.name AS SplitGateway,
  split.subtype AS SplitType,
  type(r1) AS SplitRelation,
  mid.name AS IntermediateNode,
  type(r2) AS JoinRelation,
  join.name AS JoinGateway,
  join.subtype AS JoinType,
  deadlockExplanation AS DeadlockExplanation

//no. 5
MATCH (a)-[r]->(b)
WHERE
  (any(label IN labels(a) WHERE toLower(label) CONTAINS "gateway") OR toLower(a.name) CONTAINS "gateway") AND
  (any(label IN labels(b) WHERE toLower(label) CONTAINS "end") OR toLower(b.name) CONTAINS "end event")
WITH a, b, r
SET r.deadlock = "structural – relation as end"
RETURN
  id(r) AS rel_id,
  a.name AS gateway_name,
  b.name AS end_event_name,
  r.deadlock AS flagged