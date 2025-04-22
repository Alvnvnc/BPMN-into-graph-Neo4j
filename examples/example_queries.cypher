// get_all_tasks

            MATCH (t:Task)
            RETURN t.id, t.name, t.type, t.subtype
        

// get_process_flow

            MATCH path = (start:Event_Start)-[*]->(end:Event_End)
            RETURN path LIMIT 10
        

// count_activities_by_lane

            MATCH (a)-[:IN_LANE]->(l:Lane)
            RETURN l.name AS lane, count(a) AS activityCount
            ORDER BY activityCount DESC
        

// find_parallel_paths

            MATCH (a)-[r:PARALLEL_SPLIT]->(b)
            MATCH path = (a)-[*]->(end:Event_End)
            RETURN path LIMIT 10
        

// find_exclusive_decisions

            MATCH (a)-[r:EXCLUSIVE_SPLIT]->(b)
            RETURN a.name AS sourceActivity, 
                   collect(b.name) AS targetActivities,
                   collect(r.condition) AS conditions
        

// find_potential_bottlenecks

            MATCH (a)-[*]->(b)
            WITH b, count(a) AS incomingCount
            WHERE incomingCount > 2
            RETURN b.name AS activity, incomingCount
            ORDER BY incomingCount DESC
        

// detect_deadlocks

            MATCH (a)-[r1]->(b)-[r2*]->(a)
            WHERE NOT a:Event_Start AND NOT a:Event_End
            RETURN a.name AS deadlockStart, 
                   [node in nodes(path) | node.name] AS deadlockCycle
        

// detect_structural_deadlocks

            // Find missing gateway convergence - structural deadlock
            MATCH (g:Gateway)-[:GATEWAY_SPLIT|INCLUSIVE_SPLIT|PARALLEL_SPLIT]->()
            WITH g, g.subtype AS type
            MATCH path = (g)-[*..20]->()
            WHERE NOT EXISTS {
                MATCH path2 = (g)-[*..20]->(converge:Gateway)
                WHERE converge.subtype = type AND converge.direction = 'Converging'
            }
            RETURN DISTINCT g.id, g.name, g.subtype, g.direction
            LIMIT 5
        

// detect_sql_deadlocks

            // Find potential SQL deadlocks with conflicting tables
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            RETURN d.type, d.subtype, d.description, 
                   collect(a.name) AS affected_activities,
                   d.tables AS tables
            ORDER BY d.severity DESC
        

// detect_task_pairs_with_deadlocks

            // Find task pairs that have conflicting SQL access patterns
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            MATCH (d)-[:AFFECTS]->(b:Task)
            WHERE a.id <> b.id 
              AND d.subtype = 'Update Ordering Deadlock'
            RETURN a.name AS task1, b.name AS task2,
                   d.tables AS tables,
                   d.description
        

// find_transactions_with_delays

            // Find transactions that have WAITFOR delays that can cause deadlocks
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            WHERE d.subtype = 'Transaction With Delay'
            RETURN a.name AS task_name,
                   a.SQL AS sql_code,
                   d.description,
                   d.tables
        

// detect_time_deadlocks

            // Find activities with excessive processing time
            MATCH (a:Task)
            WHERE exists(a.Time) AND toFloat(a.Time) > 120
            RETURN a.id, a.name, a.Time
            ORDER BY toFloat(a.Time) DESC
        

// get_deadlocks

            // Get all detected deadlocks
            MATCH (d:Deadlock)-[:AFFECTS]->(a)
            RETURN d.type, d.subtype, d.description, a.name AS affected_activity
            ORDER BY d.severity
        

// detect_deadlocks_by_type

            // Find all deadlocks grouped by type and subtype
            MATCH (d:Deadlock)
            RETURN d.type AS deadlock_type, d.subtype AS subtype, count(*) AS count
            ORDER BY count DESC
        

// sql_deadlock_details

            // Examine SQL deadlocks in detail
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            RETURN d.id, d.description, a.name AS affected_task, a.SQL AS sql
        

// detect_sql_update_conflicts

            // Detect SQL update conflicts between tasks
            MATCH (d:SQLDeadlock)-[:AFFECTS]->(a:Task)
            MATCH (d)-[:AFFECTS]->(b:Task)
            WHERE a.id <> b.id AND a.SQL CONTAINS 'UPDATE' AND b.SQL CONTAINS 'UPDATE'
            RETURN d.description, a.name AS task1, b.name AS task2,
                   a.SQL AS sql1, b.SQL AS sql2
        

// find_parallel_activities_with_long_time

            // Find activities in parallel paths with long processing times
            MATCH (g)-[:PARALLEL_SPLIT]->()-[*]->(a:Task)
            WHERE toFloat(a.Time) > 120
            RETURN g.name AS gateway_name, a.name AS task_name, 
                   a.Time AS processing_time
            ORDER BY toFloat(a.Time) DESC
        

// find_structural_gateway_issues

            // Find structural issues with gateways (missing convergence)
            MATCH (g:Gateway)
            WHERE g.subtype IN ['Inclusive', 'Parallel'] 
                  AND g.direction = 'Diverging'
            WITH g
            MATCH path = (g)-[*..15]->()
            WHERE NOT EXISTS {
                MATCH (g)-[*..15]->(converge:Gateway)
                WHERE converge.subtype = g.subtype 
                      AND converge.direction = 'Converging'
            }
            RETURN DISTINCT g.name AS gateway_name, g.subtype AS type,
                   [(n) IN nodes(path) WHERE n:Task | n.name] AS path_activities
            LIMIT 10
        

// deadlocks_with_affected_nodes

            // Find all deadlocks with their affected nodes
            MATCH (d:Deadlock)-[r:AFFECTS]->(n)
            RETURN d.type AS deadlock_type, d.subtype AS subtype, 
                   d.description AS description, 
                   collect(distinct n.name) AS affected_nodes
        

