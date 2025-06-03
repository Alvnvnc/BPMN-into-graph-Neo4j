#!/usr/bin/env python3
"""
Test script untuk konsep nested structural deadlock detection
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from collections import defaultdict, deque
import json

def load_graph_data():
    """Load graph data from JSON file"""
    try:
        with open('graph_representation.json', 'r') as f:
            data = json.load(f)
        
        # Convert nodes dict to list format for easier processing
        if 'nodes' in data and isinstance(data['nodes'], dict):
            nodes_list = []
            for node_id, node_data in data['nodes'].items():
                nodes_list.append(node_data)
            data['nodes'] = nodes_list
        
        return data
    except Exception as e:
        print(f"Error loading graph data: {e}")
        return None

def analyze_nested_gateways(graph_data):
    """Analyze nested gateway structure with improved filtering"""
    print("=== ANALYZING NESTED GATEWAY STRUCTURE ===")
    
    # Get all nodes for reference
    nodes_by_id = {}
    for node in graph_data['nodes']:
        nodes_by_id[node['id']] = node
    
    # Filter out Start nodes like in Cypher query: NOT splitNode.name = "Start"
    excluded_start_nodes = set()
    for node in graph_data['nodes']:
        node_name = node.get('name', '')
        if node_name == "Start":
            excluded_start_nodes.add(node['id'])
            print(f"[FILTERED] Start node excluded from split analysis: {node_name} (ID: {node['id']})")
    
    # Find all gateways from relationships (following Cypher logic)
    gateways = {}
    gateway_relationships = []
    
    for rel in graph_data['relationships']:
        rel_type = rel['rel_type']
        source_id = rel['source_id']
        target_id = rel['target_id']
        source_name = rel.get('source_name', '')
        target_name = rel.get('target_name', '')
        
        # Follow Cypher logic: exclude Start nodes from being split gateways
        
        # Check for split gateways (source acts as gateway)
        # Follow Cypher: WHERE type(outRel) CONTAINS "_SPLIT" AND NOT splitNode.name = "Start"
        if '_SPLIT' in rel_type and source_id not in excluded_start_nodes:
            gateway_id = rel.get('properties', {}).get('gateway_id', source_id)
            if gateway_id not in gateways:
                gateways[gateway_id] = {
                    'name': source_name,
                    'node_id': source_id,
                    'level': 0,
                    'type': rel_type,
                    'gateway_type': rel.get('properties', {}).get('gateway_type', 'Unknown')
                }
            gateway_relationships.append({
                'gateway_id': gateway_id,
                'type': 'SPLIT',
                'rel_type': rel_type,
                'source_id': source_id,
                'target_id': target_id,
                'source_name': source_name,
                'target_name': target_name
            })
        
        # Check for join gateways (target acts as gateway)
        # Follow Cypher: joinNode.name <> "End"
        elif '_JOIN' in rel_type and target_name != "End":
            gateway_id = rel.get('properties', {}).get('gateway_id', target_id)
            if gateway_id not in gateways:
                gateways[gateway_id] = {
                    'name': target_name,
                    'node_id': target_id,
                    'level': 0,
                    'type': rel_type,
                    'gateway_type': rel.get('properties', {}).get('gateway_type', 'Unknown')
                }
            gateway_relationships.append({
                'gateway_id': gateway_id,
                'type': 'JOIN',
                'rel_type': rel_type,
                'source_id': source_id,
                'target_id': target_id,
                'source_name': source_name,
                'target_name': target_name
            })
    
    print(f"Found {len(gateways)} gateways from relationships")
    
    # Print gateway details
    print("\n[DISCOVERY] DISCOVERED GATEWAYS:")
    for gw_id, gw_data in gateways.items():
        print(f"   • {gw_data['name']} ({gw_data['type']}) - {gw_data['gateway_type']}")
    
    # Calculate nesting levels
    levels = calculate_nesting_levels(gateways, gateway_relationships)
    
    # Print gateway hierarchy
    print("\n[HIERARCHY] GATEWAY HIERARCHY:")
    for level in sorted(levels.keys()):
        print(f"\n  Level {level}:")
        for gateway_id in levels[level]:
            gateway = gateways[gateway_id]
            print(f"    • {gateway['name']} ({gateway['type']}) - {gateway['gateway_type']}")
    
    # Find nested pairs using the concept: split_n pairs with join_n+1, split_n+1 pairs with join_n
    nested_pairs = find_nested_pairs(levels, gateways, gateway_relationships, graph_data['relationships'])
    
    print(f"\n[ANALYSIS] NESTED GATEWAY PAIRS ANALYSIS:")
    print(f"   Total pairs found: {len(nested_pairs)}")
    
    # Categorize pairs
    same_level = [p for p in nested_pairs if p['relationship'] == 'same_level']
    cross_level_down = [p for p in nested_pairs if p['relationship'] == 'cross_level_down']
    cross_level_up = [p for p in nested_pairs if p['relationship'] == 'cross_level_up']
    
    print(f"   • Same level pairs: {len(same_level)}")
    print(f"   • Cross-level down (split_n -> join_n+1): {len(cross_level_down)}")
    print(f"   • Cross-level up (split_n+1 -> join_n): {len(cross_level_up)}")
    
    # Show detailed pairs
    if nested_pairs:
        print("\n[DETAILS] DETAILED PAIRS:")
        for i, pair in enumerate(nested_pairs, 1):
            print(f"   {i}. {pair['split_name']} ({pair['split_type']}) -> {pair['join_name']} ({pair['join_type']})")
            print(f"      Relationship: {pair['relationship']} (Level {pair['split_level']} -> {pair['join_level']})")
    
    return gateways, levels, nested_pairs

def calculate_nesting_levels(gateways, gateway_relationships):
    """Calculate nesting levels for gateways based on process flow"""
    # For simplicity, assign levels based on gateway type and flow order
    # Split gateways typically come before join gateways in the same process level
    
    levels = defaultdict(list)
    
    # Group gateways by their process flow position
    splits = [gw_id for gw_id, gw_data in gateways.items() if 'SPLIT' in gw_data['type']]
    joins = [gw_id for gw_id, gw_data in gateways.items() if 'JOIN' in gw_data['type']]
    
    # Assign levels: splits at even levels, joins at odd levels
    # This creates the nested structure where split_n pairs with join_n+1
    
    split_level = 0
    join_level = 1
    
    # Assign splits to even levels
    for i, split_id in enumerate(splits):
        current_level = split_level + (i * 2)  # 0, 2, 4, ...
        levels[current_level].append(split_id)
        gateways[split_id]['level'] = current_level
    
    # Assign joins to odd levels
    for i, join_id in enumerate(joins):
        current_level = join_level + (i * 2)  # 1, 3, 5, ...
        levels[current_level].append(join_id)
        gateways[join_id]['level'] = current_level
    
    return levels

def has_limited_path(source_node_id, target_node_id, all_relationships, max_depth=10):
    """Check if there's a path between nodes with depth limit to prevent infinite loops"""
    if source_node_id == target_node_id:
        return True
        
    visited = set()
    queue = deque([(source_node_id, 0)])
    
    while queue:
        current, depth = queue.popleft()
        if depth > max_depth:
            continue
            
        if current == target_node_id:
            return True
        if current in visited:
            continue
        visited.add(current)
        
        for rel in all_relationships:
            if rel['source_id'] == current and rel['target_id'] not in visited:
                queue.append((rel['target_id'], depth + 1))
    return False

def find_nested_pairs(levels, gateways, gateway_relationships, all_relationships):
    """Find nested gateway pairs using the concept: split_n pairs with join_n+1, split_n+1 pairs with join_n"""
    pairs = []
    
    # Implement the nested concept: split_n pairs with join_n+1, split_n+1 pairs with join_n
    for level, gateways_at_level in levels.items():
        splits = [gw for gw in gateways_at_level if 'SPLIT' in gateways[gw]['type']]
        
        # For each split at level n, find joins at level n+1 (cross-level down)
        if level + 1 in levels:
            next_level_joins = [gw for gw in levels[level + 1] if 'JOIN' in gateways[gw]['type']]
            
            for split_id in splits:
                split_node_id = gateways[split_id]['node_id']
                for join_id in next_level_joins:
                    join_node_id = gateways[join_id]['node_id']
                    if split_node_id != join_node_id and has_limited_path(split_node_id, join_node_id, all_relationships):
                        pairs.append({
                            'split_id': split_id,
                            'join_id': join_id,
                            'split_level': level,
                            'join_level': level + 1,
                            'relationship': 'cross_level_down',
                            'split_name': gateways[split_id]['name'],
                            'join_name': gateways[join_id]['name'],
                            'split_type': gateways[split_id]['type'],
                            'join_type': gateways[join_id]['type']
                        })
        
        # For each split at level n+1, find joins at level n (cross-level up)
        if level - 1 >= 0 and level - 1 in levels:
            prev_level_joins = [gw for gw in levels[level - 1] if 'JOIN' in gateways[gw]['type']]
            
            for split_id in splits:
                split_node_id = gateways[split_id]['node_id']
                for join_id in prev_level_joins:
                    join_node_id = gateways[join_id]['node_id']
                    if split_node_id != join_node_id and has_limited_path(split_node_id, join_node_id, all_relationships):
                        pairs.append({
                            'split_id': split_id,
                            'join_id': join_id,
                            'split_level': level,
                            'join_level': level - 1,
                            'relationship': 'cross_level_up',
                            'split_name': gateways[split_id]['name'],
                            'join_name': gateways[join_id]['name'],
                            'split_type': gateways[split_id]['type'],
                            'join_type': gateways[join_id]['type']
                        })
        
        # Also check same level pairs for completeness
        joins = [gw for gw in gateways_at_level if 'JOIN' in gateways[gw]['type']]
        for split_id in splits:
            split_node_id = gateways[split_id]['node_id']
            for join_id in joins:
                join_node_id = gateways[join_id]['node_id']
                if split_node_id != join_node_id and has_limited_path(split_node_id, join_node_id, all_relationships):
                    pairs.append({
                        'split_id': split_id,
                        'join_id': join_id,
                        'split_level': level,
                        'join_level': level,
                        'relationship': 'same_level',
                        'split_name': gateways[split_id]['name'],
                        'join_name': gateways[join_id]['name'],
                        'split_type': gateways[split_id]['type'],
                        'join_type': gateways[join_id]['type']
                    })
    
    return pairs

def analyze_potential_deadlocks(nested_pairs, gateways):
    """Analyze potential deadlocks following Cypher logic"""
    print("\n=== ANALYZING POTENTIAL DEADLOCKS (Following Cypher Logic) ===")
    
    deadlocks = []
    
    # Define problematic combinations based on Cypher logic
    # Map actual gateway types: Parallel=AND, Inclusive=OR, Exclusive=XOR
    problematic_combinations = {
        ('Parallel_SPLIT', 'Inclusive_JOIN'): 'Parallel-split to Inclusive-join (AND to OR)',
        ('Parallel_SPLIT', 'Exclusive_JOIN'): 'Parallel-split to Exclusive-join (AND to XOR)', 
        ('Inclusive_SPLIT', 'Parallel_JOIN'): 'Inclusive-split to Parallel-join (OR to AND)',
        ('Exclusive_SPLIT', 'Parallel_JOIN'): 'Exclusive-split to Parallel-join (XOR to AND)'
    }
    
    # Safe combinations (not reported as deadlocks)
    safe_combinations = {
        ('Parallel_SPLIT', 'Parallel_JOIN'): 'Parallel-split to Parallel-join (AND to AND - Safe)',
        ('Exclusive_SPLIT', 'Exclusive_JOIN'): 'Exclusive-split to Exclusive-join (XOR to XOR - Safe)',
        ('Inclusive_SPLIT', 'Inclusive_JOIN'): 'Inclusive-split to Inclusive-join (OR to OR - Safe)',
        ('Exclusive_SPLIT', 'Inclusive_JOIN'): 'Exclusive-split to Inclusive-join (XOR to OR - Safe)'
    }
    
    # Potential race conditions
    race_conditions = {
        ('Inclusive_SPLIT', 'Exclusive_JOIN'): 'Inclusive-split to Exclusive-join (OR to XOR - Potential race condition)'
    }
    
    deadlocks_detected = 0
    safe_combinations_found = 0
    race_conditions_found = 0
    
    for pair in nested_pairs:
        # Extract gateway information from the pair data structure
        split_id = pair['split_id']
        join_id = pair['join_id']
        split_name = pair['split_name']
        join_name = pair['join_name']
        
        # Get gateway types from gateways dictionary
        split_gateway = gateways.get(pair['split_id'])
        join_gateway = gateways.get(pair['join_id'])
        
        if not split_gateway or not join_gateway:
            continue
            
        # Map gateway types to include SPLIT/JOIN suffix
        split_gateway_type = split_gateway.get('gateway_type', 'Unknown')
        join_gateway_type = join_gateway.get('gateway_type', 'Unknown')
        
        split_type_key = f"{split_gateway_type}_SPLIT"
        join_type_key = f"{join_gateway_type}_JOIN"
        
        # Create combination key
        combination_key = (split_type_key, join_type_key)
        
        if combination_key in problematic_combinations:
            deadlocks_detected += 1
            deadlock = {
                'split_id': split_id,
                'join_id': join_id,
                'split_name': split_name,
                'join_name': join_name,
                'split_type': split_type_key,
                'join_type': join_type_key,
                'description': problematic_combinations[combination_key],
                'relationship': pair['relationship']
            }
            deadlocks.append(deadlock)
            
            print(f"\n[STRUCTURAL DEADLOCK {deadlocks_detected}]")
            print(f"Split Gateway: {split_name} ({split_type_key})")
            print(f"Join Gateway: {join_name} ({join_type_key})")
            print(f"Relationship: {pair['relationship']}")
            print(f"Issue: {problematic_combinations[combination_key]}")
            
        elif combination_key in safe_combinations:
            safe_combinations_found += 1
            print(f"\n[SAFE COMBINATION {safe_combinations_found}]")
            print(f"Split Gateway: {split_name} ({split_type_key})")
            print(f"Join Gateway: {join_name} ({join_type_key})")
            print(f"Status: {safe_combinations[combination_key]}")
            
        elif combination_key in race_conditions:
            race_conditions_found += 1
            print(f"\n[POTENTIAL RACE CONDITION {race_conditions_found}]")
            print(f"Split Gateway: {split_name} ({split_type_key})")
            print(f"Join Gateway: {join_name} ({join_type_key})")
            print(f"Warning: {race_conditions[combination_key]}")
    
    print(f"\n=== DEADLOCK ANALYSIS RESULTS ===")
    print(f"Structural deadlocks detected: {deadlocks_detected}")
    print(f"Safe combinations found: {safe_combinations_found}")
    print(f"Potential race conditions: {race_conditions_found}")
    
    return deadlocks

def main():
    """Main function to test nested deadlock detection with improved filtering"""
    print("=== NESTED STRUCTURAL DEADLOCK DETECTION TEST (IMPROVED) ===")
    
    # Load graph data
    graph_data = load_graph_data()
    if not graph_data:
        print("[ERROR] Failed to load graph data")
        return
    
    print(f"\n[SUCCESS] Loaded graph with {len(graph_data['nodes'])} nodes and {len(graph_data['relationships'])} relationships")
    
    # Analyze nested gateway structure with improved filtering
    gateways, levels, nested_pairs = analyze_nested_gateways(graph_data)
    
    # Analyze potential deadlocks following Cypher logic
    deadlocks = analyze_potential_deadlocks(nested_pairs, gateways)
    
    print("\n=== ANALYSIS COMPLETE ===")
    print(f"Total actual gateways found: {len(gateways)}")
    print(f"Nesting levels: {len(levels)}")
    print(f"Valid nested pairs identified: {len(nested_pairs)}")
    print(f"Structural deadlocks detected: {len(deadlocks)}")
    
    # Show improvements made
    print("\n=== CYPHER LOGIC IMPLEMENTATION ===")
    print("[OK] Start nodes excluded from split gateway analysis (following Cypher)")
    print("[OK] End nodes excluded from join gateway analysis (following Cypher)")
    print("[OK] Structural deadlock detection based on gateway type combinations")
    print("[OK] Safe combinations identified and reported")
    print("[OK] Race conditions detected and flagged")
    
    # Summary
    print("\n=== SUMMARY ===")
    print("This analysis follows the exact logic from structural_deadlock.cypher.")
    print("Focus is on detecting structural deadlocks from incompatible split-join combinations.")
    print("Start nodes are excluded from split analysis, End nodes from join analysis.")

if __name__ == "__main__":
    main()