#!/usr/bin/env python3
"""
Balanced Split-Join Deadlock Detector
Menghindari deteksi deadlock sampai ke 'End' dengan mengecek keseimbangan split-join dalam satu proses
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

def analyze_balanced_gateways(graph_data):
    """Analyze gateways with balanced split-join detection"""
    print("=== BALANCED SPLIT-JOIN DEADLOCK ANALYSIS ===")
    print("Konsep: Menghentikan deteksi jika split dan join dalam satu proses sudah seimbang")
    
    # Find all gateways from relationships
    gateways = {}
    gateway_relationships = []
    
    for rel in graph_data['relationships']:
        rel_type = rel['rel_type']
        source_id = rel['source_id']
        target_id = rel['target_id']
        source_name = rel.get('source_name', '')
        target_name = rel.get('target_name', '')
        
        # Check for split gateways
        if '_SPLIT' in rel_type:
            gateway_id = rel.get('properties', {}).get('gateway_id', source_id)
            if gateway_id not in gateways:
                gateways[gateway_id] = {
                    'name': source_name,
                    'node_id': source_id,
                    'type': rel_type,
                    'gateway_type': rel.get('properties', {}).get('gateway_type', 'Unknown'),
                    'is_split': True,
                    'is_join': False
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
        
        # Check for join gateways
        elif '_JOIN' in rel_type:
            gateway_id = rel.get('properties', {}).get('gateway_id', target_id)
            if gateway_id not in gateways:
                gateways[gateway_id] = {
                    'name': target_name,
                    'node_id': target_id,
                    'type': rel_type,
                    'gateway_type': rel.get('properties', {}).get('gateway_type', 'Unknown'),
                    'is_split': False,
                    'is_join': True
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
    
    print(f"\n[DISCOVERY] Found {len(gateways)} gateways")
    
    # Group gateways by process/scope
    process_groups = group_gateways_by_process(gateways, gateway_relationships, graph_data['relationships'])
    
    print(f"\n[GROUPING] Found {len(process_groups)} process groups:")
    for i, group in enumerate(process_groups, 1):
        splits = [gw for gw in group['gateways'] if gateways[gw]['is_split']]
        joins = [gw for gw in group['gateways'] if gateways[gw]['is_join']]
        print(f"   Group {i}: {len(splits)} splits, {len(joins)} joins")
        print(f"      Splits: {[gateways[s]['name'] for s in splits]}")
        print(f"      Joins:  {[gateways[j]['name'] for j in joins]}")
        print(f"      Balanced: {'Yes' if len(splits) == len(joins) else 'No'}")
    
    # Find problematic pairs within balanced groups
    deadlocks = find_balanced_deadlocks(process_groups, gateways, graph_data['relationships'])
    
    print(f"\n[ANALYSIS] Deadlock Analysis Results:")
    print(f"   Total problematic pairs found: {len(deadlocks)}")
    
    if deadlocks:
        print("\n[DEADLOCKS] Detected Structural Deadlocks:")
        for i, deadlock in enumerate(deadlocks, 1):
            print(f"\n   [DEADLOCK #{i}]:")
            print(f"      Split: {deadlock['split_name']} ({deadlock['split_type']})")
            print(f"      Join:  {deadlock['join_name']} ({deadlock['join_type']})")
            print(f"      Process Group: {deadlock['group_id']}")
            print(f"      Issue: {deadlock['issue']}")
            print(f"      Scope: Within balanced process (not extending to End nodes)")
    else:
        print("\n   [OK] No structural deadlocks found within balanced process groups")
    
    return gateways, process_groups, deadlocks

def group_gateways_by_process(gateways, gateway_relationships, all_relationships):
    """Group gateways by their process scope to avoid extending to End nodes"""
    process_groups = []
    visited_gateways = set()
    
    # Build adjacency graph for gateway connections
    gateway_graph = defaultdict(list)
    for rel in gateway_relationships:
        gateway_graph[rel['gateway_id']].append(rel)
    
    # Find connected components of gateways
    for gateway_id in gateways.keys():
        if gateway_id in visited_gateways:
            continue
        
        # BFS to find connected gateways in the same process scope
        group_gateways = set()
        queue = deque([gateway_id])
        
        while queue:
            current_gw = queue.popleft()
            if current_gw in visited_gateways:
                continue
            
            visited_gateways.add(current_gw)
            group_gateways.add(current_gw)
            
            # Find connected gateways through direct paths (not through End nodes)
            current_node = gateways[current_gw]['node_id']
            
            # Look for paths to other gateways within reasonable distance
            for other_gw_id, other_gw_data in gateways.items():
                if other_gw_id not in visited_gateways:
                    other_node = other_gw_data['node_id']
                    
                    # Check if there's a direct path without going through End nodes
                    if has_direct_path(current_node, other_node, all_relationships, max_hops=5):
                        queue.append(other_gw_id)
        
        if group_gateways:
            process_groups.append({
                'group_id': len(process_groups) + 1,
                'gateways': list(group_gateways)
            })
    
    return process_groups

def has_direct_path(source, target, relationships, max_hops=5):
    """Check if there's a direct path between nodes without going through End nodes"""
    if source == target:
        return True
    
    visited = set()
    queue = deque([(source, 0)])
    
    while queue:
        current, hops = queue.popleft()
        
        if hops >= max_hops:
            continue
        
        if current == target:
            return True
        
        if current in visited:
            continue
        
        visited.add(current)
        
        for rel in relationships:
            if rel['source_id'] == current:
                next_node = rel['target_id']
                next_name = rel.get('target_name', '').lower()
                
                # Skip End nodes to avoid extending deadlock detection to process termination
                if 'end' in next_name and next_node != target:
                    continue
                
                if next_node not in visited:
                    queue.append((next_node, hops + 1))
    
    return False

def find_balanced_deadlocks(process_groups, gateways, all_relationships):
    """Find deadlocks within balanced process groups only"""
    deadlocks = []
    
    problematic_combinations = {
        ('AND_SPLIT', 'OR_JOIN'): 'AND-split activates all paths, but OR-join continues after first arrival',
        ('AND_SPLIT', 'XOR_JOIN'): 'AND-split activates all paths, but XOR-join only accepts one token',
        ('OR_SPLIT', 'AND_JOIN'): 'OR-split may not activate all paths, but AND-join requires all paths',
        ('XOR_SPLIT', 'AND_JOIN'): 'XOR-split activates only one path, but AND-join waits for all paths'
    }
    
    for group in process_groups:
        group_gateways = group['gateways']
        splits = [gw for gw in group_gateways if gateways[gw]['is_split']]
        joins = [gw for gw in group_gateways if gateways[gw]['is_join']]
        
        # Only analyze balanced groups (equal number of splits and joins)
        if len(splits) != len(joins):
            continue
        
        # Check for problematic split-join combinations within the group
        for split_id in splits:
            split_node = gateways[split_id]['node_id']
            split_type = gateways[split_id]['type']
            
            for join_id in joins:
                join_node = gateways[join_id]['node_id']
                join_type = gateways[join_id]['type']
                
                # Check if there's a path between split and join
                if has_direct_path(split_node, join_node, all_relationships, max_hops=3):
                    combination = (split_type, join_type)
                    
                    if combination in problematic_combinations:
                        deadlocks.append({
                            'split_id': split_id,
                            'join_id': join_id,
                            'split_name': gateways[split_id]['name'],
                            'join_name': gateways[join_id]['name'],
                            'split_type': split_type,
                            'join_type': join_type,
                            'group_id': group['group_id'],
                            'issue': problematic_combinations[combination]
                        })
    
    return deadlocks

def main():
    print("=== BALANCED SPLIT-JOIN DEADLOCK DETECTOR ===")
    print("Menghindari deteksi deadlock yang meluas sampai ke node 'End'")
    print("Fokus pada keseimbangan split-join dalam scope proses yang sama\n")
    
    # Load graph data
    graph_data = load_graph_data()
    if not graph_data:
        print("[ERROR] Failed to load graph data")
        return
    
    print(f"[OK] Loaded graph with {len(graph_data['nodes'])} nodes and {len(graph_data['relationships'])} relationships")
    
    # Analyze with balanced approach
    gateways, process_groups, deadlocks = analyze_balanced_gateways(graph_data)
    
    print("\n=== ANALYSIS COMPLETE ===")
    print(f"\n[VALIDATION] Balanced Approach Results:")
    print(f"   • Mengidentifikasi {len(process_groups)} process groups")
    print(f"   • Mendeteksi {len(deadlocks)} structural deadlocks dalam scope yang seimbang")
    print(f"   • Menghindari false positive dari deteksi sampai ke End nodes")
    print(f"   • Fokus pada split-join pairs dalam proses yang sama")

if __name__ == "__main__":
    main()