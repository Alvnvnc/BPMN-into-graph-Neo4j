import logging
from typing import Dict, List
import networkx as nx
import numpy as np

logger = logging.getLogger(__name__)

class DeadlockDetector:
    """
    Enhanced Deadlock Detector:
    - Detect Structural and Time-based Deadlocks
    - Predict Potential Time Deadlocks
    - Fully compatible with Parallel, Inclusive, Exclusive, Complex, Event-Based gateways
    """

    def __init__(self, activities: Dict, transitions: Dict, gateways: Dict, gateway_patterns: Dict):
        self.activities = activities
        self.transitions = transitions
        self.gateways = gateways
        self.gateway_patterns = gateway_patterns
        self.deadlocks = []

    def detect_all_deadlocks(self) -> List[Dict]:
        self.deadlocks = []
        self.detect_structural_deadlocks()
        self.detect_time_deadlocks()
        return self.deadlocks

    def detect_structural_deadlocks(self) -> List[Dict]:
        for gw_id, pattern in self.gateway_patterns.items():
            if pattern['pattern'] == 'Split':
                requires_convergence = pattern['subtype'] in ['Inclusive', 'Parallel', 'Complex']
                if requires_convergence:
                    has_convergence = any(
                        other_pattern['pattern'] == 'Join' and
                        self._are_gateways_connected(gw_id, other_id)
                        for other_id, other_pattern in self.gateway_patterns.items()
                    )
                    if not has_convergence:
                        gateway = self.gateways[gw_id]
                        self.deadlocks.append({
                            'type': 'Structural',
                            'subtype': 'Missing Gateway Convergence',
                            'description': f"{pattern['subtype']} Gateway (ID: {gw_id}) splits without matching convergence",
                            'severity': 'Critical',
                            'location': gateway.get('lane_id', 'Unknown'),
                            'element_id': gw_id,
                            'element_name': gateway.get('name', 'Unnamed'),
                            'affected_nodes': [gw_id]
                        })
                else:
                    if not self._has_any_outcome(gw_id):
                        gateway = self.gateways[gw_id]
                        self.deadlocks.append({
                            'type': 'Structural',
                            'subtype': 'Warning - No Outcome Path',
                            'description': f"{pattern['subtype']} Gateway (ID: {gw_id}) has no reachable end path",
                            'severity': 'Medium',
                            'location': gateway.get('lane_id', 'Unknown'),
                            'element_id': gw_id,
                            'element_name': gateway.get('name', 'Unnamed'),
                            'affected_nodes': [gw_id]
                        })
        return self.deadlocks

    def detect_time_deadlocks(self) -> List[Dict]:
        threshold_long, threshold_extreme = self.calculate_dynamic_thresholds()

        for act_id, activity in self.activities.items():
            time = self._parse_time(activity.get('Time', '0'))
            if time is None:
                continue

            if time > threshold_long:
                in_parallel, parallel_gw_id = self._check_if_in_parallel_path(act_id)
                subtype = 'Extreme Processing Time' if time > threshold_extreme else 'Long Processing Time'
                severity = 'Critical' if time > threshold_extreme or in_parallel else 'Medium'

                deadlock = {
                    'type': 'Time',
                    'subtype': subtype,
                    'description': f"Activity '{activity.get('name', 'Unnamed')}' processing time {time} min",
                    'severity': severity,
                    'location': activity.get('lane_id', 'Unknown'),
                    'element_id': act_id,
                    'element_name': activity.get('name', 'Unnamed'),
                    'processing_time': time,
                    'in_parallel_path': in_parallel,
                    'affected_nodes': [act_id]
                }
                if parallel_gw_id:
                    deadlock['parallel_gateway_id'] = parallel_gw_id
                    deadlock['affected_nodes'].append(parallel_gw_id)
                self.deadlocks.append(deadlock)
        return self.deadlocks

    def predict_potential_time_deadlocks(self, threshold: float = 60) -> List[Dict]:
        predictions = []
        for gw_id, pattern in self.gateway_patterns.items():
            if pattern['pattern'] == 'Split' and pattern['subtype'] == 'Parallel':
                paths = [
                    sum(
                        self._parse_time(self.activities.get(act_id, {}).get('Time', '0')) or 0
                        for act_id in self._get_activities_in_path(outgoing['to'])
                    ) for outgoing in pattern['outgoing']
                ]
                if paths and max(paths) - min(paths) >= threshold:
                    predictions.append({
                        'type': 'Prediction',
                        'subtype': 'Potential Time Deadlock',
                        'gateway_id': gw_id,
                        'max_time': max(paths),
                        'min_time': min(paths),
                        'delta_time': max(paths) - min(paths),
                        'description': f"Time imbalance across parallel paths exceeds {threshold} minutes",
                        'severity': 'High'
                    })
        return predictions

    def calculate_dynamic_thresholds(self) -> (float, float):
        times = [self._parse_time(activity.get('Time', '0')) for activity in self.activities.values() if self._parse_time(activity.get('Time', '0')) is not None]
        if not times:
            return 60.0, 120.0
        mean_time, std_dev = np.mean(times), np.std(times)
        return mean_time + std_dev, mean_time + 2 * std_dev

    def _parse_time(self, time_str: str) -> float:
        try:
            time = float(time_str)
            return time if time > 0 else None
        except (ValueError, TypeError):
            return None

    def _check_if_in_parallel_path(self, activity_id: str) -> (bool, str):
        for gw_id, pattern in self.gateway_patterns.items():
            if pattern['pattern'] == 'Split' and pattern['subtype'] == 'Parallel':
                if self._is_activity_in_gateway_path(gw_id, activity_id):
                    return True, gw_id
        return False, None

    def _are_gateways_connected(self, source_id: str, target_id: str) -> bool:
        visited = set()
        def dfs(current_id):
            if current_id == target_id:
                return True
            if current_id in visited:
                return False
            visited.add(current_id)
            return any(dfs(t['to']) for t_id, t in self.transitions.items() if t['from'] == current_id)
        return any(dfs(t['to']) for t_id, t in self.transitions.items() if t['from'] == source_id)

    def _is_activity_in_gateway_path(self, gateway_id: str, activity_id: str) -> bool:
        visited = set()
        def dfs(current_id):
            if current_id == activity_id:
                return True
            if current_id in visited:
                return False
            visited.add(current_id)
            return any(dfs(t['to']) for t_id, t in self.transitions.items() if t['from'] == current_id)
        return any(dfs(t['to']) for t_id, t in self.transitions.items() if t['from'] == gateway_id)

    def _get_activities_in_path(self, start_id: str) -> List[str]:
        activities = []
        visited = set()
        def dfs(node_id):
            if node_id in visited:
                return
            visited.add(node_id)
            if node_id in self.activities and node_id not in self.gateways:
                activities.append(node_id)
            for t_id, t in self.transitions.items():
                if t['from'] == node_id:
                    dfs(t['to'])
        dfs(start_id)
        return activities

    def _has_any_outcome(self, gateway_id: str) -> bool:
        visited = set()
        def dfs(node_id):
            if node_id in visited:
                return False
            visited.add(node_id)
            if node_id in self.activities and self.activities[node_id].get('subtype') == 'End':
                return True
            return any(dfs(t['to']) for t_id, t in self.transitions.items() if t['from'] == node_id)
        return any(dfs(t['to']) for t_id, t in self.transitions.items() if t['from'] == gateway_id)
