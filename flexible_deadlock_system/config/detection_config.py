from typing import Dict, List, Any, Type
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from core.base_detector import BaseDeadlockStrategy

class StrategyRegistry:
    """Registry for managing deadlock detection strategies"""
    
    def __init__(self):
        self.strategies: Dict[str, BaseDeadlockStrategy] = {}
        self.strategy_configs: Dict[str, Dict] = {}
    
    def register_strategy(self, name: str, strategy: BaseDeadlockStrategy, config: Dict = None):
        """
        Register a deadlock detection strategy
        
        Args:
            name: Strategy name
            strategy: Strategy instance
            config: Strategy-specific configuration
        """
        self.strategies[name] = strategy
        self.strategy_configs[name] = config or {}
        
    def unregister_strategy(self, name: str):
        """Unregister a strategy"""
        if name in self.strategies:
            del self.strategies[name]
        if name in self.strategy_configs:
            del self.strategy_configs[name]
    
    def get_strategy(self, name: str) -> BaseDeadlockStrategy:
        """Get a strategy by name"""
        return self.strategies.get(name)
    
    def get_all_strategies(self) -> Dict[str, BaseDeadlockStrategy]:
        """Get all registered strategies"""
        return self.strategies.copy()
    
    def get_enabled_strategies(self) -> Dict[str, BaseDeadlockStrategy]:
        """Get only enabled strategies"""
        return {name: strategy for name, strategy in self.strategies.items() if strategy.enabled}
    
    def enable_strategy(self, name: str):
        """Enable a strategy"""
        if name in self.strategies:
            self.strategies[name].enabled = True
    
    def disable_strategy(self, name: str):
        """Disable a strategy"""
        if name in self.strategies:
            self.strategies[name].enabled = False
    
    def set_strategy_priority(self, name: str, priority: int):
        """Set strategy priority (higher = executed first)"""
        if name in self.strategies:
            self.strategies[name].priority = priority
    
    def get_strategies_by_priority(self) -> List[tuple]:
        """Get strategies sorted by priority (highest first)"""
        strategy_items = [(name, strategy) for name, strategy in self.strategies.items() if strategy.enabled]
        return sorted(strategy_items, key=lambda x: x[1].priority, reverse=True)
    
    def update_strategy_config(self, name: str, config: Dict):
        """Update configuration for a strategy"""
        if name in self.strategy_configs:
            self.strategy_configs[name].update(config)
        else:
            self.strategy_configs[name] = config
    
    def get_strategy_config(self, name: str) -> Dict:
        """Get configuration for a strategy"""
        return self.strategy_configs.get(name, {})


class DetectionConfig:
    """Configuration for deadlock detection"""
    
    def __init__(self, config_dict: Dict = None):
        self.config = config_dict or {}
        self._load_default_config()
    
    def _load_default_config(self):
        """Load default configuration values"""
        defaults = {
            # Global settings
            'max_depth': 20,
            'timeout_seconds': 300,
            'enable_logging': True,
            'log_level': 'INFO',
            
            # Detection thresholds
            'severity_threshold': 'MEDIUM',
            'confidence_threshold': 0.5,
            'conflict_score_threshold': 0.3,
            
            # Strategy settings
            'enabled_strategies': ['parallel_execution', 'resource_contention', 'gateway_specific'],
            'strategy_priorities': {
                'parallel_execution': 10,
                'resource_contention': 8,
                'gateway_specific': 6,
                'custom': 5
            },
            
            # Filtering options
            'exclude_xor_gateways': True,
            'exclude_sequential_paths': True,
            'exclude_mutually_exclusive': True,
            'include_convergent_joins': True,
            'include_conditional_parallel': True,
            
            # SQL analysis settings
            'sql_operation_weights': {
                'INSERT': 1.0,
                'UPDATE': 1.2,
                'DELETE': 1.1,
                'SELECT': 0.3,
                'MERGE': 1.3,
                'UPSERT': 1.2
            },
            
            # Resource conflict settings
            'table_conflict_weight': 1.0,
            'column_conflict_weight': 0.5,
            'write_write_conflict_weight': 1.5,
            'write_read_conflict_weight': 0.8,
            
            # Output settings
            'output_format': 'json',
            'include_recommendations': True,
            'include_sql_details': True,
            'group_by_severity': True,
            
            # Performance settings
            'batch_size': 100,
            'parallel_processing': False,
            'cache_results': True,
            'cache_ttl_seconds': 3600
        }
        
        # Merge with provided config
        for key, value in defaults.items():
            if key not in self.config:
                self.config[key] = value
    
    def get(self, key: str, default=None):
        """Get configuration value"""
        return self.config.get(key, default)
    
    def set(self, key: str, value):
        """Set configuration value"""
        self.config[key] = value
    
    def update(self, config_dict: Dict):
        """Update configuration with new values"""
        self.config.update(config_dict)
    
    def get_strategy_config(self, strategy_name: str) -> Dict:
        """Get strategy-specific configuration"""
        strategy_configs = self.config.get('strategy_configs', {})
        return strategy_configs.get(strategy_name, {})
    
    def set_strategy_config(self, strategy_name: str, config: Dict):
        """Set strategy-specific configuration"""
        if 'strategy_configs' not in self.config:
            self.config['strategy_configs'] = {}
        self.config['strategy_configs'][strategy_name] = config
    
    def is_strategy_enabled(self, strategy_name: str) -> bool:
        """Check if a strategy is enabled"""
        enabled_strategies = self.config.get('enabled_strategies', [])
        return strategy_name in enabled_strategies
    
    def get_strategy_priority(self, strategy_name: str) -> int:
        """Get priority for a strategy"""
        priorities = self.config.get('strategy_priorities', {})
        return priorities.get(strategy_name, 5)  # Default priority
    
    def should_exclude_xor(self) -> bool:
        """Check if XOR gateways should be excluded"""
        return self.config.get('exclude_xor_gateways', True)
    
    def should_include_convergent(self) -> bool:
        """Check if convergent joins should be included"""
        return self.config.get('include_convergent_joins', True)
    
    def get_severity_threshold(self) -> str:
        """Get minimum severity threshold"""
        return self.config.get('severity_threshold', 'MEDIUM')
    
    def get_confidence_threshold(self) -> float:
        """Get minimum confidence threshold"""
        return self.config.get('confidence_threshold', 0.5)
    
    def to_dict(self) -> Dict:
        """Export configuration as dictionary"""
        return self.config.copy()
    
    def from_dict(self, config_dict: Dict):
        """Load configuration from dictionary"""
        self.config = config_dict.copy()
    
    def save_to_file(self, file_path: str):
        """Save configuration to JSON file"""
        import json
        with open(file_path, 'w') as f:
            json.dump(self.config, f, indent=2)
    
    def load_from_file(self, file_path: str):
        """Load configuration from JSON file"""
        import json
        try:
            with open(file_path, 'r') as f:
                config_dict = json.load(f)
            self.from_dict(config_dict)
        except FileNotFoundError:
            print(f"Configuration file {file_path} not found, using defaults")
        except json.JSONDecodeError as e:
            print(f"Error parsing configuration file: {e}, using defaults")

    @classmethod
    def create_balanced_config(cls):
        """Create a balanced configuration preset"""
        config = cls()
        config.update(STRATEGY_PRESETS['balanced'])
        return config
    
    @classmethod
    def create_aggressive_config(cls):
        """Create an aggressive configuration preset"""
        config = cls()
        config.update(STRATEGY_PRESETS['aggressive'])
        return config
    
    @classmethod
    def create_conservative_config(cls):
        """Create a conservative configuration preset"""
        config = cls()
        config.update(STRATEGY_PRESETS['conservative'])
        return config
    
    @classmethod
    def create_performance_focused_config(cls):
        """Create a performance-focused configuration preset"""
        config = cls()
        config.update(STRATEGY_PRESETS['performance_focused'])
        return config
        

# Pre-configured strategy configurations
STRATEGY_PRESETS = {
    'aggressive': {
        'severity_threshold': 'LOW',
        'confidence_threshold': 0.3,
        'exclude_mutually_exclusive': False,
        'include_conditional_parallel': True
    },
    
    'conservative': {
        'severity_threshold': 'HIGH',
        'confidence_threshold': 0.8,
        'exclude_mutually_exclusive': True,
        'exclude_sequential_paths': True
    },
    
    'balanced': {
        'severity_threshold': 'MEDIUM',
        'confidence_threshold': 0.6,
        'exclude_xor_gateways': True,
        'include_convergent_joins': True
    },
    
    'performance_focused': {
        'max_depth': 10,
        'batch_size': 50,
        'parallel_processing': True,
        'cache_results': True
    }
}
