"""
Configuration for Flexible Deadlock Detector
- Dynamic configuration management
- Strategy-specific settings
- Runtime configuration updates
"""

import json
import os
from typing import Dict, Any, List
from dataclasses import dataclass, asdict

@dataclass
class DetectionConfig:
    """Configuration for deadlock detection"""
    max_path_depth: int = 20
    min_severity_threshold: str = 'LOW'
    enable_filtering: bool = True
    output_format: str = 'json'
    enable_parallel_detection: bool = True
    enable_convergent_detection: bool = True
    enable_resource_contention: bool = True
    enable_circular_dependency: bool = True
    enable_transaction_boundary: bool = False
    
    # Strategy-specific configurations
    parallel_gateway_config: Dict = None
    convergent_join_config: Dict = None
    table_lock_config: Dict = None
    
    def __post_init__(self):
        if self.parallel_gateway_config is None:
            self.parallel_gateway_config = {
                'trace_depth': 15,
                'require_shared_tables': True,
                'minimum_operations': 1
            }
        
        if self.convergent_join_config is None:
            self.convergent_join_config = {
                'trace_depth': 20,
                'analyze_xor_convergence': True,
                'minimum_conflicts': 1
            }
        
        if self.table_lock_config is None:
            self.table_lock_config = {
                'detect_write_write': True,
                'detect_read_write': True,
                'minimum_severity': 'MEDIUM'
            }

class FlexibleConfigManager:
    """Manages configuration for flexible deadlock detector"""
    
    def __init__(self, config_file: str = None):
        self.config_file = config_file or "deadlock_detection_config.json"
        self.config = DetectionConfig()
        self.load_config()
    
    def load_config(self):
        """Load configuration from file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    config_data = json.load(f)
                
                # Update config with loaded data
                for key, value in config_data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                print(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                print(f"Error loading config: {e}, using defaults")
        else:
            print("No config file found, using defaults")
    
    def save_config(self):
        """Save current configuration to file"""
        try:
            config_dict = asdict(self.config)
            with open(self.config_file, 'w') as f:
                json.dump(config_dict, f, indent=2)
            print(f"Configuration saved to {self.config_file}")
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def update_config(self, **kwargs):
        """Update configuration with new values"""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                print(f"Updated {key} = {value}")
            else:
                print(f"Warning: Unknown config key '{key}'")
    
    def get_strategy_config(self, strategy_name: str) -> Dict:
        """Get configuration for specific strategy"""
        strategy_configs = {
            'ParallelGatewayStrategy': self.config.parallel_gateway_config,
            'ConvergentJoinStrategy': self.config.convergent_join_config,
            'SQLTableLockStrategy': self.config.table_lock_config
        }
        
        return strategy_configs.get(strategy_name, {})
    
    def is_strategy_enabled(self, strategy_name: str) -> bool:
        """Check if strategy is enabled"""
        strategy_flags = {
            'ParallelGatewayStrategy': self.config.enable_parallel_detection,
            'ConvergentJoinStrategy': self.config.enable_convergent_detection,
            'ResourceContentionStrategy': self.config.enable_resource_contention,
            'CircularDependencyStrategy': self.config.enable_circular_dependency,
            'TransactionBoundaryStrategy': self.config.enable_transaction_boundary,
            'SQLTableLockStrategy': self.config.enable_resource_contention
        }
        
        return strategy_flags.get(strategy_name, True)
    
    def get_enabled_strategies(self) -> List[str]:
        """Get list of enabled strategy names"""
        all_strategies = [
            'ParallelGatewayStrategy',
            'ConvergentJoinStrategy', 
            'ResourceContentionStrategy',
            'CircularDependencyStrategy',
            'TransactionBoundaryStrategy',
            'SQLTableLockStrategy'
        ]
        
        return [s for s in all_strategies if self.is_strategy_enabled(s)]
    
    def create_detection_profiles(self) -> Dict[str, DetectionConfig]:
        """Create predefined detection profiles"""
        profiles = {}
        
        # Conservative profile - fewer false positives
        conservative = DetectionConfig(
            min_severity_threshold='HIGH',
            enable_filtering=True,
            enable_parallel_detection=True,
            enable_convergent_detection=True,
            enable_resource_contention=True,
            enable_circular_dependency=True,
            enable_transaction_boundary=False
        )
        conservative.parallel_gateway_config['require_shared_tables'] = True
        conservative.table_lock_config['minimum_severity'] = 'HIGH'
        profiles['conservative'] = conservative
        
        # Aggressive profile - catch all potential deadlocks
        aggressive = DetectionConfig(
            min_severity_threshold='LOW',
            enable_filtering=False,
            enable_parallel_detection=True,
            enable_convergent_detection=True,
            enable_resource_contention=True,
            enable_circular_dependency=True,
            enable_transaction_boundary=True
        )
        aggressive.parallel_gateway_config['require_shared_tables'] = False
        aggressive.table_lock_config['detect_read_write'] = True
        profiles['aggressive'] = aggressive
        
        # Production profile - balanced for real-world use
        production = DetectionConfig(
            min_severity_threshold='MEDIUM',
            enable_filtering=True,
            enable_parallel_detection=True,
            enable_convergent_detection=True,
            enable_resource_contention=True,
            enable_circular_dependency=True,
            enable_transaction_boundary=False
        )
        profiles['production'] = production
        
        # Debug profile - maximum information
        debug = DetectionConfig(
            min_severity_threshold='LOW',
            enable_filtering=False,
            max_path_depth=30,
            enable_parallel_detection=True,
            enable_convergent_detection=True,
            enable_resource_contention=True,
            enable_circular_dependency=True,
            enable_transaction_boundary=True
        )
        profiles['debug'] = debug
        
        return profiles
    
    def apply_profile(self, profile_name: str):
        """Apply a predefined profile"""
        profiles = self.create_detection_profiles()
        
        if profile_name in profiles:
            self.config = profiles[profile_name]
            print(f"Applied profile: {profile_name}")
        else:
            print(f"Unknown profile: {profile_name}")
            print(f"Available profiles: {list(profiles.keys())}")
    
    def print_current_config(self):
        """Print current configuration"""
        print("\n=== CURRENT CONFIGURATION ===")
        config_dict = asdict(self.config)
        for key, value in config_dict.items():
            if isinstance(value, dict):
                print(f"{key}:")
                for sub_key, sub_value in value.items():
                    print(f"  {sub_key}: {sub_value}")
            else:
                print(f"{key}: {value}")
        print("=" * 30)

# Example usage and configuration presets
def create_sample_config():
    """Create a sample configuration file"""
    config_manager = FlexibleConfigManager("sample_deadlock_config.json")
    
    # Apply production profile
    config_manager.apply_profile('production')
    
    # Customize some settings
    config_manager.update_config(
        max_path_depth=25,
        enable_transaction_boundary=True
    )
    
    # Save configuration
    config_manager.save_config()
    
    print("Sample configuration created!")
    config_manager.print_current_config()

if __name__ == "__main__":
    create_sample_config()
