# Flexible SQL Deadlock Detection System

## Overview
Sistem deteksi deadlock SQL yang fleksibel dan dinamis untuk BPMN processes dengan arsitektur modular dan extensible.

## Features
- **Flexible Strategy System**: Easily add new deadlock detection strategies
- **Dynamic Configuration**: Runtime configuration without code changes
- **Modular Architecture**: Separated concerns for better maintainability
- **Multiple Detection Methods**: Various approaches for different deadlock types
- **Clean Interface**: Simple API for integration

## Architecture

```
flexible_deadlock_system/
├── core/                    # Core components
│   ├── base_detector.py     # Abstract base detector
│   ├── graph_analyzer.py    # Graph analysis utilities
│   └── sql_parser.py        # SQL resource extraction
├── strategies/              # Detection strategies
│   ├── parallel_strategy.py    # Parallel execution deadlocks
│   ├── resource_strategy.py    # Resource contention deadlocks
│   ├── gateway_strategy.py     # Gateway-specific deadlocks
│   └── custom_strategy.py      # User-defined strategies
├── config/                  # Configuration
│   ├── detection_config.py  # Detection parameters
│   └── strategy_registry.py # Strategy management
├── utils/                   # Utilities
│   ├── logger.py           # Logging utilities
│   └── validator.py        # Validation helpers
├── examples/               # Usage examples
│   ├── basic_usage.py      # Basic example
│   └── advanced_usage.py   # Advanced example
└── main.py                 # Main entry point
```

## Quick Start

```python
from flexible_deadlock_system import FlexibleDeadlockDetector

# Initialize detector
detector = FlexibleDeadlockDetector()

# Add detection strategies
detector.add_strategy('parallel', ParallelStrategy())
detector.add_strategy('resource', ResourceStrategy())

# Run detection
results = detector.detect_deadlocks(graph_data)
```

## Configuration

The system uses a flexible configuration approach:

```python
config = {
    'strategies': ['parallel', 'resource', 'gateway'],
    'thresholds': {
        'severity_threshold': 'MEDIUM',
        'confidence_threshold': 0.7
    },
    'filters': {
        'exclude_xor': True,
        'include_convergent': True
    }
}
```

## Adding Custom Strategies

```python
from core.base_detector import BaseDeadlockStrategy

class MyCustomStrategy(BaseDeadlockStrategy):
    def detect(self, graph_data):
        # Your custom detection logic
        return deadlock_results
        
# Register strategy
detector.register_strategy('my_custom', MyCustomStrategy())
```
