"""
Logging utilities for the flexible deadlock detection system.
"""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json


class DeadlockLogger:
    """
    Specialized logger for deadlock detection system with structured output.
    """
    
    def __init__(self, name: str = "deadlock_detector", level: int = logging.INFO):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Set up console and file handlers with custom formatting."""
        
        # Console handler with colored output
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.INFO)
        
        # File handler for detailed logs
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        file_handler = logging.FileHandler(
            log_dir / f"deadlock_detection_{datetime.now().strftime('%Y%m%d')}.log"
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Custom formatters
        console_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%H:%M:%S'
        )
        
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        
        console_handler.setFormatter(console_format)
        file_handler.setFormatter(file_format)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def log_detection_start(self, strategy_name: str, config: Dict[str, Any]):
        """Log the start of deadlock detection."""
        self.logger.info(f"Starting deadlock detection with strategy: {strategy_name}")
        self.logger.debug(f"Detection configuration: {json.dumps(config, indent=2)}")
    
    def log_detection_result(self, result: 'DeadlockResult'):
        """Log detection results with structured information."""
        severity_emoji = {
            'LOW': '🟡',
            'MEDIUM': '🟠', 
            'HIGH': '🔴',
            'CRITICAL': '💀'
        }
        
        emoji = severity_emoji.get(result.severity.name, '❓')
        
        # Create description from result data
        description = f"{result.conflict_type} between {result.node1_name} and {result.node2_name}"
        
        self.logger.info(
            f"{emoji} Deadlock detected: {description} "
            f"[Severity: {result.severity.name}]"
        )
        
        if result.shared_resources:
            self.logger.info(f"Shared resources: {', '.join(result.shared_resources)}")
        
        if result.confidence:
            self.logger.info(f"Confidence: {result.confidence:.2%}")
        
        # Log detailed information at debug level
        self.logger.debug(f"Full detection result: {result}")
    
    def log_strategy_execution(self, strategy_name: str, execution_time: float, nodes_analyzed: int):
        """Log strategy execution metrics."""
        self.logger.info(
            f"Strategy '{strategy_name}' completed in {execution_time:.3f}s "
            f"(analyzed {nodes_analyzed} nodes)"
        )
    
    def log_error(self, error: Exception, context: Optional[str] = None):
        """Log errors with context information."""
        context_msg = f" in {context}" if context else ""
        self.logger.error(f"Error occurred{context_msg}: {str(error)}", exc_info=True)
    
    def log_warning(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Log warnings with optional details."""
        self.logger.warning(message)
        if details:
            self.logger.debug(f"Warning details: {json.dumps(details, indent=2)}")
    
    def set_level(self, level: int):
        """Set logging level."""
        self.logger.setLevel(level)
        for handler in self.logger.handlers:
            handler.setLevel(level)


# Global logger instance
logger = DeadlockLogger()


def get_logger(name: Optional[str] = None) -> DeadlockLogger:
    """
    Get a logger instance for the deadlock detection system.
    
    Args:
        name: Optional name for the logger. If None, returns the global logger.
    
    Returns:
        DeadlockLogger instance
    """
    if name:
        return DeadlockLogger(name)
    return logger


def set_log_level(level: str):
    """
    Set the global log level.
    
    Args:
        level: Log level ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.set_level(numeric_level)


def log_system_info():
    """Log system information for debugging purposes."""
    import platform
    import psutil
    
    logger.logger.info("=== System Information ===")
    logger.logger.info(f"Platform: {platform.platform()}")
    logger.logger.info(f"Python: {platform.python_version()}")
    logger.logger.info(f"CPU cores: {psutil.cpu_count()}")
    logger.logger.info(f"Memory: {psutil.virtual_memory().total // (1024**3)} GB")
    logger.logger.info("==========================")
