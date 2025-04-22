import configparser
import os
from typing import Dict

def load_config(config_path: str = None) -> Dict:
    """
    Load configuration from a config file or environment variables.
    
    Args:
        config_path: Path to the configuration file (optional)
        
    Returns:
        Dictionary containing configuration parameters
    """
    # Default configuration
    config = {
        'xpdl_file': 'your_xpdl_file_path',  # Changed from xpdl_path to xpdl_file for consistency
        'neo4j_uri': 'bolt://localhost:7687',
        'neo4j_user': 'your_username',
        'neo4j_password': 'your_password',
    }
    
    # Load from config file if provided
    if config_path and os.path.exists(config_path):
        parser = configparser.ConfigParser()
        parser.read(config_path)
        
        if 'Database' in parser:
            if 'uri' in parser['Database']:
                config['neo4j_uri'] = parser['Database']['uri']
            if 'username' in parser['Database']:
                config['neo4j_user'] = parser['Database']['username']
            if 'password' in parser['Database']:
                config['neo4j_password'] = parser['Database']['password']
        
        if 'Files' in parser and 'xpdl_file' in parser['Files']:  # Changed from xpdl_path to xpdl_file
            config['xpdl_file'] = parser['Files']['xpdl_file']
    
    # Override with environment variables if they exist
    if 'NEO4J_URI' in os.environ:
        config['neo4j_uri'] = os.environ['NEO4J_URI']
    if 'NEO4J_USER' in os.environ:
        config['neo4j_user'] = os.environ['NEO4J_USER']
    if 'NEO4J_PASSWORD' in os.environ:
        config['neo4j_password'] = os.environ['NEO4J_PASSWORD']
    if 'XPDL_FILE' in os.environ:
        config['xpdl_file'] = os.environ['XPDL_FILE']
    
    return config

def save_config(config: Dict, config_path: str) -> None:
    """
    Save configuration to a file.
    
    Args:
        config: Dictionary containing configuration parameters
        config_path: Path where to save the configuration file
    """
    parser = configparser.ConfigParser()
    
    parser['Database'] = {
        'uri': config['neo4j_uri'],
        'username': config['neo4j_user'],
        'password': config['neo4j_password']
    }
    
    parser['Files'] = {
        'xpdl_file': config['xpdl_file']  # Changed from xpdl_path to xpdl_file
    }
    
    with open(config_path, 'w') as f:
        parser.write(f)