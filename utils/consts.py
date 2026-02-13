"""
Configuration module for loading tokens from tokens.yaml
"""
import os
import yaml
from pathlib import Path

# Get the tokens.yaml path (in project root)
TOKENS_FILE = Path(__file__).parent.parent / "tokens.yaml"

def load_tokens():
    """
    Load tokens from tokens.yaml file.
    
    Returns:
        dict: Dictionary with 'openai' and 'git_domains' keys
    """
    if not TOKENS_FILE.exists():
        return {"openai": None, "git_domains": {}}
    
    with open(TOKENS_FILE, 'r') as f:
        config = yaml.safe_load(f)
    
    return {
        "openai": config.get("openai", None),
        "git_domains": config.get("git_domains", {})
    }

# Load tokens at module import
tokens_config = load_tokens()

# Export for use in notebooks/scripts
openai_token = tokens_config["openai"]

# Build tokens dict for GitDataExtractor (domain -> token)
tokens = tokens_config["git_domains"]
