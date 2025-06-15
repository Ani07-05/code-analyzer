"""
Configuration Management Module

Centralized configuration handling for the Code Security Analyzer.
Supports YAML and JSON configuration files with environment variable overrides.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class SecurityConfig:
    """Security analysis configuration."""
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_depth: int = 10
    timeout_seconds: int = 300
    enable_ai_validation: bool = True
    consensus_strategy: str = "weighted_confidence"
    

@dataclass
class ModelConfig:
    """AI model configuration."""
    model_name: str = "codellama-7b"
    quantization: str = "4bit"
    max_tokens: int = 2048
    temperature: float = 0.1
    

@dataclass
class OutputConfig:
    """Output and reporting configuration."""
    output_format: str = "html"
    include_citations: bool = True
    include_reasoning: bool = True
    theme: str = "dark"


class ConfigManager:
    """
    Centralized configuration management for the security analyzer.
    
    Handles loading from multiple sources with priority:
    1. Environment variables (highest priority)
    2. Config files (JSON/YAML)
    3. Default values (lowest priority)
    """
    
    def __init__(self, config_dir: Optional[Path] = None):
        """
        Initialize configuration manager.
        
        Args:
            config_dir: Optional custom configuration directory
        """
        self.config_dir = config_dir or Path("config")
        self.config: Dict[str, Any] = {}
        self._load_configuration()
    
    def _load_configuration(self) -> None:
        """Load configuration from multiple sources."""
        # Start with defaults
        self.config = self._get_default_config()
        
        # Load from config files
        config_files = [
            self.config_dir / "settings.yaml",
            self.config_dir / "settings.json",
            Path.home() / ".codesec" / "config.yaml"
        ]
        
        for config_file in config_files:
            if config_file.exists():
                try:
                    file_config = self._load_config_file(config_file)
                    self._merge_config(self.config, file_config)
                    logger.info(f"Loaded configuration from {config_file}")
                except Exception as e:
                    logger.warning(f"Failed to load config from {config_file}: {e}")
        
        # Apply environment variable overrides
        self._apply_env_overrides()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "security": {
                "max_file_size": 10 * 1024 * 1024,
                "max_depth": 10,
                "timeout_seconds": 300,
                "enable_ai_validation": True,
                "consensus_strategy": "weighted_confidence"
            },
            "models": {
                "model_name": "codellama-7b",
                "quantization": "4bit",
                "max_tokens": 2048,
                "temperature": 0.1
            },
            "output": {
                "output_format": "html",
                "include_citations": True,
                "include_reasoning": True,
                "theme": "dark"
            },
            "logging": {
                "level": "INFO",
                "file": "scanner.log",
                "max_size_mb": 100
            }
        }
    
    def _load_config_file(self, config_file: Path) -> Dict[str, Any]:
        """Load configuration from a file."""
        with open(config_file, 'r', encoding='utf-8') as f:
            if config_file.suffix.lower() in ['.yml', '.yaml']:
                return yaml.safe_load(f) or {}
            elif config_file.suffix.lower() == '.json':
                return json.load(f)
            else:
                raise ValueError(f"Unsupported config file format: {config_file.suffix}")
    
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]) -> None:
        """Recursively merge configuration dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides."""
        env_mappings = {
            "CODESEC_MAX_FILE_SIZE": ("security", "max_file_size", int),
            "CODESEC_ENABLE_AI": ("security", "enable_ai_validation", bool),
            "CODESEC_MODEL_NAME": ("models", "model_name", str),
            "CODESEC_OUTPUT_FORMAT": ("output", "output_format", str),
            "CODESEC_LOG_LEVEL": ("logging", "level", str),
        }
        
        for env_var, (section, key, value_type) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                try:
                    if value_type == bool:
                        value = value.lower() in ('true', '1', 'yes', 'on')
                    elif value_type == int:
                        value = int(value)
                    
                    if section not in self.config:
                        self.config[section] = {}
                    self.config[section][key] = value
                    logger.debug(f"Applied env override: {env_var}={value}")
                except ValueError as e:
                    logger.warning(f"Invalid value for {env_var}: {value} ({e})")
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found
            
        Returns:
            Configuration value
        """
        return self.config.get(section, {}).get(key, default)
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration as dataclass."""
        security_dict = self.config.get("security", {})
        return SecurityConfig(**{
            k: v for k, v in security_dict.items() 
            if k in SecurityConfig.__dataclass_fields__
        })
    
    def get_model_config(self) -> ModelConfig:
        """Get model configuration as dataclass."""
        model_dict = self.config.get("models", {})
        return ModelConfig(**{
            k: v for k, v in model_dict.items() 
            if k in ModelConfig.__dataclass_fields__
        })
    
    def get_output_config(self) -> OutputConfig:
        """Get output configuration as dataclass."""
        output_dict = self.config.get("output", {})
        return OutputConfig(**{
            k: v for k, v in output_dict.items() 
            if k in OutputConfig.__dataclass_fields__
        })
    
    def save_config(self, config_file: Optional[Path] = None) -> None:
        """
        Save current configuration to file.
        
        Args:
            config_file: Optional custom config file path
        """
        if not config_file:
            config_file = self.config_dir / "settings.yaml"
        
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(self.config, f, default_flow_style=False, indent=2)
        
        logger.info(f"Configuration saved to {config_file}")


# Global configuration instance
_config_manager: Optional[ConfigManager] = None


def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def get_config(section: str, key: str, default: Any = None) -> Any:
    """Convenience function to get configuration values."""
    return get_config_manager().get(section, key, default)