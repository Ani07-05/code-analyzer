"""
Logger Utility Module

Provides centralized logging configuration for the Code Security Analyzer.
Supports both console and file logging with colored output and proper formatting.
"""

import logging
import sys
from pathlib import Path
from typing import Optional
import colorlog


def setup_logger(level: int = logging.INFO, 
                log_file: Optional[str] = None,
                log_dir: str = "logs") -> logging.Logger:
    """
    Set up centralized logging for the application
    
    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional log file name (defaults to scanner.log)
        log_dir: Directory for log files
    
    Returns:
        Configured logger instance
    """
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(level)
    
    # Clear any existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console_handler = colorlog.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    
    # Color formatter for console
    console_formatter = colorlog.ColoredFormatter(
        '%(log_color)s%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%H:%M:%S',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow', 
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file or level <= logging.INFO:
        # Create logs directory if it doesn't exist
        log_path = Path(log_dir)
        log_path.mkdir(exist_ok=True)
        
        # Use default filename if not provided
        if not log_file:
            log_file = "scanner.log"
        
        file_handler = logging.FileHandler(log_path / log_file)
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        
        # Plain formatter for file
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger instance for a specific module
    
    Args:
        name: Name of the module/component
        
    Returns:
        Logger instance
    """
    return logging.getLogger(name)