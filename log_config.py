"""
Logging configuration for the application.
"""

import logging
import logging.handlers
from pathlib import Path
from typing import Optional
import os
from datetime import datetime

def setup_logging(
    log_dir: str = "logs",
    app_name: Optional[str] = None,
    level: int = logging.INFO
) -> logging.Logger:
    """
    Set up logging with rotation and formatting.
    
    Args:
        log_dir: Directory for log files
        app_name: Name of the application (used for log file name)
        level: Logging level
        
    Returns:
        Logger instance configured for the application
    """
    # Create logs directory if it doesn't exist
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Generate log filename
    if app_name:
        log_file = f"{app_name}.log"
    else:
        log_file = f"app_{datetime.now():%Y%m%d}.log"
    
    log_path = os.path.join(log_dir, log_file)
    
    # Create logger
    logger = logging.getLogger(app_name if app_name else 'checkmate')
    logger.setLevel(level)
    
    # Remove existing handlers to avoid duplicates
    if logger.hasHandlers():
        logger.handlers.clear()
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5,
        mode='a'
    )
    
    # Console handler
    console_handler = logging.StreamHandler()
    
    # Formatter
    formatter = logging.Formatter(
        '[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s'
    )
    
    # Set formatter for both handlers
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def get_operation_logger(operation: str) -> logging.Logger:
    """
    Get a logger for a specific operation.
    
    Args:
        operation: Name of the operation
        
    Returns:
        Logger configured for the specific operation
    """
    return logging.getLogger(f"checkmate.{operation}")
