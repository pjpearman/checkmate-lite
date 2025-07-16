"""
File operation utilities with pathlib-based implementation and validation.
"""

from pathlib import Path
import json
import logging
from typing import List, Dict, Optional, Union
import shutil
from datetime import datetime

logger = logging.getLogger(__name__)

def ensure_dir(path: Union[str, Path]) -> Path:
    """
    Ensure a directory exists and return its Path object.
    Creates the directory if it doesn't exist.
    
    Args:
        path: Directory path as string or Path
        
    Returns:
        Path object for the directory
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path

def validate_file_ext(path: Union[str, Path], allowed_exts: List[str]) -> bool:
    """
    Validate that a file has an allowed extension.
    
    Args:
        path: File path to validate
        allowed_exts: List of allowed extensions (with dot)
        
    Returns:
        bool: Whether the file extension is allowed
    """
    path = Path(path)
    return path.suffix.lower() in [ext.lower() for ext in allowed_exts]

def safe_json_load(path: Union[str, Path]) -> Dict:
    """
    Safely load a JSON file with error handling.
    
    Args:
        path: Path to JSON file
        
    Returns:
        Dict containing the JSON data
        
    Raises:
        ValueError: If file is invalid JSON
        FileNotFoundError: If file doesn't exist
    """
    path = Path(path)
    try:
        with path.open('r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {path}: {e}")
        raise ValueError(f"Invalid JSON in {path}: {e}")
    except FileNotFoundError:
        logger.error(f"File not found: {path}")
        raise
    except Exception as e:
        logger.error(f"Error reading {path}: {e}")
        raise

def safe_file_move(src: Union[str, Path], dest: Union[str, Path]) -> Path:
    """
    Safely move a file with error handling and backup.
    
    Args:
        src: Source file path
        dest: Destination file path
        
    Returns:
        Path object for the destination file
        
    Raises:
        FileNotFoundError: If source doesn't exist
        OSError: If move operation fails
    """
    src, dest = Path(src), Path(dest)
    
    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")
        
    if dest.exists():
        backup = dest.with_suffix(f"{dest.suffix}.{datetime.now():%Y%m%d_%H%M%S}.bak")
        logger.info(f"Creating backup: {backup}")
        shutil.copy2(dest, backup)
    
    try:
        shutil.move(src, dest)
        return dest
    except Exception as e:
        logger.error(f"Error moving {src} to {dest}: {e}")
        raise

def list_files_with_ext(
    directory: Union[str, Path],
    extension: str,
    recursive: bool = False
) -> List[Path]:
    """
    List all files with a given extension in a directory.
    
    Args:
        directory: Directory to search
        extension: File extension to match (with or without dot)
        recursive: Whether to search recursively
        
    Returns:
        List of Path objects for matching files
    """
    directory = Path(directory)
    if not extension.startswith('.'):
        extension = f".{extension}"
        
    pattern = f"**/*{extension}" if recursive else f"*{extension}"
    return sorted(directory.glob(pattern))
