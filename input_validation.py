"""
Input validation utilities for the TUI application.
"""

import re
from typing import Optional, Dict, Any
from pathlib import Path

def validate_filename(filename: str) -> bool:
    """
    Validate a filename is safe and follows conventions.
    
    Args:
        filename: The filename to validate
        
    Returns:
        bool: Whether the filename is valid
    """
    # Check for common unsafe characters
    unsafe_chars = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
    if unsafe_chars.search(filename):
        return False
        
    # Check it's not too long
    if len(filename) > 255:
        return False
        
    # Don't allow . or .. as filenames
    if filename in ('.', '..'):
        return False
        
    return True

def validate_stig_id(stig_id: str) -> bool:
    """
    Validate a STIG ID follows the expected format.
    
    Args:
        stig_id: The STIG ID to validate
        
    Returns:
        bool: Whether the STIG ID is valid
    """
    # Basic STIG ID format validation
    stig_pattern = re.compile(r'^[A-Za-z0-9_-]+$')
    return bool(stig_pattern.match(stig_id))

def validate_version_release(version: str, release: str) -> bool:
    """
    Validate version and release numbers.
    Supports two formats:
    1. V#R# format - where version and release are numeric (e.g., version="2", release="3")
    2. Y##M## format - where version starts with 'Y' and release starts with 'M' (e.g., version="Y25", release="M04")
    
    Args:
        version: Version number string
        release: Release number string
        
    Returns:
        bool: Whether the version and release are valid
    """
    # Handle Y##M## format
    if str(version).startswith('Y') and str(release).startswith('M'):
        try:
            year = int(version[1:])
            month = int(release[1:])
            return 0 <= year <= 99 and 1 <= month <= 12
        except (ValueError, TypeError, IndexError):
            return False
    
    # Handle V#R# format
    try:
        v = int(version)
        r = int(release)
        return v > 0 and r > 0
    except (ValueError, TypeError):
        return False

def validate_cklb_basic(data: Dict[str, Any]) -> bool:
    """
    Basic validation of CKLB JSON structure.
    
    Args:
        data: The CKLB data dictionary
        
    Returns:
        bool: Whether the basic CKLB structure is valid
    """
    required_fields = {'stigs', 'metadata'}
    return all(field in data for field in required_fields)

def get_safe_path(base_dir: str, filename: str) -> Optional[Path]:
    """
    Get a safe path joining base_dir and filename.
    Prevents directory traversal attacks.
    
    Args:
        base_dir: Base directory path
        filename: Filename to join
        
    Returns:
        Path object if safe, None if unsafe
    """
    if not validate_filename(filename):
        return None
        
    try:
        base = Path(base_dir).resolve()
        full_path = (base / filename).resolve()
        
        # Check if the resolved path is under base_dir
        if base in full_path.parents:
            return full_path
    except Exception:
        pass
        
    return None
