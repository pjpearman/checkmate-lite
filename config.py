"""
Configuration settings for the TUI application.
"""

import os

# Branding
PEAR_ART = "\U0001F350 "  # Unicode pear emoji for best TUI compatibility
ASCII_PEAR = "( )\n/ \\"  # ASCII fallback

# Professional styling constants
APP_TITLE = "CheckMate-Lite"
APP_SUBTITLE = "STIG Checklist Management Suite"
BORDER_CHAR = "═"
VERTICAL_BORDER = "║"
CORNER_TL = "╔"
CORNER_TR = "╗"
CORNER_BL = "╚"
CORNER_BR = "╝"
SEPARATOR = "─"
BULLET_POINT = "•"
ARROW_RIGHT = "▶"
CHECKMARK = "✓"
CROSS_MARK = "✗"

# Directory structure
USER_DOCS_DIR = "user_docs"
SUBDIRS = [
    "zip_files",
    "cklb_new",
    "cklb_artifacts",
    "inventory",
    "cklb_updated"
]

# Create required directories
for subdir in SUBDIRS:
    os.makedirs(os.path.join(USER_DOCS_DIR, subdir), exist_ok=True)

# Logging
LOG_DIR = "logs"
FULLAUTO_LOG = os.path.join(LOG_DIR, "fullauto.log")
DOWNLOADER_LOG = os.path.join(LOG_DIR, "downloader.log")

# Create log directory
os.makedirs(LOG_DIR, exist_ok=True)

# File extensions
CKLB_EXT = ".cklb"
JSON_EXT = ".json"

# Temporary directory
TMP_DIR = "tmp"
os.makedirs(TMP_DIR, exist_ok=True)
