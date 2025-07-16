#!/bin/bash
# Prepare Linux environment: create venv, install Linux prereqs, run TUI
# Intended to be used in codespaces dev container.

set -e

# Create venv if it doesn't exist
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate venv
source venv/bin/activate

# Install all prereqs above the '# windows prereqs' line
awk '/# windows prereqs/ {exit} {print}' requirements.txt | grep -v '^#' | grep -v '^$' > /tmp/reqs_linux.txt
pip install -r /tmp/reqs_linux.txt

# Start the TUI
python tui.py
