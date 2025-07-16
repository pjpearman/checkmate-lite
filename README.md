# CheckMate-Lite

CheckMate-Lite is a lightweight toolkit for working with Security Technical Implementation Guide (STIG) content, focusing on the creation, management, and review of checklist bundles (CKLB files). It provides a simple menu driven terminal user interface for interacting with STIG checklists.

## Features

- **Convert STIG XCCDF XML to CKLB**: Easily generate `.cklb` files from official DISA STIG XMLs using `create_cklb.py`.
- **Inventory Management**: Create and manage inventories of available checklists with `create_inventory.py`.
- **Terminal User Interface (TUI)**: Review and update checklists in a terminal environment via `tui.py`.

## Directory Structure

```
cklb_handler.py        # Logic for cklb handling.
create_cklb.py         # Convert XCCDF XML to .cklb JSON.
create_inventory.py    # Create/manage inventory of checklists.
tui.py                 # Terminal user interface for checklist interaction.
user_docs/
  cklb_artifacts       # Typically your current & completed cklbs.
  cklb_new             # Cklb files generated during dl with create option.
  cklb_updated         # The output dir for cklb A to cklb B upgrades.
  zip_files            # (Optional) Zipped checklist bundles.
  inventory            # Inventory files library.
```

## Terminal Menu Structure
```
Create Inventory File                 # Generate a list of technologies.
  | 
Download Options                      # Top-level menu item
  |- Select From All Files            # Download All .zips available.
  |- Download Using Inventory File    # Download .zips listed in inv file.
    |- Create CKLB                    # Creates CKLB. Discards .zip
    |- Download Zip Only              # Downloads zip to user_docs/zip_files
Manage Checklists                     # Top-level menu item
  |- Import CKLB(s)                   # Import user's completed cklbs
  |- Compare CKLB Versions            # Compares rules diff between version A & B
  |- Upgrade CKLB(s)                  # Select cklb(s) for version upgrade
    |-Upgrade No Edit                 # Just upgrade, no new rule edit
    |-Upgrade and Answer              # Interact with new rules to set desired state and comment(s)
  |- Compare Findings (Future)        # Compare finding status between to cklb using V-ID
  |- Automatic CKLB Library Update    # Automates the cklb update job, end to end. 
Explore My Files (Future)             # Top-level menu item
  |- My CLKB STIG Versions            # Select a ckbl directory, file info, edit file
  |- My Inventory Versions            # Select an inventory file, file info, edit file        
```
## Usage

### 1. Clone the repo

```bash
git clone git@github.com:pjpearman/checkmate-lite.git
cd checkmate-lite
```

### 2. Create python venv and install python modules

Create a python environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Windows Users: Install Python First

    Download Python from python.org/downloads.
    Run the installer. IMPORTANT: On the first screen, check the box that says "Add Python to PATH" before clicking Install.
    Complete the installation, then open a new Command Prompt to continue with the steps below.

    Uncomment the lines below windows prereqs in requirements.txt

```bash
python3 -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Terminal User Interface

Launch the TUI to interact with checklists:

```bash
python3 tui.py
```

A first run of tui.py user_docs/... and subdirectories will be created in the working directory to store and process files. 

## File Formats

- **CKLB (.cklb)**: JSON-based format containing parsed STIG rules, metadata, and evaluation status.
- **XCCDF XML**: Official DISA STIG XML input files.

## Requirements

- Python 3.7+
- Standard Python libraries (no external dependencies required for core scripts)

## License

This project is released under the MIT License.

---
