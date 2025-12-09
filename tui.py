#!/usr/bin/env python3
"""
tui.py: A lightweight, flexible terminal UI for web.py.
- Uses curses for a clean UI.
- Allows selecting and downloading files.
- Modular structure for future expansion.
- Secure by design: no sensitive input storage, logs to local log file.
Add more features as needed: toggles, input fields, etc.
"""

import curses
import os
import sys
import json
import re
import logging
import textwrap
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Union

from menu_utils import (
    render_menu, handle_menu_input, render_file_list, 
    show_progress, draw_status_bar, clean_screen
)
from config import (
    PEAR_ART, USER_DOCS_DIR, SUBDIRS, 
    LOG_DIR, FULLAUTO_LOG, TMP_DIR,
    APP_TITLE, CHECKMARK, CROSS_MARK, ARROW_RIGHT
)
from file_utils import (
    ensure_dir, validate_file_ext,
    safe_json_load, safe_file_move,
    list_files_with_ext
)
from input_validation import (
    validate_filename, validate_stig_id,
    validate_version_release, validate_cklb_basic,
    get_safe_path
)
from answerfile_manager import load_cklb, extract_non_nf_rules
from log_config import setup_logging, get_operation_logger
from web import download_file
from cklb_handler import (
    compare_cklb_versions, upgrade_cklb_no_edit,
    upgrade_cklbs_no_edit_tui, upgrade_cklbs_answer_tui
)
from create_cklb import convert_xccdf_zip_to_cklb
from create_inventory import generate_inventory
from stig_scraper import scrape_stig_file_links

# Setup logging
logger = setup_logging(app_name='tui')

# Ensure user_docs and subdirectories exist at startup
for sub in SUBDIRS:
    os.makedirs(os.path.join(USER_DOCS_DIR, sub), exist_ok=True)

# Setup a list of future functions for easy extension
FUNCTIONS = {
    "Create Inventory File": "create_inventory_file_tui",
    "Download Options": "download_options_tui",
    "Manage Checklists": "manage_checklists_tui",
    "Manage Answer File": "manage_answer_file_tui",
    "Automatic CKLB Library Update": "automatic_cklb_library_update_tui",
    # Example: "Set Download Directory": "set_download_dir",
    # Example: "Toggle File Types": "toggle_file_types",
}


def fetch_stig_file_links(mode: str = "all") -> List[Tuple[str, str]]:
    """Return (file_name, url) pairs from the shared STIG scraper."""
    file_links = scrape_stig_file_links(mode=mode)
    logger.debug("Fetched %d STIG file links for mode=%s", len(file_links), mode)
    return file_links

def draw_menu(stdscr, selected_idx):
    """Display the main menu with professional styling."""
    render_menu(
        stdscr,
        "Main Menu",
        list(FUNCTIONS.keys()),
        selected_idx,
        show_help=True
    )

def download_files(stdscr):
    """
    Downloads files with enhanced professional UI.
    Enhanced: supports multi-select, refresh, and status bar.
    If 'Create CKLB' is selected, convert downloaded zips to CKLBs.
    """
    download_mode = prompt_download_mode_tui(stdscr)
    if not download_mode:
        return  # Cancelled
    import shutil
    zip_dir = os.path.join("user_docs", "zip_files")
    cklb_dir = os.path.join("user_docs", "cklb_new")
    tmp_dir = "tmp"
    while True:
        show_progress(stdscr, "Scraping STIG catalog...")
        scrape_mode = "checklist" if download_mode == "cklb" else "all"
        try:
            file_links = fetch_stig_file_links(mode=scrape_mode)
        except Exception as e:
            logger.error("Failed to scrape STIG catalog: %s", e, exc_info=True)
            clean_screen(stdscr)
            draw_status_bar(
                stdscr,
                f"Error scraping STIG catalog: {e}. Press any key to return.",
                "error",
            )
            stdscr.refresh()
            stdscr.getch()
            return
        if not file_links:
            clean_screen(stdscr)
            draw_status_bar(stdscr, "No downloadable files found. Press any key to return.", "warning")
            stdscr.refresh()
            stdscr.getch()
            return
        selected = set()
        current_idx = 0
        scroll_offset = 0
        while True:
            render_file_list(stdscr, "Select Files to Download", file_links, selected, current_idx, scroll_offset)
            
            height = stdscr.getmaxyx()[0]
            max_lines = height - 10  # Account for header and status
            
            # Adjust scroll_offset to keep current_idx visible
            if current_idx < scroll_offset:
                scroll_offset = current_idx
            elif current_idx >= scroll_offset + max_lines:
                scroll_offset = current_idx - max_lines + 1
            
            key = stdscr.getch()
            if key == curses.KEY_UP:
                current_idx = (current_idx - 1) % len(file_links)
            elif key == curses.KEY_DOWN:
                current_idx = (current_idx + 1) % len(file_links)
            elif key == ord(' '):
                if current_idx in selected:
                    selected.remove(current_idx)
                else:
                    selected.add(current_idx)
            elif key in [10, 13]:  # ENTER
                to_download = selected if selected else {current_idx}
                total_files = len(to_download)
                for i, idx in enumerate(to_download):
                    file_name, file_url = file_links[idx]
                    progress = i / total_files
                    show_progress(stdscr, f"Downloading: {file_name}", progress)
                    try:
                        download_file(file_url, file_name)
                        # If CKLB mode, convert zip to CKLB
                        if download_mode == 'cklb' and file_name.endswith('.zip'):
                            zip_path = os.path.join(tmp_dir, file_name)
                            if not os.path.exists(cklb_dir):
                                os.makedirs(cklb_dir, mode=0o700)
                            cklb_results = convert_xccdf_zip_to_cklb(zip_path, cklb_dir)
                            for cklb_path, error in cklb_results:
                                if not cklb_path and error:
                                    draw_status_bar(stdscr, f"CKLB error: {error}", "error")
                        elif download_mode == 'zip':
                            if not os.path.exists(zip_dir):
                                os.makedirs(zip_dir, mode=0o700)
                            shutil.move(os.path.join(tmp_dir, file_name), os.path.join(zip_dir, file_name))
                    except Exception as e:
                        draw_status_bar(stdscr, f"Download error: {e}", "error")
                        stdscr.refresh()
                        stdscr.getch()
                
                show_progress(stdscr, "Download Complete!", 1.0)
                draw_status_bar(stdscr, "Press any key to continue.", "success")
                stdscr.refresh()
                stdscr.getch()
                selected.clear()
            elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
                return
            elif key in [ord('r'), ord('R')]:
                break  # Refresh file list

def prompt_download_mode_tui(stdscr):
    """
    Prompt user for download mode with professional styling.
    Returns 'cklb' or 'zip' or None if cancelled.
    """
    options = ["Create CKLB", "Download Zip Only", "Cancel"]
    selected_idx = 0
    while True:
        render_menu(stdscr, "Choose Download Mode", options, selected_idx)
        key = stdscr.getch()
        selected_idx, should_return, should_select = handle_menu_input(key, selected_idx, len(options))
        
        if should_return:
            return None
            
        if should_select:
            if selected_idx == 0:
                return 'cklb'
            elif selected_idx == 1:
                return 'zip'
            else:
                return None

def create_inventory_file_tui(stdscr):
    """
    TUI option to create an inventory file with professional styling.
    Prompts the user for the output inventory filename after selection.
    """
    import curses
    import curses.textpad
    from create_inventory import generate_inventory
    
    show_progress(stdscr, "Scraping STIG catalog...")
    try:
        file_links = fetch_stig_file_links()
    except Exception as e:
        logger.error("Failed to scrape STIG catalog: %s", e, exc_info=True)
        clean_screen(stdscr)
        draw_status_bar(
            stdscr,
            f"Error scraping STIG catalog: {e}. Press any key to return.",
            "error",
        )
        stdscr.refresh()
        stdscr.getch()
        return
    if not file_links:
        clean_screen(stdscr)
        draw_status_bar(stdscr, "No downloadable files found. Press any key to return.", "warning")
        stdscr.refresh()
        stdscr.getch()
        return
    selected = set()
    current_idx = 0
    scroll_offset = 0
    while True:
        render_file_list(stdscr, "Select Files for Inventory", file_links, selected, current_idx, scroll_offset)
        
        height = stdscr.getmaxyx()[0]
        max_lines = height - 10
        if current_idx < scroll_offset:
            scroll_offset = current_idx
        elif current_idx >= scroll_offset + max_lines:
            scroll_offset = current_idx - max_lines + 1
        
        key = stdscr.getch()
        if key == curses.KEY_UP:
            current_idx = (current_idx - 1) % len(file_links)
        elif key == curses.KEY_DOWN:
            current_idx = (current_idx + 1) % len(file_links)
        elif key == ord(' '):
            if current_idx in selected:
                selected.remove(current_idx)
            else:
                selected.add(current_idx)
        elif key in [10, 13]:  # ENTER
            to_inventory = selected if selected else {current_idx}
            selected_files = [file_links[idx] for idx in to_inventory]
            # Convert tuples to dicts for generate_inventory
            selected_dicts = [{'FileName': fn, 'URL': url} for fn, url in selected_files]
            # Prompt for filename after selection
            while True:
                clean_screen(stdscr)
                from menu_utils import draw_header, draw_border
                draw_header(stdscr)
                
                # Info box
                info_lines = [
                    "Inventory File Information:",
                    "",
                    f"{CHECKMARK} Selected items and their URLs",
                    f"{CHECKMARK} Item descriptions and categories (if available)",
                    f"{CHECKMARK} Timestamps of last updates (if available)",
                    f"{CHECKMARK} Custom fields (if any)",
                    "",
                    "The file will be saved in JSON format."
                ]
                
                try:
                    for i, line in enumerate(info_lines):
                        stdscr.attron(curses.color_pair(8))
                        stdscr.addstr(5 + i, 2, line)
                        stdscr.attroff(curses.color_pair(8))
                    
                    stdscr.attron(curses.color_pair(3))
                    stdscr.addstr(14, 2, "Enter filename (no extension needed): ")
                    stdscr.attroff(curses.color_pair(3))
                except curses.error:
                    pass
                
                stdscr.refresh()
                curses.echo()
                filename = stdscr.getstr(15, 2, 100).decode("utf-8").strip()
                curses.noecho()
                output_dir = os.path.join("user_docs", "inventory")
                if filename.lower() in ['q', 'quit']:
                    return
                if filename.lower().endswith('.json'):
                    filename = filename[:-5]
                out_path = os.path.join(output_dir, filename + '.json')
                if os.path.exists(out_path):
                    draw_status_bar(stdscr, f"Error: {filename}.json already exists. Press any key to try again or 'q' to quit.", "error")
                    stdscr.refresh()
                    key2 = stdscr.getch()
                    if key2 in [ord('q'), ord('Q')]:
                        return
                    continue
                # Use generate_inventory to write the file
                generate_inventory(selected_dicts, out_path)
                clean_screen(stdscr)
                draw_status_bar(stdscr, f"Inventory file created: {out_path}. Press any key to continue.", "success")
                stdscr.refresh()
                stdscr.getch()
                break
        elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
            return
        elif key in [ord('r'), ord('R')]:
            break  # Refresh file list

def download_options_tui(stdscr):
    """
    Presents download options with professional styling.
    """
    options = ["Select Files From DISA.mil (internet)", "Download Using an Inventory File (internet)", "Back"]
    selected_idx = 0
    while True:
        render_menu(stdscr, "Download Options", options, selected_idx)
        key = stdscr.getch()
        selected_idx, should_return, should_select = handle_menu_input(key, selected_idx, len(options))
        
        if should_return:
            return
            
        if should_select:
            if selected_idx == 0:
                # Warn the user before downloading all files
                confirm_options = ["Yes, Continue", "No, Cancel"]
                confirm_idx = 0
                while True:
                    render_menu(stdscr, "Confirm Download", confirm_options, confirm_idx)
                    draw_status_bar(stdscr, "This will download selected files from the website.", "warning")
                    key2 = stdscr.getch()
                    confirm_idx, should_return2, should_select2 = handle_menu_input(key2, confirm_idx, len(confirm_options))
                    
                    if should_return2 or (should_select2 and confirm_idx == 1):
                        break
                    elif should_select2 and confirm_idx == 0:
                        download_files(stdscr)
                        return
            elif selected_idx == 1:
                download_selected_inventory_tui(stdscr)
                return
            else:
                return

def download_selected_inventory_tui(stdscr):
    """
    TUI option to download the newest available file for each selected technology from an inventory file.
    Prompts for CKLB or Zip download mode.
    """
    import json
    import re
    import curses
    import curses.textpad
    import shutil
    user_docs_dir = os.path.join("user_docs", "inventory")
    zip_dir = os.path.join("user_docs", "zip_files")
    cklb_dir = os.path.join("user_docs", "cklb_new")
    # List inventory files
    inventory_files = [f for f in os.listdir(user_docs_dir) if f.endswith(".json") and os.path.isfile(os.path.join(user_docs_dir, f))]
    if not inventory_files:
        stdscr.clear()
        stdscr.addstr(0, 0, "No inventory files found in user_docs/inventory. Press any key to return.")
        stdscr.refresh()
        stdscr.getch()
        return
    selected_idx = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Select an inventory file:")
        for idx, fname in enumerate(inventory_files):
            if idx == selected_idx:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(idx + 1, 0, f"> {fname}")
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(idx + 1, 0, f"  {fname}")
        stdscr.addstr(len(inventory_files) + 2, 0, "UP/DOWN to select, ENTER to confirm, b/q to cancel")
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected_idx = (selected_idx - 1) % len(inventory_files)
        elif key == curses.KEY_DOWN:
            selected_idx = (selected_idx + 1) % len(inventory_files)
        elif key in [10, 13]:  # ENTER
            break
        elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
            return
    inventory_path = os.path.join(user_docs_dir, inventory_files[selected_idx])
    with open(inventory_path, "r") as f:
        inventory = json.load(f)
    # Extract technologies
    tech_map = {}
    tech_list = []
    for entry in inventory:
        file_name = entry.get('file_name')
        file_url = entry.get('url')
        if not file_name or not file_url:
            continue
        # Match _V#R# pattern
        m = re.search(r"U_([^_]+(?:_[^_]+)*)_V(\d+)[Rr](\d+)", file_name)
        if m:
            tech = m.group(1)
            if tech not in tech_map:
                tech_map[tech] = []
                tech_list.append(tech)
            tech_map[tech].append((file_name, file_url))
            continue
        # Match _Y##M## pattern
        m = re.search(r"U_([^_]+(?:_[^_]+)*)_Y(\d{2})M(\d{2})", file_name)
        if m:
            tech = m.group(1)
            if tech not in tech_map:
                tech_map[tech] = []
                tech_list.append(tech)
            tech_map[tech].append((file_name, file_url))
            continue
    if not tech_list:
        stdscr.clear()
        stdscr.addstr(0, 0, "No technologies found in inventory. Press any key to return.")
        stdscr.refresh()
        stdscr.getch()
        return
    # Select technologies
    selected = set()
    current_idx = 0
    scroll_offset = 0
    status = "SPACE: select, ENTER: download, b/q: back"
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, f"Select technologies to download from {inventory_files[selected_idx]}:")
        max_lines = curses.LINES - 3
        if current_idx < scroll_offset:
            scroll_offset = current_idx
        elif current_idx >= scroll_offset + max_lines:
            scroll_offset = current_idx - max_lines + 1
        visible_techs = tech_list[scroll_offset:scroll_offset + max_lines]
        for vis_idx, tech in enumerate(visible_techs):
            idx = scroll_offset + vis_idx
            sel = "[x]" if idx in selected else "[ ]"
            line = f"{sel} {tech}"
            line = line[:curses.COLS - 4]
            if idx == current_idx:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(vis_idx + 1, 0, f"> {PEAR_ART}{line}")
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(vis_idx + 1, 0, f"  {PEAR_ART}{line}")
        stdscr.addstr(curses.LINES-2, 0, status[:curses.COLS-1])
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            current_idx = (current_idx - 1) % len(tech_list)
        elif key == curses.KEY_DOWN:
            current_idx = (current_idx + 1) % len(tech_list)
        elif key == ord(' '):
            if current_idx in selected:
                selected.remove(current_idx)
            else:
                selected.add(current_idx)
        elif key in [10, 13]:  # ENTER
            to_download = selected if selected else {current_idx}
            # Prompt for download mode
            mode = prompt_download_mode_tui(stdscr)
            if mode is None:
                return
            if mode == 'zip':
                if not os.path.exists(zip_dir):
                    os.makedirs(zip_dir, mode=0o700)
                for idx in to_download:
                    tech = tech_list[idx]
                    files = sorted(tech_map[tech], key=lambda x: x[0], reverse=True)
                    file_name, file_url = files[0]
                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Downloading: {file_name} to zip_files...")
                    stdscr.refresh()
                    # Download to zip_files dir
                    dest_path = os.path.join(zip_dir, file_name)
                    if os.path.exists(dest_path):
                        stdscr.addstr(2, 0, f"File already exists: {file_name}")
                        stdscr.refresh()
                        continue
                    try:
                        # Download to tmp, then move
                        download_file(file_url, file_name)
                        shutil.move(os.path.join("tmp", file_name), dest_path)
                        stdscr.addstr(2, 0, f"Downloaded: {file_name}")
                    except Exception as e:
                        stdscr.addstr(2, 0, f"Download error: {e}")
                    stdscr.refresh()
                stdscr.addstr(4, 0, "Press any key to continue.")
                stdscr.getch()
                return
            elif mode == 'cklb':
                if not os.path.exists(cklb_dir):
                    os.makedirs(cklb_dir, mode=0o700)
                from create_cklb import convert_xccdf_zip_to_cklb
                results = []
                for idx in to_download:
                    tech = tech_list[idx]
                    files = sorted(tech_map[tech], key=lambda x: x[0], reverse=True)
                    file_name, file_url = files[0]
                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Downloading: {file_name} for CKLB conversion...")
                    stdscr.refresh()
                    try:
                        download_file(file_url, file_name)
                        tmp_path = os.path.join("tmp", file_name)
                        cklb_results = convert_xccdf_zip_to_cklb(tmp_path, cklb_dir)
                        for cklb_path, error in cklb_results:
                            if cklb_path:
                                results.append(f"CKLB created: {os.path.basename(cklb_path)}")
                            else:
                                results.append(error or f"Unknown CKLB error for {file_name}")
                    except Exception as e:
                        results.append(f"Download/CKLB error for {file_name}: {e}")
                        print(f"[CKLB ERROR] {e}")
                stdscr.clear()
                stdscr.addstr(0, 0, "CKLB creation results:")
                for i, msg in enumerate(results):
                    stdscr.addstr(i+1, 0, msg[:curses.COLS-1])
                stdscr.addstr(len(results)+2, 0, "Press any key to continue.")
                stdscr.refresh()
                stdscr.getch()
                return
        elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
            return
        elif key in [ord('r'), ord('R')]:
            break  # Refresh file list

def browse_and_select_cklb_files(stdscr, start_dir: Optional[Union[str, Path]] = None, file_label: str = '.cklb', tooltip: Optional[str] = None):
    """
    Professional terminal-based directory browser for selecting files.
    
    Args:
        stdscr: Curses window object
        start_dir: Starting directory path (default: user's home)
        file_label: File extension to filter by
        
    Returns:
        List of selected file paths or None if cancelled
    """
    try:
        if start_dir is None:
            start_dir = Path.home()
        current_dir = Path(start_dir).expanduser().resolve()
        current_dir.mkdir(parents=True, exist_ok=True)
        selected = set()
        current_idx = 0
        scroll_offset = 0
        
        while True:
            try:
                # Get directory entries excluding hidden files
                entries = ['..'] + [
                    entry.name for entry in current_dir.iterdir()
                    if not entry.name.startswith('.') or entry.name == '..'
                ]
                
                files_and_dirs = []
                for entry in sorted(entries):
                    full_path = current_dir / entry
                    try:
                        if full_path.is_dir():
                            files_and_dirs.append((f"{entry}/", full_path, True))
                        elif entry.endswith(file_label):
                            files_and_dirs.append((entry, full_path, False))
                    except (PermissionError, OSError) as e:
                        logger.warning(f"Could not access {full_path}: {e}")
                        continue
                
                # Create a file list compatible with render_file_list
                display_files = [(name, str(path)) for name, path, is_dir in files_and_dirs]
                
                render_file_list(
                    stdscr, 
                    f"Browse: {current_dir}", 
                    display_files, 
                    selected, 
                    current_idx, 
                    scroll_offset
                )
                if tooltip:
                    try:
                        height, width = stdscr.getmaxyx()
                        stdscr.attron(curses.color_pair(8))
                        stdscr.addstr(2, 2, tooltip[:max(0, width - 4)])
                        stdscr.attroff(curses.color_pair(8))
                    except curses.error:
                        pass
                try:
                    stdscr.refresh()
                except curses.error:
                    pass
                
                height = stdscr.getmaxyx()[0]
                max_lines = height - 10
                if current_idx < scroll_offset:
                    scroll_offset = current_idx
                elif current_idx >= scroll_offset + max_lines:
                    scroll_offset = current_idx - max_lines + 1
                
                # Update status bar for file browser
                help_text = "↑↓: Navigate  SPACE: Select File  ENTER: Open Dir/Confirm  Q: Cancel"
                draw_status_bar(stdscr, help_text, "info")
                stdscr.refresh()
                
                key = stdscr.getch()
                
                if key == curses.KEY_UP:
                    current_idx = (current_idx - 1) % len(files_and_dirs)
                elif key == curses.KEY_DOWN:
                    current_idx = (current_idx + 1) % len(files_and_dirs)
                elif key == ord(' '):
                    entry, full_path, is_dir = files_and_dirs[current_idx]
                    if not is_dir:
                        if current_idx in selected:
                            selected.remove(current_idx)
                        else:
                            selected.add(current_idx)
                elif key in [10, 13]:  # ENTER
                    entry, full_path, is_dir = files_and_dirs[current_idx]
                    if is_dir:
                        try:
                            current_dir = full_path.resolve()
                            current_idx = 0
                            scroll_offset = 0
                        except PermissionError as e:
                            logger.error(f"Permission denied accessing {full_path}: {e}")
                            draw_status_bar(stdscr, f"Permission denied: {full_path}", "error")
                            stdscr.refresh()
                            stdscr.getch()
                        except OSError as e:
                            logger.error(f"Error accessing {full_path}: {e}")
                            draw_status_bar(stdscr, f"Error accessing directory: {e}", "error")
                            stdscr.refresh()
                            stdscr.getch()
                    else:
                        if selected:
                            return [str(files_and_dirs[idx][1]) for idx in selected]
                elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
                    return None
                    
            except Exception as e:
                logger.error(f"Error in file browser: {e}", exc_info=True)
                draw_status_bar(stdscr, f"Error: {e}", "error")
                stdscr.refresh()
                stdscr.getch()
                return None
                
    except Exception as e:
        logger.error(f"Critical error in file browser: {e}", exc_info=True)
        draw_status_bar(stdscr, f"Critical error: {e}", "error")
        stdscr.refresh()
        stdscr.getch()
        return None


def manage_answer_file_tui(stdscr):
    """
    TUI flow to inspect and edit CKLB findings for answer file editing (in-memory only).
    """
    import textwrap
    clean_screen(stdscr)
    artifacts_dir = Path("user_docs") / "cklb_artifacts"
    start_dir = artifacts_dir if artifacts_dir.exists() and any(artifacts_dir.iterdir()) else Path.cwd()
    stdscr.addstr(0, 0, "Select a CKLB file to review for Answer File prep:")
    stdscr.refresh()
    selection = browse_and_select_cklb_files(
        stdscr,
        start_dir=start_dir,
        file_label='.cklb',
        tooltip="Navigate directories and select a .cklb to use for answer file prep."
    )
    if not selection:
        return
    cklb_path = selection[0]
    if not validate_file_ext(cklb_path, ['.cklb']):
        show_error_message(stdscr, "Selected file is not a .cklb")
        return

    try:
        cklb_data = load_cklb(cklb_path)
        rules = extract_non_nf_rules(cklb_data)
    except Exception as exc:
        logging.error("Failed to load CKLB for answer file view: %s", exc, exc_info=True)
        show_error_message(stdscr, f"Error loading CKLB: {exc}")
        return

    if not rules:
        clean_screen(stdscr)
        stdscr.addstr(0, 0, "No findings with status of interest (open/not_reviewed/not_a_finding/not_applicable).")
        stdscr.addstr(2, 0, "Press any key to return.")
        stdscr.refresh()
        stdscr.getch()
        return

    allowed_statuses = ["open", "not_a_finding", "not_reviewed", "not_applicable"]

    def build_table_lines(max_width: int):
        # Fixed widths for id/status; remaining space split for text columns
        num_w = 4
        gid_w = 14
        status_w = 16
        padding = 1
        min_width = max(max_width, 70)
        remaining = max(min_width - (num_w + gid_w + status_w + padding * 5), 40)
        text_col_base = max(12, remaining // 3)
        title_w = text_col_base
        fix_w = text_col_base
        comments_w = max(12, remaining - (title_w + fix_w))

        def wrap_field(val: str, width: int) -> list[str]:
            return textwrap.wrap(val or "", width) or [""]

        header = (
            f"{'#'.ljust(num_w)}{' ' * padding}"
            f"{'group_id'.ljust(gid_w)}{' ' * padding}"
            f"{'status'.ljust(status_w)}{' ' * padding}"
            f"{'group_title'.ljust(title_w)}{' ' * padding}"
            f"{'fix_text'.ljust(fix_w)}{' ' * padding}"
            f"{'comments'.ljust(comments_w)}"
        )
        sep = "-" * min(len(header), max_width)

        lines: list[str] = [header[:max_width], sep[:max_width]]
        line_rows: list[int] = [-1, -1]
        row_line_starts: list[int] = []

        # Column spans for highlighting (start inclusive, end exclusive)
        col_spans = {}
        cursor = 0
        col_spans["rownum"] = (cursor, cursor + num_w)
        cursor += num_w + padding
        col_spans["group_id"] = (cursor, cursor + gid_w)
        cursor += gid_w + padding
        col_spans["status"] = (cursor, cursor + status_w)
        cursor += status_w + padding
        col_spans["group_title"] = (cursor, cursor + title_w)
        cursor += title_w + padding
        col_spans["fix_text"] = (cursor, cursor + fix_w)
        cursor += fix_w + padding
        col_spans["comments"] = (cursor, cursor + comments_w)

        for idx, rule in enumerate(rules):
            gid_lines = wrap_field(str(rule.get("group_id", "")), gid_w)
            status_lines = wrap_field(str(rule.get("status", "")), status_w)
            title_lines = wrap_field(str(rule.get("group_title", "")), title_w)
            fix_lines = wrap_field(str(rule.get("fix_text", "")), fix_w)
            comment_lines = wrap_field(str(rule.get("comments", "")), comments_w)
            max_lines = max(len(gid_lines), len(status_lines), len(title_lines), len(fix_lines), len(comment_lines))
            row_line_starts.append(len(lines))
            for line_idx in range(max_lines):
                line = (
                    f"{(str(idx+1) if line_idx == 0 else '').ljust(num_w)}{' ' * padding}"
                    f"{(gid_lines[line_idx] if line_idx < len(gid_lines) else '').ljust(gid_w)}{' ' * padding}"
                    f"{(status_lines[line_idx] if line_idx < len(status_lines) else '').ljust(status_w)}{' ' * padding}"
                    f"{(title_lines[line_idx] if line_idx < len(title_lines) else '').ljust(title_w)}{' ' * padding}"
                    f"{(fix_lines[line_idx] if line_idx < len(fix_lines) else '').ljust(fix_w)}{' ' * padding}"
                    f"{(comment_lines[line_idx] if line_idx < len(comment_lines) else '').ljust(comments_w)}"
                )
                lines.append(line[:max_width])
                line_rows.append(idx)
        return lines, line_rows, row_line_starts, col_spans

    def get_cell_screen_pos(row_idx: int, col_name: str, pos: int, row_starts: list[int], col_spans: dict) -> tuple[int, int]:
        if row_idx < 0 or row_idx >= len(row_starts):
            return -1, -1
        line_idx = row_starts[row_idx]
        y = line_idx - pos
        span = col_spans.get(col_name)
        if not span:
            return y, 0
        return y, span[0]

    def edit_inline(col_name: str, current_text: str, pos: int, max_lines: int, row_starts: list[int], col_spans: dict) -> tuple[str | None, int]:
        # Ensure the row is visible
        target_pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))
        if target_pos != pos:
            pos = target_pos
        y, x = get_cell_screen_pos(current_row, col_name, pos, row_starts, col_spans)
        width_lim = col_spans[col_name][1] - col_spans[col_name][0] - 1
        buf = list(current_text or "")
        cursor = min(len(buf), width_lim)
        curses.curs_set(1)
        while True:
            try:
                # Rewrite the cell contents inline
                display = "".join(buf)[:width_lim]
                stdscr.addstr(y, x, " " * width_lim)
                stdscr.addstr(y, x, display)
                stdscr.move(y, x + cursor)
                stdscr.refresh()
            except curses.error:
                pass
            ch = stdscr.getch()
            if ch in (10, 13):  # Enter
                curses.curs_set(0)
                return "".join(buf), pos
            if ch == 27:  # ESC
                curses.curs_set(0)
                return None, pos
            if ch in (curses.KEY_BACKSPACE, 127, 8):
                if cursor > 0:
                    buf.pop(cursor - 1)
                    cursor -= 1
                continue
            if ch in (curses.KEY_LEFT,):
                if cursor > 0:
                    cursor -= 1
                continue
            if ch in (curses.KEY_RIGHT,):
                if cursor < min(len(buf), width_lim):
                    cursor += 1
                continue
            if 32 <= ch <= 126:
                if len(buf) < 1000:
                    if cursor >= len(buf):
                        buf.append(chr(ch))
                    else:
                        buf.insert(cursor, chr(ch))
                    if cursor < width_lim - 1:
                        cursor += 1
                continue

    def ensure_row_visible(row_idx: int, pos: int, max_lines: int, row_starts: list[int], total_lines: int) -> int:
        if row_idx < 0 or row_idx >= len(row_starts):
            return pos
        start = row_starts[row_idx]
        next_start = row_starts[row_idx + 1] if row_idx + 1 < len(row_starts) else total_lines
        end = next_start - 1
        if start < pos:
            return start
        if end >= pos + max_lines:
            return max(0, end - max_lines + 1)
        return pos

    def prompt_goto_row():
        prompt = "Goto row #: "
        draw_status_bar(stdscr, prompt, "info")
        curses.echo()
        try:
            inp = stdscr.getstr(curses.LINES - 1, len(prompt) + 1, 10)
            try:
                val = int(inp.decode().strip())
                return val
            except Exception:
                return None
        finally:
            curses.noecho()

    def select_status_dropdown(current_status: str, pos: int, max_lines: int, row_starts: list[int], col_spans: dict):
        # Ensure visibility
        target_pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))
        if target_pos != pos:
            pos = target_pos
        y, x = get_cell_screen_pos(current_row, "status", pos, row_starts, col_spans)
        current_lower = (current_status or "").lower()
        sel = allowed_statuses.index(current_lower) if current_lower in allowed_statuses else 0

        win_height = len(allowed_statuses) + 2
        max_opt_len = max(len(s) for s in allowed_statuses)
        win_width = max_opt_len + 4
        # Position dropdown just below the cell, fallback upwards if no space
        win_y = y + 1
        if win_y + win_height >= curses.LINES:
            win_y = max(0, y - win_height)
        win_x = x
        if win_x + win_width >= curses.COLS:
            win_x = max(0, curses.COLS - win_width - 1)
        try:
            curses.curs_set(0)
        except curses.error:
            pass

        win = curses.newwin(win_height, win_width, win_y, win_x)
        try:
            win.keypad(True)
        except Exception:
            pass
        try:
            win.timeout(150)  # allow reading escape sequences for arrows
        except Exception:
            pass
        try:
            win.bkgd(' ', curses.color_pair(0))
        except curses.error:
            pass
        while True:
            try:
                win.clear()
                win.border()
                for idx, opt in enumerate(allowed_statuses):
                    attr = curses.A_REVERSE if idx == sel else curses.A_NORMAL
                    win.addstr(1 + idx, 2, opt.ljust(max_opt_len), attr)
                win.refresh()
            except curses.error:
                pass
            ch = win.getch()
            if ch in (curses.KEY_UP, ord('k')):
                sel = (sel - 1) % len(allowed_statuses)
            elif ch in (curses.KEY_DOWN, ord('j')):
                sel = (sel + 1) % len(allowed_statuses)
            elif ch == 27:  # handle escape or CSI arrow sequences
                nxt = win.getch()
                if nxt == -1:
                    try:
                        curses.curs_set(1)
                    except curses.error:
                        pass
                    return None, pos
                if nxt == 91:  # '['
                    third = win.getch()
                    if third in (65,):  # 'A' up
                        sel = (sel - 1) % len(allowed_statuses)
                        continue
                    if third in (66,):  # 'B' down
                        sel = (sel + 1) % len(allowed_statuses)
                        continue
                # otherwise treat as cancel
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass
                return None, pos
            elif ch in (10, 13):
                try:
                    curses.curs_set(1)
                except curses.error:
                    pass
                return allowed_statuses[sel], pos

    def edit_comments_inline(current_text: str, pos: int, max_lines: int, row_starts: list[int], col_spans: dict):
        val, new_pos = edit_inline("comments", current_text, pos, max_lines, row_starts, col_spans)
        return val, new_pos

    # Initial render data
    lines, line_rows, row_starts, col_spans = build_table_lines(curses.COLS - 1)
    pos = 0
    current_row = 0
    current_col = "status"  # or "comments"

    try:
        curses.curs_set(1)
    except curses.error:
        pass

    while True:
        try:
            stdscr.bkgd(' ', curses.color_pair(0))
            stdscr.attrset(curses.color_pair(0))
        except curses.error:
            pass
        stdscr.clear()
        max_lines = curses.LINES - 3  # leave room for status bar
        # Render lines with highlight for current row/column
        for i in range(max_lines):
            line_idx = pos + i
            if line_idx >= len(lines):
                break
            line = lines[line_idx]
            row_idx = line_rows[line_idx]
            try:
                if row_idx == current_row:
                    stdscr.attron(curses.A_BOLD)
                    stdscr.addstr(i, 0, line[:curses.COLS-1])
                    stdscr.attroff(curses.A_BOLD)
                    span = col_spans.get(current_col)
                    if span:
                        start, end = span
                        width_lim = curses.COLS - 1
                        if start < width_lim:
                            seg = line[start:min(end, width_lim)]
                            stdscr.attron(curses.color_pair(4) | curses.A_BOLD)
                            stdscr.addstr(i, start, seg)
                            stdscr.attroff(curses.color_pair(4) | curses.A_BOLD)
                else:
                    stdscr.addstr(i, 0, line[:curses.COLS-1])
            except curses.error:
                pass

        # Place cursor at active cell start if visible
        cy, cx = get_cell_screen_pos(current_row, current_col, pos, row_starts, col_spans)
        if 0 <= cy < max_lines and cx < curses.COLS - 1 and cy >= 0:
            try:
                stdscr.move(cy, cx)
            except curses.error:
                pass

        status_hint = f"Row {current_row+1}/{len(rules)} | Col: {current_col} | ↑↓ move, ←→ col, g goto, e/Enter edit, q back"
        draw_status_bar(stdscr, status_hint, "info")
        stdscr.refresh()
        key = stdscr.getch()

        if key in [ord('q'), ord('Q'), ord('b'), ord('B')]:
            break
        elif key in [curses.KEY_UP, ord('k')]:
            if current_row > 0:
                current_row -= 1
                pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))
        elif key in [curses.KEY_DOWN, ord('j')]:
            if current_row < len(rules) - 1:
                current_row += 1
                pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))
        elif key in [curses.KEY_LEFT, ord('h')]:
            current_col = "status" if current_col == "comments" else "status"
        elif key in [curses.KEY_RIGHT, ord('l')]:
            current_col = "comments" if current_col == "status" else "comments"
        elif key in [ord('g')]:
            target = prompt_goto_row()
            if target is not None and 1 <= target <= len(rules):
                current_row = target - 1
                pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))
            else:
                draw_status_bar(stdscr, "Invalid row number.", "error")
                stdscr.refresh()
                curses.napms(600)
        elif key in [ord('e'), 10, 13]:
            if current_col == "status":
                new_status, pos = select_status_dropdown(rules[current_row].get("status", ""), pos, max_lines, row_starts, col_spans)
                if new_status:
                    rules[current_row]["status"] = new_status
                    lines, line_rows, row_starts, col_spans = build_table_lines(curses.COLS - 1)
                    pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))
            else:
                new_comment, pos = edit_comments_inline(rules[current_row].get("comments", ""), pos, max_lines, row_starts, col_spans)
                if new_comment is not None:
                    rules[current_row]["comments"] = new_comment
                    lines, line_rows, row_starts, col_spans = build_table_lines(curses.COLS - 1)
                    pos = ensure_row_visible(current_row, pos, max_lines, row_starts, len(lines))

def automatic_cklb_library_update_tui(stdscr):
    """
    Automatic CKLB Library Update: Inventory CKLBs, check for newer STIGs, download, upgrade, log, and show new rules.
    """
    import os, json, re, logging
    from datetime import datetime
    import shutil
    # Ensure log dir exists
    os.makedirs("logs", exist_ok=True)
    log_path = os.path.join("logs", "fullauto.log")
    logger = logging.getLogger("fullauto")
    logger.setLevel(logging.INFO)
    # Remove all handlers associated with the logger object (to avoid duplicate logs)
    if logger.hasHandlers():
        logger.handlers.clear()
    file_handler = logging.FileHandler(log_path, mode='a')
    formatter = logging.Formatter('[%(asctime)s] %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    # Step 1: Select directory/files
    cklb_dir = os.path.join("user_docs", "cklb_artifacts")
    stdscr.clear()
    stdscr.addstr(0, 0, "Automatic CKLB Library Update\nSelect CKLB files or directory (ENTER for default: cklb_artifacts)")
    stdscr.addstr(2, 0, f"Default: {cklb_dir}")
    stdscr.addstr(3, 0, "Press ENTER to use default, SPACE to select files, or 'q' to cancel.")
    stdscr.refresh()
    key = stdscr.getch()
    if key == ord('q') or key == ord('Q'):
        return
    if key == ord(' '):
        from tui import browse_and_select_cklb_files
        selected = browse_and_select_cklb_files(stdscr, start_dir=cklb_dir, file_label='.cklb')
        if not selected:
            return
        cklb_files = selected
    else:
        cklb_files = [os.path.join(cklb_dir, f) for f in os.listdir(cklb_dir) if f.endswith('.cklb')]
    # Step 2: Inventory local CKLBs
    local_stigs = {}  # stig_id -> list of (version:int, release:int, file)
    debug_lines = []
    debug_lines.append("[DEBUG] Starting local CKLB inventory...")
    def safe_int(val):
        try:
            return int(val)
        except Exception:
            return 0
    def normalize_stig_id(stig_id):
        return stig_id[:-5] if stig_id and stig_id.endswith('_STIG') else stig_id
    for f in cklb_files:
        try:
            with open(f, 'r') as ck:
                data = json.load(ck)
            if 'stigs' in data and data['stigs']:
                stig = data['stigs'][0]
                stig_id = stig.get('stig_id')
                version = stig.get('version')
                release = None
                relinfo = stig.get('release_info', '')
                m = re.search(r'Release:\s*(\d+)', relinfo)
                if m:
                    release = m.group(1)
                v = safe_int(version)
                r = safe_int(release)
                norm_stig_id = normalize_stig_id(stig_id)
                debug_lines.append(f"[DEBUG] Found local CKLB: {os.path.basename(f)} stig_id={stig_id} (norm={norm_stig_id}) version={v} release={r}")
                if norm_stig_id:
                    if norm_stig_id not in local_stigs:
                        local_stigs[norm_stig_id] = []
                    local_stigs[norm_stig_id].append((v, r, f))
        except Exception as e:
            debug_lines.append(f"[DEBUG] [ERROR] Could not parse {f}: {e}")
    # Step 3: Scrape website for available STIGs
    stdscr.clear()
    stdscr.addstr(0, 0, "Fetching available STIGs from website...")
    stdscr.refresh()
    try:
        file_links = fetch_stig_file_links()
    except Exception as e:
        logger.error("Failed to scrape STIG catalog: %s", e, exc_info=True)
        stdscr.addstr(2, 0, f"Error scraping STIG catalog: {e}. Press any key to return.")
        stdscr.refresh()
        stdscr.getch()
        return
    # Build available_stigs: stig_id -> list of (version:int, release:int, file_name, url)
    available_stigs = {}
    debug_lines.append("[DEBUG] Parsing available STIGs from website...")
    for file_name, file_url in file_links:
        m = re.search(r'U_([^_]+(?:_[^_]+)*)_V(\d+)[Rr](\d+)', file_name)
        if m:
            stig_id = m.group(1)
            version = safe_int(m.group(2))
            release = safe_int(m.group(3))
            debug_lines.append(f"[DEBUG] Website STIG: {file_name} stig_id={stig_id} version={version} release={release}")
            if stig_id not in available_stigs:
                available_stigs[stig_id] = []
            available_stigs[stig_id].append((version, release, file_name, file_url))
    # Step 4: For each local STIG, check for newer version
    to_update = []  # (stig_id, version, release, file_name, url, local_cklbs)
    debug_lines.append("[DEBUG] Comparing local CKLBs to website STIGs...")
    for stig_id, cklb_list in local_stigs.items():
        if stig_id in available_stigs:
            # Find the highest available version/release
            avail = sorted(available_stigs[stig_id], key=lambda x: (x[0], x[1]), reverse=True)
            top = avail[0]
            for v, r, f in cklb_list:
                debug_lines.append(f"[DEBUG] Compare: {stig_id} local v{v}r{r} vs website v{top[0]}r{top[1]}")
                if (top[0], top[1]) > (v, r):
                    debug_lines.append(f"[DEBUG] Update needed for {stig_id}: website v{top[0]}r{top[1]} > local v{v}r{r} ({os.path.basename(f)})")
                    to_update.append((stig_id, top[0], top[1], top[2], top[3], f))
                else:
                    debug_lines.append(f"[DEBUG] No update needed for {stig_id} ({os.path.basename(f)})")
        else:
            debug_lines.append(f"[DEBUG] No website STIG found for local {stig_id}")
    # Step 5: Download, create CKLB, and upgrade
    saved_files = []
    new_rules_by_stig = {}
    cklb_new_dir = os.path.join("user_docs", "cklb_new")
    cklb_updated_dir = os.path.join("user_docs", "cklb_updated")
    os.makedirs(cklb_new_dir, exist_ok=True)
    os.makedirs(cklb_updated_dir, exist_ok=True)
    # Download and convert each unique (stig_id, version, release, file_name, url) only once
    downloaded_cklbs = {}
    summary_by_stig = {}
    for stig_id, ver, rel, file_name, file_url, local_file in to_update:
        stdscr.clear()
        stdscr.addstr(0, 0, f"Downloading {file_name}...")
        stdscr.refresh()
        # Remove nodelay and 'q' check here
        try:
            if (stig_id, ver, rel) not in downloaded_cklbs:
                download_file(file_url, file_name)
                zip_path = os.path.join("tmp", file_name)
                cklb_results = convert_xccdf_zip_to_cklb(zip_path, cklb_new_dir)
                cklb_path = None
                for cpath, error in cklb_results:
                    if cpath:
                        cklb_path = cpath
                        break
                if not cklb_path:
                    logger.info(f"[ERROR] Could not convert {file_name} to CKLB")
                    continue
                downloaded_cklbs[(stig_id, ver, rel)] = cklb_path
            else:
                cklb_path = downloaded_cklbs[(stig_id, ver, rel)]
            from cklb_handler import compare_cklb_versions, upgrade_cklb_no_edit
            diff = compare_cklb_versions([local_file], cklb_path)
            # --- Perform actual upgrade/merge (no edit) using upgrade_cklb_no_edit ---
            updated_cklb_dir = os.path.join("user_docs", "cklb_updated")
            os.makedirs(updated_cklb_dir, exist_ok=True)
            try:
                out_path = upgrade_cklb_no_edit(local_file, cklb_path, updated_cklb_dir, None)
                logger.info(f"[UPGRADE] Saved upgraded CKLB: {out_path}")
            except Exception as e:
                logger.info(f"[ERROR] Could not upgrade {local_file}: {e}")
                summary_by_stig[(stig_id, ver, rel)] = {
                    'error': str(e)
                }
                continue
            # --- Summary output logic (unchanged) ---
            import json
            with open(local_file, 'r') as f:
                cklb_a = json.load(f)
            with open(cklb_path, 'r') as f:
                cklb_b = json.load(f)
            def get_rules(cklb):
                if 'stigs' in cklb and isinstance(cklb['stigs'], list) and cklb['stigs']:
                    stig = cklb['stigs'][0]
                    return stig.get('rules', [])
                for key in ['rules', 'Rules', 'stig_rules', 'stigRules']:
                    if key in cklb:
                        return cklb[key]
                for v in cklb.values():
                    if isinstance(v, list) and v and isinstance(v[0], dict) and 'rule_id' in v[0]:
                        return v
                return []
            def rule_key(rule):
                val = rule.get('rule_id') or rule.get('id') or rule.get('Rule_ID')
                if val:
                    import re
                    m = re.match(r'(SV-\d+)', val)
                    if m:
                        return m.group(1)
                return val
            rules_a = {rule_key(r): r for r in get_rules(cklb_a)}
            rules_b = {rule_key(r): r for r in get_rules(cklb_b)}
            # New rules: in B not in A
            new_rules = []
            for rk, rule in rules_b.items():
                if rk not in rules_a:
                    new_rules.append(rule)
            # Old rules: in A not in B
            old_rules = []
            for rk, rule in rules_a.items():
                if rk not in rules_b:
                    old_rules.append(rule)
            # Deduplicate by (rule_id, rule_title)
            seen_new = set()
            unique_new = []
            for rule in new_rules:
                key = (rule.get('rule_id',''), rule.get('rule_title',''))
                if key not in seen_new:
                    seen_new.add(key)
                    unique_new.append(rule)
            seen_old = set()
            unique_old = []
            for rule in old_rules:
                key = (rule.get('rule_id',''), rule.get('rule_title',''))
                if key not in seen_old:
                    seen_old.add(key)
                    unique_old.append(rule)
            summary_by_stig[(stig_id, ver, rel)] = {
                'unique_new': unique_new,
                'unique_old': unique_old
            }
        except Exception as e:
            summary_by_stig[(stig_id, ver, rel)] = {
                'error': str(e)
            }
        # Remove 'Press q to cancel' and getch after each file
    # --- Show summary in a scrollable terminal window ---
    stdscr.clear()
    lines = []
    lines.append("Automatic CKLB Library Update Summary:")
    if not summary_by_stig:
        lines.append("No upgrades were performed.")
    else:
        for (stig_id, ver, rel), result in summary_by_stig.items():
            header = f"{stig_id} version {ver} release {rel}"
            lines.append(header)
            if 'error' in result:
                lines.append(f"  [ERROR] Could not load CKLBs: {result['error']}")
                continue
            lines.append("  New Rules Found:")
            if result['unique_new']:
                for rule in result['unique_new']:
                    rule_id = rule.get('rule_id','')
                    rule_title = rule.get('rule_title','')
                    out_line = f"{stig_id}, {rule_id}, {rule_title}"
                    wrapped = textwrap.wrap(out_line, width=max(10, curses.COLS - 8))
                    for wline in wrapped:
                        lines.append(f"    {wline}")
            else:
                lines.append("    (none)")
            lines.append("  Old Rules Not Used:")
            if result['unique_old']:
                for rule in result['unique_old']:
                    rule_id = rule.get('rule_id','')
                    rule_title = rule.get('rule_title','')
                    out_line = f"{stig_id}, {rule_id}, {rule_title}"
                    wrapped = textwrap.wrap(out_line, width=max(10, curses.COLS - 8))
                    for wline in wrapped:
                        lines.append(f"    {wline}")
            else:
                lines.append("    (none)")
            lines.append("")
    # Scrollable output
    pos = 0
    while True:
        stdscr.clear()
        max_lines = curses.LINES - 2
        for i in range(max_lines):
            if pos + i < len(lines):
                stdscr.addstr(i, 0, lines[pos + i][:curses.COLS-1])
        stdscr.addstr(curses.LINES-1, 0, "UP/DOWN: scroll, q: quit"[:curses.COLS-1])
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            if pos > 0:
                pos -= 1
        elif key == curses.KEY_DOWN:
            if pos + max_lines < len(lines):
                pos += 1
        elif key in [ord('q'), ord('Q')]:
            break

def import_cklbs_tui(stdscr):
    """
    TUI for importing one or more CKLB files into user_docs/cklb_artifacts.
    After import, refresh and show the list of imported files in cklb_artifacts.
    """
    import os
    from cklb_handler import import_cklbs
    stdscr.clear()
    stdscr.addstr(0, 0, "Select CKLB files to import:")
    stdscr.refresh()
    files = browse_and_select_cklb_files(stdscr, start_dir=os.path.expanduser("~"), file_label='.cklb')
    if not files:
        return
    dest_dir = os.path.join("user_docs", "cklb_artifacts")
    os.makedirs(dest_dir, exist_ok=True)
    results = import_cklbs(files, dest_dir)
    stdscr.clear()
    stdscr.addstr(0, 0, "Import Results:")
    for i, (fname, status) in enumerate(results):
        stdscr.addstr(i+1, 0, f"{os.path.basename(fname)}: {status}"[:curses.COLS-1])
    stdscr.addstr(len(results)+2, 0, "Press any key to view imported files.")
    stdscr.refresh()
    stdscr.getch()
    # --- Show imported files in cklb_artifacts directory ---
    artifact_files = [f for f in os.listdir(dest_dir) if f.endswith('.cklb')]
    artifact_files.sort()
    pos = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, f"CKLB Artifacts in {dest_dir}:")
        max_lines = curses.LINES - 2
        for i in range(max_lines):
            if pos + i < len(artifact_files):
                stdscr.addstr(i+1, 0, artifact_files[pos + i][:curses.COLS-1])
        stdscr.addstr(curses.LINES-1, 0, "UP/DOWN: scroll, q: quit"[:curses.COLS-1])
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            if pos > 0:
                pos -= 1
        elif key == curses.KEY_DOWN:
            if pos + max_lines < len(artifact_files):
                pos += 1
        elif key in [ord('q'), ord('Q')]:
            break

def compare_cklb_versions_tui(stdscr):
    """
    TUI for comparing one or more CKLB files to a target CKLB file.
    """
    import os
    from cklb_handler import compare_cklb_versions
    stdscr.clear()
    stdscr.addstr(0, 0, "Compare CKLB Versions")
    stdscr.addstr(2, 0, "This feature compares rules differences between two checklists.\nPlease select a checklist to compare.")
    stdscr.addstr(5, 0, "Press any key to continue.")
    stdscr.refresh()
    stdscr.getch()
    stdscr.clear()
    stdscr.addstr(0, 0, "Select one or more CKLB files to compare (A):")
    stdscr.refresh()
    files_a = browse_and_select_cklb_files(stdscr, start_dir=os.path.join("user_docs", "cklb_artifacts"), file_label='.cklb')
    if not files_a:
        return
    stdscr.clear()
    stdscr.addstr(0, 0, "Select a CKLB file to compare to (B):")
    stdscr.refresh()
    files_b = browse_and_select_cklb_files(stdscr, start_dir=os.path.join("user_docs", "cklb_new"), file_label='.cklb')
    if not files_b or len(files_b) != 1:
        stdscr.clear()
        stdscr.addstr(0, 0, "You must select exactly one CKLB file to compare to. Press any key to return.")
        stdscr.refresh()
        stdscr.getch()
        return
    file_b = files_b[0]
    result = compare_cklb_versions(files_a, file_b)
    # Scrollable output
    lines = result.split('\n')
    pos = 0
    while True:
        stdscr.clear()
        max_lines = curses.LINES - 2
        for i in range(max_lines):
            if pos + i < len(lines):
                stdscr.addstr(i, 0, lines[pos + i][:curses.COLS-1])
        stdscr.addstr(curses.LINES-1, 0, "UP/DOWN: scroll, q: quit"[:curses.COLS-1])
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            if pos > 0:
                pos -= 1
        elif key == curses.KEY_DOWN:
            if pos + max_lines < len(lines):
                pos += 1
        elif key in [ord('q'), ord('Q')]:
            break

def manage_checklists_tui(stdscr):
    """
    Professional manage checklists submenu.
    """
    from cklb_handler import upgrade_cklbs_no_edit_tui, upgrade_cklbs_answer_tui
    
    submenu = [
        "Import CKLB(s)",
        "Compare CKLB Versions", 
        "Upgrade CKLB(s)",
        "Compare Findings",
        "Back"
    ]
    
    upgrade_submenu = [
        "Upgrade No Edit",
        "Upgrade and Answer",
        "Back"
    ]
    
    actions = {
        "Import CKLB(s)": import_cklbs_tui,
        "Compare CKLB Versions": compare_cklb_versions_tui,
        "Compare Findings": lambda x: show_not_implemented(x, "Compare Findings")
    }
    
    selected_idx = 0
    while True:
        try:
            render_menu(stdscr, "Manage Checklists", submenu, selected_idx)
            key = stdscr.getch()
            selected_idx, should_return, should_select = handle_menu_input(key, selected_idx, len(submenu))
            
            if should_return:
                break
                
            if should_select:
                option = submenu[selected_idx]
                if option == "Back":
                    break
                elif option == "Upgrade CKLB(s)":
                    handle_upgrade_submenu(stdscr, upgrade_submenu)
                else:
                    action = actions.get(option)
                    if action:
                        action(stdscr)
                    
        except Exception as e:
            logging.error(f"Error in manage_checklists_tui: {e}", exc_info=True)
            show_error_message(stdscr, f"An error occurred: {e}")

def handle_upgrade_submenu(stdscr, upgrade_submenu):
    """Handle the upgrade submenu with professional styling."""
    from cklb_handler import upgrade_cklbs_no_edit_tui, upgrade_cklbs_answer_tui
    
    actions = {
        "Upgrade No Edit": upgrade_cklbs_no_edit_tui,
        "Upgrade and Answer": upgrade_cklbs_answer_tui
    }
    
    selected_idx = 0
    while True:
        try:
            render_menu(stdscr, "Upgrade CKLB Options", upgrade_submenu, selected_idx)
            key = stdscr.getch()
            selected_idx, should_return, should_select = handle_menu_input(key, selected_idx, len(upgrade_submenu))
            
            if should_return:
                break
                
            if should_select:
                option = upgrade_submenu[selected_idx]
                if option == "Back":
                    break
                    
                action = actions.get(option)
                if action:
                    action(stdscr)
                    
        except Exception as e:
            logging.error(f"Error in handle_upgrade_submenu: {e}", exc_info=True)
            show_error_message(stdscr, f"An error occurred: {e}")

def show_error_message(stdscr, message):
    """Display a professional error message and wait for user input."""
    clean_screen(stdscr)
    from menu_utils import draw_header, draw_border
    
    draw_header(stdscr)
    height, width = stdscr.getmaxyx()
    
    # Error box
    box_width = min(width - 10, 60)
    box_height = 8
    box_x = (width - box_width) // 2
    box_y = height // 2 - 4
    
    try:
        draw_border(stdscr, box_y, box_x, box_height, box_width)
        
        # Error title
        stdscr.attron(curses.color_pair(5) | curses.A_BOLD)
        error_title = f"{CROSS_MARK} Error"
        title_x = box_x + (box_width - len(error_title)) // 2
        stdscr.addstr(box_y + 2, title_x, error_title)
        stdscr.attroff(curses.color_pair(5) | curses.A_BOLD)
        
        # Error message (wrap if needed)
        import textwrap
        wrapped_msg = textwrap.wrap(message, box_width - 4)
        for i, line in enumerate(wrapped_msg[:3]):  # Max 3 lines
            stdscr.attron(curses.color_pair(8))
            msg_x = box_x + 2
            stdscr.addstr(box_y + 4 + i, msg_x, line)
            stdscr.attroff(curses.color_pair(8))
    except curses.error:
        pass
    
    draw_status_bar(stdscr, "Press any key to continue...", "error")
    stdscr.refresh()
    stdscr.getch()

def show_not_implemented(stdscr, feature):
    """Display a professional not implemented message."""
    clean_screen(stdscr)
    from menu_utils import draw_header, draw_border
    
    draw_header(stdscr)
    height, width = stdscr.getmaxyx()
    
    # Info box
    box_width = min(width - 10, 50)
    box_height = 6
    box_x = (width - box_width) // 2
    box_y = height // 2 - 3
    
    try:
        draw_border(stdscr, box_y, box_x, box_height, box_width)
        
        # Title
        stdscr.attron(curses.color_pair(7) | curses.A_BOLD)
        title = "Feature Coming Soon"
        title_x = box_x + (box_width - len(title)) // 2
        stdscr.addstr(box_y + 2, title_x, title)
        stdscr.attroff(curses.color_pair(7) | curses.A_BOLD)
        
        # Message
        stdscr.attron(curses.color_pair(8))
        msg = f"{feature} is not yet implemented"
        msg_x = box_x + (box_width - len(msg)) // 2
        stdscr.addstr(box_y + 4, msg_x, msg)
        stdscr.attroff(curses.color_pair(8))
    except curses.error:
        pass
    
    draw_status_bar(stdscr, "Press any key to return...", "warning")
    stdscr.refresh()
    stdscr.getch()

def main(stdscr):
    # Initialize professional color scheme
    curses.start_color()
    curses.use_default_colors()
    
    # Color pairs for professional appearance
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)      # Selected item
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLUE)      # Status bar
    curses.init_pair(3, curses.COLOR_YELLOW, -1)                   # Headers/titles
    curses.init_pair(4, curses.COLOR_CYAN, -1)                     # Subtitles
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_RED)       # Error status
    curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_GREEN)     # Success status
    curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_YELLOW)    # Warning status
    curses.init_pair(8, curses.COLOR_WHITE, -1)                    # Normal text
    
    selected_idx = 0
    while True:
        draw_menu(stdscr, selected_idx)
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected_idx = (selected_idx - 1) % len(FUNCTIONS)
        elif key == curses.KEY_DOWN:
            selected_idx = (selected_idx + 1) % len(FUNCTIONS)
        elif key in [10, 13]:  # ENTER
            func_name = list(FUNCTIONS.values())[selected_idx]
            func = globals().get(func_name)
            if func:
                func(stdscr)
        elif key in [ord('q'), ord('Q')]:
            break

if __name__ == "__main__":
    curses.wrapper(main)
