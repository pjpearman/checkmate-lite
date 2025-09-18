from pathlib import Path
import logging
import os
import shutil
import json
import random
import string
import re
import curses

def ensure_discussion_field(rules: list[dict]) -> list[dict]:
    """
    Ensure every rule in the list has a 'discussion' field.
    """
    for rule in rules:
        if 'discussion' not in rule:
            rule['discussion'] = ''
    return rules

def import_cklbs(selected_files: list[str], dest_dir: str = None) -> list[tuple[str, str]]:
    """
    Import one or more CKLB files into the specified destination directory.
    If dest_dir is None, defaults to 'user_docs/cklb_artifacts'.
    Returns a list of (filename, status) tuples.
    """
    if dest_dir is None:
        dest_dir = Path("user_docs") / "cklb_artifacts"
    else:
        dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    results: list[tuple[str, str]] = []
    for file_path in selected_files:
        src_path = Path(file_path)
        if not src_path.is_file():
            results.append((str(file_path), "File not found"))
            continue
        dest_path = dest_dir / src_path.name
        try:
            # Ensure discussion field in all rules before copying
            with src_path.open('r', encoding='utf-8') as src_file:
                data = json.load(src_file)
            if 'stigs' in data and isinstance(data['stigs'], list):
                for stig in data['stigs']:
                    if 'rules' in stig and isinstance(stig['rules'], list):
                        ensure_discussion_field(stig['rules'])
            with dest_path.open('w', encoding='utf-8') as dest_file:
                json.dump(data, dest_file, indent=2)
            results.append((str(file_path), "Imported"))
        except Exception as exc:
            logging.error(f"Error importing {file_path}: {exc}")
            results.append((str(file_path), f"Error: {exc}"))
    return results

def compare_cklb_versions(file_a_list: list[str], file_b: str) -> str:
    """
    Compare one or more CKLB files (A) to a second CKLB file (B).
    Returns a string with highlighted rule and finding differences.
    Ignores comment differences. Only .cklb files are allowed.
    Warns if the STIGs are obviously mismatched (e.g., Redhat vs Windows), using 'stig_id' as the primary property.
    """
    def load_cklb(path: str) -> dict:
        try:
            with Path(path).open('r') as file:
                return json.load(file)
        except Exception as exc:
            logging.error(f"Error loading CKLB file {path}: {exc}")
            return {}
    def get_rules(cklb: dict) -> list[dict]:
        # Try to get rules from common keys
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
    def rule_key(rule: dict) -> str:
        import re
        val = rule.get('rule_id') or rule.get('id') or rule.get('Rule_ID')
        if val:
            match = re.match(r'(SV-\d+)', val)
            if match:
                return match.group(1)
        return val
    def get_stig_id(cklb: dict) -> str | None:
        if 'stigs' in cklb and isinstance(cklb['stigs'], list) and cklb['stigs']:
            stig = cklb['stigs'][0]
            return stig.get('stig_id')
        return cklb.get('stig_id')
    cklb_b = load_cklb(file_b)
    if not cklb_b:
        return f"[ERROR] Could not load CKLB file: {file_b}"
    if 'stigs' in cklb_b and isinstance(cklb_b['stigs'], list):
        for stig in cklb_b['stigs']:
            if 'rules' in stig and isinstance(stig['rules'], list):
                ensure_discussion_field(stig['rules'])
    stig_b = get_stig_id(cklb_b)
    rules_b_list = get_rules(cklb_b)
    rules_b = {rule_key(r): r for r in rules_b_list}
    output: list[str] = []
    for file_a in file_a_list:
        if not file_a.endswith('.cklb') or not file_b.endswith('.cklb'):
            output.append(f"[ERROR] Only .cklb files are supported: {Path(file_a).name} or {Path(file_b).name}")
            continue
        cklb_a = load_cklb(file_a)
        if not cklb_a:
            output.append(f"[ERROR] Could not load CKLB file: {file_a}")
            continue
        if 'stigs' in cklb_a and isinstance(cklb_a['stigs'], list):
            for stig in cklb_a['stigs']:
                if 'rules' in stig and isinstance(stig['rules'], list):
                    ensure_discussion_field(stig['rules'])
        stig_a = get_stig_id(cklb_a)
        if stig_a and stig_b and stig_a != stig_b:
            output.append(f"[ERROR] Mismatched STIG IDs: '{stig_a}' vs '{stig_b}'. Comparison cancelled.")
            continue
        rules_a = {rule_key(r): r for r in get_rules(cklb_a)}
        output.append(f"=== Comparing {Path(file_a).name} to {Path(file_b).name} ===\n")
        all_rule_ids = set(rules_a.keys()) | set(rules_b.keys())
        # Find rules in B but not in A
        new_in_b = [rid for rid in rules_b.keys() if rid not in rules_a]
        TITLE_WIDTH = 70
        def wrap_text(text: str, width: int) -> list[str]:
            import textwrap
            return textwrap.wrap(text, width)
        if new_in_b:
            output.append(f"New rules in {Path(file_b).name} (not in {Path(file_a).name}):")
            output.append(f"{'id':<16} {'rule title'}")
            output.append(f"{'-'*16} {'-'*TITLE_WIDTH}")
            for rid in new_in_b:
                rule = rules_b[rid]
                title = rule.get('rule_title') or rule.get('title') or ''
                wrapped = wrap_text(title, TITLE_WIDTH)
                if wrapped:
                    output.append(f"{rid:<16} {wrapped[0]}")
                    for line in wrapped[1:]:
                        output.append(f"{'':<16} {line}")
                else:
                    output.append(f"{rid:<16} ")
            output.append("")
        # Find rules in A but not in B, and display in same column format
        only_in_a = [rid for rid in rules_a.keys() if rid not in rules_b]
        if only_in_a:
            output.append(f"Rules only in {Path(file_a).name} (not in {Path(file_b).name}):")
            output.append(f"{'id':<16} {'rule title'}")
            output.append(f"{'-'*16} {'-'*TITLE_WIDTH}")
            for rid in only_in_a:
                rule = rules_a[rid]
                title = rule.get('rule_title') or rule.get('title') or ''
                wrapped = wrap_text(title, TITLE_WIDTH)
                if wrapped:
                    output.append(f"{rid:<16} {wrapped[0]}")
                    for line in wrapped[1:]:
                        output.append(f"{'':<16} {line}")
                else:
                    output.append(f"{rid:<16} ")
            output.append("")
        output.append("")

    # If output is too long, page/scroll it in the TUI (if called from tui.py)
    # This is a backend function, so actual scrolling should be handled by the TUI frontend.
    # Return the full string for the TUI to handle paging/scrolling.
    return '\n'.join(output)

def upgrade_cklbs_no_edit_tui(stdscr):
    """
    TUI for upgrading CKLB(s) with no edit. User selects one or more source CKLBs (A), then chooses upgrade source:
    - Download latest from DISA (if available)
    - Select from CKLB library
    """
    import os
    import json
    import shutil
    import curses
    import textwrap
    from tui import browse_and_select_cklb_files
    from web import collect_all_file_links, download_file
    from create_cklb import convert_xccdf_zip_to_cklb
    updated_dir = os.path.join("user_docs", "cklb_updated")
    os.makedirs(updated_dir, exist_ok=True)
    stdscr.clear()
    stdscr.addstr(0, 0, "Select one or more CKLB files to upgrade (A):"[:curses.COLS-1])
    stdscr.refresh()
    files_a = browse_and_select_cklb_files(stdscr, start_dir=os.path.join("user_docs", "cklb_artifacts"), file_label='.cklb')
    if not files_a:
        return
    # Submenu for upgrade source
    options = ["Download the latest version from DISA", "Select from CKLB library", "Back"]
    selected_idx = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Choose upgrade source:")
        for idx, opt in enumerate(options):
            if idx == selected_idx:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(idx+1, 0, f"> {opt}")
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(idx+1, 0, f"  {opt}")
        stdscr.addstr(len(options)+2, 0, "UP/DOWN to select, ENTER to confirm, b/q to cancel")
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected_idx = (selected_idx - 1) % len(options)
        elif key == curses.KEY_DOWN:
            selected_idx = (selected_idx + 1) % len(options)
        elif key in [10, 13]:
            if options[selected_idx] == "Back":
                return
            elif options[selected_idx] == "Download the latest version from DISA":
                # For each selected CKLB, check for newer version online and upgrade if available
                # --- Inventory local CKLBs ---
                local_stigs = {}
                def safe_int(val):
                    try:
                        return int(val)
                    except Exception:
                        return 0
                def normalize_stig_id(stig_id):
                    return stig_id[:-5] if stig_id and stig_id.endswith('_STIG') else stig_id
                for f in files_a:
                    try:
                        with open(f, 'r', encoding='utf-8') as ck:
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
                            if norm_stig_id:
                                if norm_stig_id not in local_stigs:
                                    local_stigs[norm_stig_id] = []
                                local_stigs[norm_stig_id].append((v, r, f))
                    except Exception:
                        continue
                # --- Scrape website for available STIGs ---
                stdscr.clear()
                stdscr.addstr(0, 0, "Fetching available STIGs from website...")
                stdscr.refresh()
                try:
                    file_links = collect_all_file_links()
                except Exception as e:
                    stdscr.addstr(2, 0, f"Error fetching website: {e}. Press any key to return.")
                    stdscr.refresh()
                    stdscr.getch()
                    return
                available_stigs = {}
                for file_name, file_url in file_links:
                    m = re.search(r'U_([^_]+(?:_[^_]+)*)_V(\d+)[Rr](\d+)', file_name)
                    if m:
                        stig_id = m.group(1)
                        version = safe_int(m.group(2))
                        release = safe_int(m.group(3))
                        if stig_id not in available_stigs:
                            available_stigs[stig_id] = []
                        available_stigs[stig_id].append((version, release, file_name, file_url))
                # --- For each local STIG, check for newer version ---
                to_upgrade = []  # (file_a, stig_id, top_version, top_release, file_name, file_url)
                for stig_id, cklb_list in local_stigs.items():
                    if stig_id in available_stigs:
                        avail = sorted(available_stigs[stig_id], key=lambda x: (x[0], x[1]), reverse=True)
                        top = avail[0]
                        for v, r, f in cklb_list:
                            if (top[0], top[1]) > (v, r):
                                to_upgrade.append((f, stig_id, top[0], top[1], top[2], top[3]))
                if not to_upgrade:
                    stdscr.clear()
                    stdscr.addstr(0, 0, "No upgrades available online for selected CKLB(s). Press any key to return.")
                    stdscr.refresh()
                    stdscr.getch()
                    return
                # --- Download, convert, and upgrade ---
                cklb_new_dir = os.path.join("user_docs", "cklb_new")
                os.makedirs(cklb_new_dir, exist_ok=True)
                results = []
                for file_a, stig_id, ver, rel, file_name, file_url in to_upgrade:
                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Downloading {file_name} for upgrade...")
                    stdscr.refresh()
                    try:
                        download_file(file_url, file_name)
                        zip_path = os.path.join("tmp", file_name)
                        cklb_results = convert_xccdf_zip_to_cklb(zip_path, cklb_new_dir)
                        cklb_path = None
                        for cpath, error in cklb_results:
                            if cpath:
                                cklb_path = cpath
                                break
                        if not cklb_path:
                            results.append((file_a, f"[ERROR] Could not convert {file_name} to CKLB"))
                            continue
                        # Now run upgrade (no edit)
                        try:
                            upgrade_cklb_no_edit(file_a, cklb_path, updated_dir, stdscr)
                            results.append((file_a, f"Upgraded (no edit)."))
                        except Exception as e:
                            results.append((file_a, f"[ERROR] Could not upgrade: {e}"))
                    except Exception as e:
                        results.append((file_a, f"[ERROR] Download/convert error: {e}"))
                stdscr.clear()
                stdscr.addstr(0, 0, "Upgrade No Edit results:"[:curses.COLS-1])
                for i, (fname, status) in enumerate(results):
                    stdscr.addstr(i+1, 0, f"{os.path.basename(fname)}: {status}"[:curses.COLS-1])
                stdscr.addstr(len(results)+2, 0, "Press any key to continue."[:curses.COLS-1])
                stdscr.refresh()
                stdscr.getch()
                return
            elif options[selected_idx] == "Select from CKLB library":
                stdscr.clear()
                stdscr.addstr(0, 0, "Select a CKLB file to upgrade to (B):"[:curses.COLS-1])
                stdscr.refresh()
                files_b = browse_and_select_cklb_files(stdscr, start_dir=os.path.join("user_docs", "cklb_new"), file_label='.cklb')
                if not files_b or len(files_b) != 1:
                    stdscr.clear()
                    stdscr.addstr(0, 0, "You must select exactly one CKLB file to upgrade to. Press any key to return."[:curses.COLS-1])
                    stdscr.refresh()
                    stdscr.getch()
                    return
                file_b = files_b[0]
                # Use no-edit logic for upgrade
                results = []
                for file_a in files_a:
                    try:
                        upgrade_cklb_no_edit(file_a, file_b, updated_dir, stdscr)
                        results.append((file_a, f"Upgraded (no edit)."))
                    except Exception as e:
                        results.append((file_a, f"[ERROR] Could not upgrade: {e}"))
                stdscr.clear()
                stdscr.addstr(0, 0, "Upgrade No Edit results:"[:curses.COLS-1])
                for i, (fname, status) in enumerate(results):
                    stdscr.addstr(i+1, 0, f"{os.path.basename(fname)}: {status}"[:curses.COLS-1])
                stdscr.addstr(len(results)+2, 0, "Press any key to continue."[:curses.COLS-1])
                stdscr.refresh()
                stdscr.getch()
                return
        elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
            return


def upgrade_cklbs_answer_tui(stdscr):
    """
    TUI for upgrading CKLB(s) with user input for new rules. User selects one or more source CKLBs (A), then chooses upgrade source:
    - Download latest from DISA (if available)
    - Select from CKLB library
    """
    import os
    import json
    import curses
    import textwrap
    from tui import browse_and_select_cklb_files
    from web import collect_all_file_links, download_file
    from create_cklb import convert_xccdf_zip_to_cklb
    updated_dir = os.path.join("user_docs", "cklb_updated")
    os.makedirs(updated_dir, exist_ok=True)
    stdscr.clear()
    stdscr.addstr(0, 0, "Select one or more CKLB files to upgrade (A):"[:curses.COLS-1])
    stdscr.refresh()
    files_a = browse_and_select_cklb_files(stdscr, start_dir=os.path.join("user_docs", "cklb_artifacts"), file_label='.cklb')
    if not files_a:
        return
    # Submenu for upgrade source
    options = ["Download the latest version from DISA", "Select from CKLB library", "Back"]
    selected_idx = 0
    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "Choose upgrade source:")
        for idx, opt in enumerate(options):
            if idx == selected_idx:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(idx+1, 0, f"> {opt}")
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(idx+1, 0, f"  {opt}")
        stdscr.addstr(len(options)+2, 0, "UP/DOWN to select, ENTER to confirm, b/q to cancel")
        stdscr.refresh()
        key = stdscr.getch()
        if key == curses.KEY_UP:
            selected_idx = (selected_idx - 1) % len(options)
        elif key == curses.KEY_DOWN:
            selected_idx = (selected_idx + 1) % len(options)
        elif key in [10, 13]:
            if options[selected_idx] == "Back":
                return
            elif options[selected_idx] == "Download the latest version from DISA":
                # For each selected CKLB, check for newer version online and upgrade if available
                local_stigs = {}
                def safe_int(val):
                    try:
                        return int(val)
                    except Exception:
                        return 0
                def normalize_stig_id(stig_id):
                    return stig_id[:-5] if stig_id and stig_id.endswith('_STIG') else stig_id
                for f in files_a:
                    try:
                        with open(f, 'r', encoding='utf-8') as ck:
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
                            if norm_stig_id:
                                if norm_stig_id not in local_stigs:
                                    local_stigs[norm_stig_id] = []
                                local_stigs[norm_stig_id].append((v, r, f))
                    except Exception:
                        continue
                # --- Scrape website for available STIGs ---
                stdscr.clear()
                stdscr.addstr(0, 0, "Fetching available STIGs from website...")
                stdscr.refresh()
                try:
                    file_links = collect_all_file_links()
                except Exception as e:
                    stdscr.addstr(2, 0, f"Error fetching website: {e}. Press any key to return.")
                    stdscr.refresh()
                    stdscr.getch()
                    return
                available_stigs = {}
                for file_name, file_url in file_links:
                    m = re.search(r'U_([^_]+(?:_[^_]+)*)_V(\d+)[Rr](\d+)', file_name)
                    if m:
                        stig_id = m.group(1)
                        version = safe_int(m.group(2))
                        release = safe_int(m.group(3))
                        if stig_id not in available_stigs:
                            available_stigs[stig_id] = []
                        available_stigs[stig_id].append((version, release, file_name, file_url))
                # --- For each local STIG, check for newer version ---
                to_upgrade = []  # (file_a, stig_id, top_version, top_release, file_name, file_url)
                for stig_id, cklb_list in local_stigs.items():
                    if stig_id in available_stigs:
                        avail = sorted(available_stigs[stig_id], key=lambda x: (x[0], x[1]), reverse=True)
                        top = avail[0]
                        for v, r, f in cklb_list:
                            if (top[0], top[1]) > (v, r):
                                to_upgrade.append((f, stig_id, top[0], top[1], top[2], top[3]))
                if not to_upgrade:
                    stdscr.clear()
                    stdscr.addstr(0, 0, "No upgrades available online for selected CKLB(s). Press any key to return.")
                    stdscr.refresh()
                    stdscr.getch()
                    return
                # --- Download, convert, and upgrade ---
                cklb_new_dir = os.path.join("user_docs", "cklb_new")
                os.makedirs(cklb_new_dir, exist_ok=True)
                results = []
                for file_a, stig_id, ver, rel, file_name, file_url in to_upgrade:
                    stdscr.clear()
                    stdscr.addstr(0, 0, f"Downloading {file_name} for upgrade...")
                    stdscr.refresh()
                    try:
                        download_file(file_url, file_name)
                        zip_path = os.path.join("tmp", file_name)
                        cklb_results = convert_xccdf_zip_to_cklb(zip_path, cklb_new_dir)
                        cklb_path = None
                        for cpath, error in cklb_results:
                            if cpath:
                                cklb_path = cpath
                                break
                        if not cklb_path:
                            results.append((file_a, f"[ERROR] Could not convert {file_name} to CKLB"))
                            continue
                        # Now run upgrade (with answer prompts)
                        try:
                            upgrade_cklb_answer_prompt(stdscr, file_a, cklb_path, updated_dir)
                            results.append((file_a, f"Upgraded with answers."))
                        except Exception as e:
                            results.append((file_a, f"[ERROR] Could not upgrade: {e}"))
                    except Exception as e:
                        results.append((file_a, f"[ERROR] Download/convert error: {e}"))
                stdscr.clear()
                stdscr.addstr(0, 0, "Upgrade (Edit) results:"[:curses.COLS-1])
                for i, (fname, status) in enumerate(results):
                    stdscr.addstr(i+1, 0, f"{os.path.basename(fname)}: {status}"[:curses.COLS-1])
                stdscr.addstr(len(results)+2, 0, "Press any key to continue."[:curses.COLS-1])
                stdscr.refresh()
                stdscr.getch()
                return
            elif options[selected_idx] == "Select from CKLB library":
                stdscr.clear()
                stdscr.addstr(0, 0, "Select a CKLB file to upgrade to (B):"[:curses.COLS-1])
                stdscr.refresh()
                files_b = browse_and_select_cklb_files(stdscr, start_dir=os.path.join("user_docs", "cklb_new"), file_label='.cklb')
                if not files_b or len(files_b) != 1:
                    stdscr.clear()
                    stdscr.addstr(0, 0, "You must select exactly one CKLB file to upgrade to. Press any key to return."[:curses.COLS-1])
                    stdscr.refresh()
                    stdscr.getch()
                    return
                file_b = files_b[0]
                # Use existing logic for upgrade with answer prompts
                results = []
                for file_a in files_a:
                    try:
                        upgrade_cklb_answer_prompt(stdscr, file_a, file_b, updated_dir)
                        results.append((file_a, f"Upgraded with answers."))
                    except Exception as e:
                        results.append((file_a, f"[ERROR] Could not upgrade: {e}"))
                stdscr.clear()
                stdscr.addstr(0, 0, "Upgrade (Edit) results:"[:curses.COLS-1])
                for i, (fname, status) in enumerate(results):
                    stdscr.addstr(i+1, 0, f"{os.path.basename(fname)}: {status}"[:curses.COLS-1])
                stdscr.addstr(len(results)+2, 0, "Press any key to continue."[:curses.COLS-1])
                stdscr.refresh()
                stdscr.getch()
                return
        elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
            return

def upgrade_cklb_no_edit(file_a, file_b, updated_dir, stdscr=None):
    """
    Upgrade CKLB file_a to the schema/rules of file_b, merging findings/comments/status where possible.
    Returns the output file path.
    """
    import json
    import os
    import re
    from datetime import datetime
    # Load both CKLBs
    with open(file_a, 'r', encoding='utf-8') as f:
        cklb_a = json.load(f)
    with open(file_b, 'r', encoding='utf-8') as f:
        cklb_b = json.load(f)
    # Helper to get rules as dict by rule_id
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
            m = re.match(r'(SV-\d+)', val)
            if m:
                return m.group(1)
        return val
    # Build merged CKLB (start from b, merge findings from a)
    merged = json.loads(json.dumps(cklb_b))
    rules_a = {rule_key(r): r for r in get_rules(cklb_a)}
    if 'stigs' in merged and isinstance(merged['stigs'], list) and merged['stigs']:
        rules_b = merged['stigs'][0].get('rules', [])
    else:
        rules_b = get_rules(merged)
    
    # Identify new and old rules for summary
    rules_b_keys = {rule_key(r) for r in rules_b}
    new_rules = [r for r in rules_b if rule_key(r) not in rules_a]
    old_rules = [r for r in get_rules(cklb_a) if rule_key(r) not in rules_b_keys]
    
    for rule_b in rules_b:
        rk = rule_key(rule_b)
        if rk in rules_a:
            rule_a = rules_a[rk]
            for k in ['comments', 'comment', 'status', 'finding', 'Finding']:
                if k in rule_a:
                    rule_b[k] = rule_a[k]
            if 'comments' in rule_a:
                rule_b['comments'] = rule_a['comments']
    # Copy over target_data if present
    if 'target_data' in cklb_a and isinstance(cklb_a['target_data'], dict):
        merged['target_data'] = cklb_a['target_data']
    # Compose output filename
    stig_id = None
    version = None
    release = None
    if 'stigs' in cklb_b and isinstance(cklb_b['stigs'], list) and cklb_b['stigs']:
        stig = cklb_b['stigs'][0]
        stig_id = stig.get('stig_id', 'unknownstig')
        version = stig.get('version')
        release_info = stig.get('release_info', '')
        m = re.search(r'Release:\s*(\d+)', release_info)
        release = m.group(1) if m else None
    v_str = f"v{version or '0'}r{release or '0'}"
    hostname = None
    if 'target_data' in merged and isinstance(merged['target_data'], dict):
        hostname = merged['target_data'].get('host_name')
    if not hostname:
        import random, string
        hostname = ''.join(random.choices(string.ascii_uppercase, k=8))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{hostname}_{stig_id or 'unknown'}_{v_str}_{timestamp}.cklb"
    out_path = os.path.join(updated_dir, out_name)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2)
    # Show summary of changes (if stdscr is available)
    if stdscr:
        stdscr.clear()
        stdscr.addstr(0, 0, "Upgrade Complete!", curses.A_BOLD)
        stdscr.addstr(1, 0, f"Output file: {os.path.basename(out_path)}")
        stdscr.addstr(2, 0, f"New rules found: {len(new_rules)}")
        stdscr.addstr(3, 0, f"Old rules not included: {len(old_rules)}")
        stdscr.hline(4, 0, '-', 60)
        
        line = 5
        if new_rules:
            stdscr.addstr(line, 0, "NEW RULES:", curses.A_BOLD)
            line += 1
            for rule in new_rules[:min(5, len(new_rules))]:
                rule_title = rule.get('rule_title', rule.get('group_title', ''))[:50]
                rid = rule.get('rule_id', '')[:20]
                stdscr.addstr(line, 0, f"  {rid}: {rule_title}")
                line += 1
                if line >= curses.LINES - 5:
                    break
            if len(new_rules) > 5:
                stdscr.addstr(line, 0, f"  ... and {len(new_rules) - 5} more")
                line += 1
        
        if old_rules and line < curses.LINES - 3:
            line += 1
            stdscr.addstr(line, 0, "OLD RULES NOT INCLUDED:", curses.A_BOLD)
            line += 1
            remaining_lines = min(3, curses.LINES - line - 2)
            for rule in old_rules[:remaining_lines]:
                rule_title = rule.get('rule_title', rule.get('group_title', ''))[:50]
                rid = rule.get('rule_id', '')[:20]
                stdscr.addstr(line, 0, f"  {rid}: {rule_title}")
                line += 1
            if len(old_rules) > remaining_lines:
                stdscr.addstr(line, 0, f"  ... and {len(old_rules) - remaining_lines} more")
        
        stdscr.addstr(curses.LINES-1, 0, "Press any key to continue.")
        stdscr.refresh()
        stdscr.getch()
    return out_path

# Helper for answer mode upgrade (reuses most of the original answer logic)
def upgrade_cklb_answer_prompt(stdscr, file_a, file_b, updated_dir):
    import json
    import os
    import textwrap
    import curses
    with open(file_b, 'r', encoding='utf-8') as f:
        cklb_b = json.load(f)
    stig_id_b = None
    if 'stigs' in cklb_b and isinstance(cklb_b['stigs'], list) and cklb_b['stigs']:
        stig_id_b = cklb_b['stigs'][0].get('stig_id')
    if not stig_id_b:
        stig_id_b = cklb_b.get('stig_id')
    with open(file_a, 'r', encoding='utf-8') as f:
        cklb_a = json.load(f)
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
        import re
        val = rule.get('rule_id') or rule.get('id') or rule.get('Rule_ID')
        if val:
            m = re.match(r'(SV-\d+)', val)
            if m:
                return m.group(1)
        return val
    merged = json.loads(json.dumps(cklb_b))
    rules_a = {rule_key(r): r for r in get_rules(cklb_a)}
    if 'stigs' in merged and isinstance(merged['stigs'], list) and merged['stigs']:
        rules_b = merged['stigs'][0].get('rules', [])
    else:
        rules_b = get_rules(merged)
    new_rules = [r for r in rules_b if rule_key(r) not in rules_a]
    
    # Identify old rules not included for summary
    rules_b_keys = {rule_key(r) for r in rules_b}
    old_rules = [r for r in get_rules(cklb_a) if rule_key(r) not in rules_b_keys]
    host_name = ""
    if 'target_data' in cklb_a and isinstance(cklb_a['target_data'], dict):
        host_name = cklb_a['target_data'].get('host_name', "")
    status_options = ["open", "not_a_finding", "not_applicable", "not_reviewed"]
    user_statuses = [status_options[0] for _ in new_rules]
    user_comments = ["" for _ in new_rules]
    current_rule = 0
    field = 0  # 0 = status, 1 = comments
    abort_job = False
    confirm_submit = False
    while current_rule < len(new_rules):
        rule = new_rules[current_rule]
        while True:
            stdscr.clear()
            max_y, max_x = stdscr.getmaxyx()
            stdscr.addstr(0, 0, f"Answer for new rule {current_rule+1}/{len(new_rules)}:", curses.A_BOLD)
            stdscr.hline(1, 0, '-', max_x)
            stdscr.addstr(2, 0, f"Rule ID: {rule.get('rule_id','')}")
            title = rule.get('rule_title','')
            wrapped_title = textwrap.wrap(title, max_x-10)
            stdscr.addstr(3, 0, "Title: ")
            for i, line in enumerate(wrapped_title):
                stdscr.addstr(3+i, 7, line)
            y = 3 + len(wrapped_title)
            stdscr.hline(y, 0, '-', max_x)
            # Status field
            status_label = f"Status: {user_statuses[current_rule]}"
            if field == 0:
                stdscr.addstr(y+1, 0, status_label, curses.A_REVERSE)
            else:
                stdscr.addstr(y+1, 0, status_label)
            # Comments field
            comment_label = f"Comments: {user_comments[current_rule]}"
            if field == 1:
                stdscr.addstr(y+2, 0, comment_label, curses.A_REVERSE)
            else:
                stdscr.addstr(y+2, 0, comment_label)
            stdscr.hline(y+3, 0, '-', max_x)
            stdscr.addstr(y+4, 0, "UP/DOWN: rule  TAB: next  SHIFT+TAB: prev  LEFT/RIGHT: status  ENTER: edit comment  F2: save  q: abort", curses.A_DIM)
            stdscr.refresh()
            key = stdscr.getch()
            if key == curses.KEY_UP:
                current_rule = (current_rule - 1) % len(new_rules)
                break
            elif key == curses.KEY_DOWN:
                current_rule = (current_rule + 1) % len(new_rules)
                break
            elif key in [9]:  # TAB
                field = (field + 1) % 2
            elif key == 353:  # SHIFT+TAB
                field = (field - 1) % 2
            elif key == curses.KEY_LEFT and field == 0:
                idx = status_options.index(user_statuses[current_rule])
                user_statuses[current_rule] = status_options[(idx - 1) % len(status_options)]
            elif key == curses.KEY_RIGHT and field == 0:
                idx = status_options.index(user_statuses[current_rule])
                user_statuses[current_rule] = status_options[(idx + 1) % len(status_options)]
            elif key in [10, 13] and field == 1:
                # Edit comments
                curses.echo()
                stdscr.move(y+2, 10)
                stdscr.clrtoeol()
                stdscr.addstr(y+2, 10, " ")
                stdscr.refresh()
                comment = stdscr.getstr(y+2, 10, max_x-12).decode('utf-8')
                user_comments[current_rule] = comment
                curses.noecho()
                # After editing, return to navigation mode
                break
            elif key == curses.KEY_F2:
                # Ask for confirmation before saving
                stdscr.clear()
                stdscr.addstr(0, 0, "Submit all answers? (y/n)", curses.A_BOLD)
                stdscr.refresh()
                while True:
                    c = stdscr.getch()
                    if c in [ord('y'), ord('Y')]:
                        confirm_submit = True
                        break
                    elif c in [ord('n'), ord('N')]:
                        confirm_submit = False
                        break
                if confirm_submit:
                    abort_job = False
                    current_rule = len(new_rules)  # break outer loop
                    break
                else:
                    # Return to editing
                    break
            elif key in [ord('q'), ord('Q')]:
                abort_job = True
                break
        if abort_job or confirm_submit:
            break
    if abort_job:
        stdscr.clear()
        stdscr.addstr(0, 0, "Upgrade aborted by user. Press any key to continue.")
        stdscr.refresh()
        stdscr.getch()
        return
    if not confirm_submit:
        return  # User chose not to submit, return to editing
    # Merge answers into new_rules
    for i, rule in enumerate(new_rules):
        rule['status'] = user_statuses[i]
        rule['comments'] = user_comments[i]
    # Merge logic (reuse from no_edit)
    rules_a = {rule_key(r): r for r in get_rules(cklb_a)}
    if 'stigs' in merged and isinstance(merged['stigs'], list) and merged['stigs']:
        rules_b = merged['stigs'][0].get('rules', [])
    else:
        rules_b = get_rules(merged)
    for rule_b in rules_b:
        rk = rule_key(rule_b)
        if rk in rules_a:
            rule_a = rules_a[rk]
            for k in ['comments', 'comment', 'status', 'finding', 'Finding']:
                if k in rule_a:
                    rule_b[k] = rule_a[k]
            if 'comments' in rule_a:
                rule_b['comments'] = rule_a['comments']
    for i, rule in enumerate(new_rules):
        rk = rule_key(rule)
        for rule_b in rules_b:
            if rule_key(rule_b) == rk:
                rule_b['status'] = user_statuses[i]
                rule_b['comments'] = user_comments[i]
    # Target-level data
    for k in ['host', 'Host', 'hostname', 'Hostname']:
        if k in cklb_a:
            merged[k] = cklb_a[k]
    if 'target_data' in cklb_a and isinstance(cklb_a['target_data'], dict):
        if 'target_data' not in merged or not isinstance(merged['target_data'], dict):
            merged['target_data'] = {}
        for tk, tv in cklb_a['target_data'].items():
            merged['target_data'][tk] = tv
    # Filename logic
    hostname = None
    if 'target_data' in merged and isinstance(merged['target_data'], dict):
        hostname = merged['target_data'].get('host_name')
    if not hostname:
        import random, string
        hostname = ''.join(random.choices(string.ascii_uppercase, k=8))
    stig_id = stig_id_b or "unknownstig"
    version = None
    release = None
    if 'stigs' in cklb_b and isinstance(cklb_b['stigs'], list) and cklb_b['stigs']:
        stig = cklb_b['stigs'][0]
        version = stig.get('version')
        release_info = stig.get('release_info', '')
        import re
        m = re.search(r'Release:\s*(\d+)', release_info)
        if m:
            release = m.group(1)
    v_str = f"v{version or '0'}r{release or '0'}"
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_name = f"{hostname}_{stig_id}_{v_str}_{timestamp}.cklb"
    out_path = os.path.join(updated_dir, out_name)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(merged, f, indent=2)
    # Show summary of changes (immediately after saving, using local variables)
    stdscr.clear()
    stdscr.addstr(0, 0, "Upgrade Complete!", curses.A_BOLD)
    stdscr.addstr(1, 0, f"Output file: {os.path.basename(out_path)}")
    stdscr.addstr(2, 0, f"New rules answered: {len(new_rules)}")
    stdscr.addstr(3, 0, f"Old rules not included: {len(old_rules)}")
    stdscr.hline(4, 0, '-', 60)
    
    line = 5
    if new_rules:
        stdscr.addstr(line, 0, "NEW RULES ANSWERED:", curses.A_BOLD)
        line += 1
        for rule in new_rules[:min(5, len(new_rules))]:
            rule_title = rule.get('rule_title', rule.get('group_title', ''))[:45]
            rid = rule.get('rule_id', '')[:20]
            status = rule.get('status', '')
            stdscr.addstr(line, 0, f"  {rid}: {rule_title} [{status}]")
            line += 1
            if line >= curses.LINES - 5:
                break
        if len(new_rules) > 5:
            stdscr.addstr(line, 0, f"  ... and {len(new_rules) - 5} more")
            line += 1
    
    if old_rules and line < curses.LINES - 3:
        line += 1
        stdscr.addstr(line, 0, "OLD RULES NOT INCLUDED:", curses.A_BOLD)
        line += 1
        remaining_lines = min(3, curses.LINES - line - 2)
        for rule in old_rules[:remaining_lines]:
            rule_title = rule.get('rule_title', rule.get('group_title', ''))[:50]
            rid = rule.get('rule_id', '')[:20]
            stdscr.addstr(line, 0, f"  {rid}: {rule_title}")
            line += 1
        if len(old_rules) > remaining_lines:
            stdscr.addstr(line, 0, f"  ... and {len(old_rules) - remaining_lines} more")
    
    stdscr.addstr(curses.LINES-1, 0, "Press any key to continue.")
    stdscr.refresh()
    stdscr.getch()
    return out_path
