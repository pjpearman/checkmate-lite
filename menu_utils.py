"""
Menu utilities for the TUI application.
Contains reusable menu rendering and handling functions with professional styling.
"""

import curses
import textwrap
from config import (
    BORDER_CHAR, VERTICAL_BORDER, CORNER_TL, CORNER_TR, 
    CORNER_BL, CORNER_BR, SEPARATOR, BULLET_POINT, 
    ARROW_RIGHT, APP_TITLE, APP_SUBTITLE, PEAR_ART, CHECKMARK
)

def draw_border(stdscr, start_y, start_x, height, width):
    """Draw a professional border box."""
    try:
        # Top border
        stdscr.addstr(start_y, start_x, CORNER_TL + BORDER_CHAR * (width - 2) + CORNER_TR)
        
        # Side borders
        for y in range(start_y + 1, start_y + height - 1):
            stdscr.addstr(y, start_x, VERTICAL_BORDER)
            stdscr.addstr(y, start_x + width - 1, VERTICAL_BORDER)
        
        # Bottom border
        stdscr.addstr(start_y + height - 1, start_x, CORNER_BL + BORDER_CHAR * (width - 2) + CORNER_BR)
    except curses.error:
        pass  # Ignore drawing errors at screen edges

def draw_header(stdscr, author="ppear"):
    """Draw a professional header with title and subtitle."""
    height, width = stdscr.getmaxyx()
    
    # Main title
    title_text = f"{APP_TITLE} by {PEAR_ART}{author}"
    subtitle_text = APP_SUBTITLE
    
    # Center the text
    title_x = max(0, (width - len(title_text)) // 2)
    subtitle_x = max(0, (width - len(subtitle_text)) // 2)
    
    try:
        # Title with emphasis
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(0, title_x, title_text)
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
        
        # Subtitle
        stdscr.attron(curses.color_pair(4))
        stdscr.addstr(1, subtitle_x, subtitle_text)
        stdscr.attroff(curses.color_pair(4))
        
        # Separator line
        separator_line = SEPARATOR * min(width - 4, 60)
        sep_x = max(0, (width - len(separator_line)) // 2)
        stdscr.addstr(2, sep_x, separator_line)
    except curses.error:
        pass

def draw_status_bar(stdscr, text, status_type="info"):
    """Draw a status bar at the bottom of the screen."""
    height, width = stdscr.getmaxyx()
    
    # Truncate text if too long
    if len(text) > width - 4:
        text = text[:width - 7] + "..."
    
    try:
        # Choose color based on status type
        if status_type == "error":
            color_pair = 5
        elif status_type == "success":
            color_pair = 6
        elif status_type == "warning":
            color_pair = 7
        else:
            color_pair = 2
        
        # Clear the status line
        stdscr.move(height - 1, 0)
        stdscr.clrtoeol()
        
        # Draw status bar background
        stdscr.attron(curses.color_pair(color_pair))
        status_line = f" {text}".ljust(width)
        stdscr.addstr(height - 1, 0, status_line[:width])
        stdscr.attroff(curses.color_pair(color_pair))
    except curses.error:
        pass

def render_menu(stdscr, title, options, selected_idx, start_y=4, pear_art="", show_help=True):
    """
    Enhanced menu rendering function with professional styling.
    
    Args:
        stdscr: Curses window object
        title: Menu title string
        options: List of menu options
        selected_idx: Currently selected option index
        start_y: Starting Y coordinate for the menu
        pear_art: Optional pear art to prepend to menu items
        show_help: Whether to show help text
    """
    clean_screen(stdscr)
    height, width = stdscr.getmaxyx()
    
    # Draw header
    draw_header(stdscr)
    
    # Draw menu title
    try:
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        title_x = 2
        stdscr.addstr(start_y, title_x, f"{ARROW_RIGHT} {title}")
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
    except curses.error:
        pass
    
    # Draw menu border
    menu_width = min(width - 4, 70)
    menu_height = len(options) + 4
    if start_y + menu_height + 2 < height:
        draw_border(stdscr, start_y + 1, 1, menu_height, menu_width)
    
    # Draw menu options
    for idx, opt in enumerate(options):
        y_pos = start_y + 3 + idx
        if y_pos >= height - 2:
            break
            
        try:
            if idx == selected_idx:
                # Highlighted selection
                stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                prefix = f" {ARROW_RIGHT} "
                stdscr.addstr(y_pos, 3, prefix)
                stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
                
                stdscr.attron(curses.color_pair(1))
                menu_text = f"{opt}".ljust(menu_width - 8)
                stdscr.addstr(y_pos, 3 + len(prefix), menu_text[:menu_width - 8])
                stdscr.attroff(curses.color_pair(1))
            else:
                # Normal menu item
                stdscr.attron(curses.color_pair(8))
                prefix = f" {BULLET_POINT} "
                stdscr.addstr(y_pos, 3, prefix)
                stdscr.addstr(y_pos, 3 + len(prefix), opt[:menu_width - 8])
                stdscr.attroff(curses.color_pair(8))
        except curses.error:
            pass
    
    # Show help text
    if show_help:
        help_text = "↑↓: Navigate  ENTER: Select  Q: Quit"
        draw_status_bar(stdscr, help_text, "info")

def render_file_list(stdscr, title, files, selected, current_idx, scroll_offset=0):
    """Render a professional file selection list."""
    clean_screen(stdscr)
    height, width = stdscr.getmaxyx()
    
    # Draw header
    draw_header(stdscr)
    
    # Draw title
    try:
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        stdscr.addstr(4, 2, f"{ARROW_RIGHT} {title}")
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
    except curses.error:
        pass
    
    # File list area
    list_start_y = 6
    max_lines = height - list_start_y - 3
    
    # Draw file list border
    list_width = width - 4
    if list_start_y + max_lines + 2 < height:
        draw_border(stdscr, list_start_y, 1, max_lines + 2, list_width)
    
    # Display files
    visible_files = files[scroll_offset:scroll_offset + max_lines]
    
    for vis_idx, (file_name, file_url) in enumerate(visible_files):
        idx = scroll_offset + vis_idx
        y_pos = list_start_y + 1 + vis_idx
        
        if y_pos >= height - 3:
            break
            
        try:
            # Selection checkbox
            if hasattr(selected, '__contains__'):  # set-like object
                is_selected = idx in selected
            else:  # single selection
                is_selected = idx == selected
                
            checkbox = f"[{CHECKMARK}]" if is_selected else "[ ]"
            
            # Current item highlight
            if idx == current_idx:
                stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
                prefix = f" {ARROW_RIGHT} {checkbox} "
                stdscr.addstr(y_pos, 3, prefix)
                stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)
                
                stdscr.attron(curses.color_pair(1))
                text = file_name[:list_width - 12]
                stdscr.addstr(y_pos, 3 + len(prefix), text)
                stdscr.attroff(curses.color_pair(1))
            else:
                # Normal item
                color = 6 if is_selected else 8
                stdscr.attron(curses.color_pair(color))
                prefix = f" {BULLET_POINT} {checkbox} "
                stdscr.addstr(y_pos, 3, prefix)
                text = file_name[:list_width - 12]
                stdscr.addstr(y_pos, 3 + len(prefix), text)
                stdscr.attroff(curses.color_pair(color))
        except curses.error:
            pass
    
    # Status bar with instructions
    help_text = "↑↓: Navigate  SPACE: Select  ENTER: Confirm  Q: Cancel"
    draw_status_bar(stdscr, help_text, "info")

def show_progress(stdscr, message, progress=None):
    """Show a progress message with optional progress bar."""
    clean_screen(stdscr)
    height, width = stdscr.getmaxyx()
    
    # Draw header
    draw_header(stdscr)
    
    # Center the progress message
    y_center = height // 2
    
    try:
        # Progress box
        box_width = min(width - 10, 60)
        box_height = 6
        box_x = (width - box_width) // 2
        box_y = y_center - 3
        
        draw_border(stdscr, box_y, box_x, box_height, box_width)
        
        # Message
        stdscr.attron(curses.color_pair(3) | curses.A_BOLD)
        msg_x = (width - len(message)) // 2
        stdscr.addstr(box_y + 2, msg_x, message)
        stdscr.attroff(curses.color_pair(3) | curses.A_BOLD)
        
        # Progress bar if provided
        if progress is not None:
            bar_width = box_width - 6
            filled_width = int(bar_width * min(progress, 1.0))
            
            stdscr.attron(curses.color_pair(6))
            bar_x = box_x + 3
            bar_y = box_y + 4
            
            # Filled portion
            stdscr.addstr(bar_y, bar_x, "█" * filled_width)
            
            # Empty portion
            stdscr.attroff(curses.color_pair(6))
            stdscr.attron(curses.color_pair(8))
            stdscr.addstr(bar_y, bar_x + filled_width, "░" * (bar_width - filled_width))
            stdscr.attroff(curses.color_pair(8))
            
            # Percentage
            percent_text = f"{int(progress * 100)}%"
            percent_x = (width - len(percent_text)) // 2
            stdscr.addstr(bar_y + 1, percent_x, percent_text)
    except curses.error:
        pass
    
    stdscr.refresh()

def handle_menu_input(key, selected_idx, num_options):
    """
    Handle standard menu navigation input.
    
    Args:
        key: Input key code
        selected_idx: Current selection index
        num_options: Total number of menu options
        
    Returns:
        new_idx: New selection index
        should_return: Whether to exit the menu
        should_select: Whether an option was selected
    """
    if key == curses.KEY_UP:
        return (selected_idx - 1) % num_options, False, False
    elif key == curses.KEY_DOWN:
        return (selected_idx + 1) % num_options, False, False
    elif key in [10, 13]:  # Enter
        return selected_idx, False, True
    elif key in [ord('b'), ord('B'), ord('q'), ord('Q')]:
        return selected_idx, True, False
    return selected_idx, False, False

def clean_screen(stdscr):
    """
    Thoroughly clean the screen by filling it with spaces.
    
    Args:
        stdscr: Curses window object
    """
    try:
        stdscr.clear()
        stdscr.refresh()
    except curses.error:
        pass
