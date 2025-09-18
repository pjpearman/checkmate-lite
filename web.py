#!/usr/bin/env python3
"""
This script fetches a webpage, parses its table to find new file links, 
and downloads them securely using requests. 
It uses BeautifulSoup for HTML parsing.

Make sure to:
- Adapt the URL and table/element selectors for your specific webpage.
- Run `pip install requests beautifulsoup4` before executing this script.
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import os
import logging
import json
from datetime import datetime

# URL of the page containing the table
URL = "https://www.cyber.mil/stigs/downloads"  # Change this to your target URL
# Directory to save downloaded files
DOWNLOAD_DIR = "tmp"

# User-Agent header to mimic a browser request (some servers block default python-requests User-Agent)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FileDownloaderBot/1.0; +https://example.com/bot)"
}

# Set up logging
LOG_DIR = os.path.join(os.path.dirname(__file__), "logs")
LOG_FILE = os.path.join(LOG_DIR, "downloader.logs")
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, mode=0o700)
logging.basicConfig(
    filename=LOG_FILE,
    filemode="a",
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

def fetch_page(url):
    """Fetch the webpage content with JavaScript rendering support."""
    cert_path = "./certs/www-cyber-mil-full-chain.crt"
    
    try:
        from requests_html import HTMLSession
        
        # Create session with custom certificate verification
        session = HTMLSession()
        session.verify = cert_path
        
        # Get page and render JavaScript
        response = session.get(url, headers=HEADERS, timeout=30)
        response.raise_for_status()
        
        # Execute JavaScript to load dynamic content
        logging.info(f"Rendering JavaScript for: {url}")
        response.html.render(timeout=30, wait=5, sleep=2)
        
        logging.info(f"Fetched and rendered page: {url}")
        return response.html.html
        
    except ImportError:
        # Fallback to regular requests if requests-html not available
        logging.warning("requests-html not installed, falling back to basic requests")
        response = requests.get(url, headers=HEADERS, timeout=10, verify=cert_path)
        response.raise_for_status()
        logging.info(f"Fetched page (no JS): {url}")
        return response.text
    except Exception as e:
        logging.error(f"Failed to fetch page {url}: {e}")
        raise

def parse_table_for_links(html_content):
    """Parse the downloads table and return STIG checklist download links."""

    def _is_stig_checklist(value):
        return bool(value) and value.strip().lower() == "stig checklist"

    soup = BeautifulSoup(html_content, "html.parser")
    file_links = []
    seen_links = set()
    release_metadata = {}

    for table in soup.select("table.views-table"):
        for row in table.find_all("tr"):
            # Skip header rows that don't contain table data
            if not row.find_all("td"):
                continue

            doc_type_cell = row.find(class_="views-field-field-document-type")
            doc_type_text = doc_type_cell.get_text(strip=True) if doc_type_cell else ""

            download_element = row.find(attrs={"data-download-link": True})
            if not download_element:
                continue

            button_file_type = download_element.get("data-file-type", "")
            if not (_is_stig_checklist(button_file_type) or _is_stig_checklist(doc_type_text)):
                continue

            download_path = (download_element.get("data-download-link") or "").strip()
            if not download_path:
                continue

            file_name = (download_element.get("data-file-name") or "").strip()
            if not file_name:
                file_name = os.path.basename(download_path.rstrip("/"))
            if not file_name:
                continue

            download_url = urljoin(URL, download_path)
            link_info = (file_name, download_url)

            if link_info in seen_links:
                continue

            seen_links.add(link_info)
            file_links.append(link_info)

            release = download_element.get("data-release") or download_element.get("data-version")
            if release:
                release_metadata[link_info] = release

    if file_links:
        logging.info(f"Found {len(file_links)} STIG checklist download links")
        if release_metadata:
            logging.debug("Captured release metadata for %d checklists", len(release_metadata))
    else:
        msg = """Warning: No download links found after JavaScript rendering.

The cyber.mil site may have changed its structure or requires additional
interaction to load content.

WORKAROUND: 
1. Visit https://www.cyber.mil/stigs/downloads manually
2. Download STIG .zip files to the 'tmp/' directory  
3. Use 'Create CKLB' menu to convert them"""
        print(msg)
        logging.warning("No download links found after JS rendering")

    return file_links

def download_file(file_url, file_name):
    """Download the file and save it to DOWNLOAD_DIR."""
    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR, mode=0o700)  # Restrict permissions for security
        logging.info(f"Created download directory: {DOWNLOAD_DIR}")

    # Prevent overwriting existing files
    dest_path = os.path.join(DOWNLOAD_DIR, file_name)
    if os.path.exists(dest_path):
        msg = f"File already exists: {file_name}"
        print(msg)
        logging.info(msg)
        return

    try:
        with requests.get(file_url, headers=HEADERS, stream=True, timeout=10, verify="./certs/www-cyber-mil-full-chain.crt") as response:
            response.raise_for_status()
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
        msg = f"Downloaded: {file_name}"
        print(msg)
        logging.info(msg)
    except Exception as e:
        msg = f"Failed to download {file_name} from {file_url}: {e}"
        print(msg)
        logging.error(msg)

def main():
    logging.info("Downloader script started.")
    try:
        html_content = fetch_page(URL)
        file_links = parse_table_for_links(html_content)
        
        for file_name, file_url in file_links:
            # TODO: Add logic to determine if this file is "new" (e.g., by timestamp or tracking a database)
            # For now, download every file found:
            download_file(file_url, file_name)
        
        logging.info("Downloader script finished.")
    except Exception as e:
        logging.error(f"Script terminated with error: {e}")
        raise

if __name__ == "__main__":
    main()
