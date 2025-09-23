#!/usr/bin/env python3
"""
This script fetches a webpage, parses its table to find new file links, 
and downloads them securely using requests. 
It uses BeautifulSoup for HTML parsing.

Make sure to:
- Adapt the URL and table/element selectors for your specific webpage.
- Run `pip install requests beautifulsoup4` before executing this script.
"""

import logging
import os
from datetime import datetime
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

from stig_scraper import scrape_stig_file_links

# URL of the page containing the table
URL = "https://public.cyber.mil/stigs/downloads/"  # Change this to your target URL
# Directory to save downloaded files
DOWNLOAD_DIR = "tmp"

# User-Agent header to mimic a browser request (some servers block default python-requests User-Agent)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; FileDownloaderBot/1.0; +https://example.com/bot)"
}

TARGET_ZIP_SUFFIXES = ("stig.zip", "srg.zip")


def _is_target_zip(value: str) -> bool:
    """Return True if *value* ends with a desired STIG/SRG zip filename."""

    if not value:
        return False
    return value.lower().endswith(TARGET_ZIP_SUFFIXES)


def _should_include(file_name: str, file_url: str) -> bool:
    """Determine if the discovered file should be included in the results."""

    return _is_target_zip(file_name) or _is_target_zip(file_url)

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
    """Parse the page and extract file links (only .zip files) with JS-rendered content."""
    soup = BeautifulSoup(html_content, "html.parser")
    file_links = []
    
    # Method 1: Look for data-link attributes (post-JS execution)
    for element in soup.find_all(attrs={"data-link": True}):
        data_link = element["data-link"]
        if data_link.lower().endswith(".zip"):
            file_name = os.path.basename(data_link)
            if _should_include(file_name, data_link):
                file_links.append((file_name, data_link))
                logging.info(f"Found file (data-link): {file_name} -> {data_link}")
    
    # Method 2: Look for download-related buttons/links with onclick handlers
    if not file_links:
        for element in soup.find_all(['button', 'a', 'div'], {'onclick': True}):
            onclick = element.get('onclick', '')
            if '.zip' in onclick.lower():
                import re
                url_match = re.search(r'https?://[^\s"\'>]+\.zip', onclick)
                if url_match:
                    url = url_match.group(0)
                    file_name = os.path.basename(url)
                    if _should_include(file_name, url):
                        file_links.append((file_name, url))
                        logging.info(f"Found file (onclick): {file_name} -> {url}")
    
    # Method 3: Look for any .zip URLs in rendered content (broader search)
    if not file_links:
        import re
        zip_urls = re.findall(r'https?://[^\s"\'<>]+\.zip', html_content)
        for url in zip_urls:
            file_name = os.path.basename(url)
            if _should_include(file_name, url):
                file_links.append((file_name, url))
                logging.info(f"Found file (regex): {file_name} -> {url}")
    
    # Method 4: Traditional href links (fallback)
    if not file_links:
        for link in soup.find_all("a", href=True):
            href = link["href"]
            if href.lower().endswith(".zip"):
                file_url = urljoin(URL, href)
                file_name = os.path.basename(href)
                if _should_include(file_name, file_url):
                    file_links.append((file_name, file_url))
                    logging.info(f"Found file (href): {file_name} -> {file_url}")
    
    # Filter to only STIG-related files if we found any
    if file_links:
        filtered_links = [
            (name, url)
            for name, url in file_links
            if _should_include(name, url)
        ]
        file_links = filtered_links
        if file_links:
            logging.info(
                "Filtered to %d STIG/SRG zip files", len(file_links)
            )
    
    if not file_links:
        msg = """Warning: No download links found after JavaScript rendering.

The cyber.mil site may have changed its structure or requires additional
interaction to load content. 

WORKAROUND: 
1. Visit https://public.cyber.mil/stigs/downloads/ manually
2. Download STIG .zip files to the 'tmp/' directory  
3. Use 'Create CKLB' menu to convert them"""
        print(msg)
        logging.warning("No download links found after JS rendering")
    else:
        logging.info(f"Found {len(file_links)} download links")
    
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
        try:
            file_links = scrape_stig_file_links()
            logging.info(
                "Captured %d download links via Playwright scraper",
                len(file_links),
            )
        except Exception as playwright_error:
            logging.warning(
                "Playwright scraper failed (%s); falling back to legacy HTML parser.",
                playwright_error,
            )
            html_content = fetch_page(URL)
            file_links = parse_table_for_links(html_content)

        file_links = [
            (file_name, file_url)
            for file_name, file_url in file_links
            if _should_include(file_name, file_url)
        ]
        logging.info(
            "Processing %d STIG/SRG download links after filtering",
            len(file_links),
        )

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
