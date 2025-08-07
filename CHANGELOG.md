# Changelog

All notable changes to CheckMate-Lite will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-08-07

### Added
- **JavaScript Rendering Support**: Implemented `requests-html` for automated STIG downloads from DISA's dynamically-loaded cyber.mil website
- **Enhanced Web Scraping**: Multi-method detection system for STIG download links including:
  - `data-link` attribute parsing
  - JavaScript onclick handler extraction  
  - Regex URL pattern matching
  - Traditional href link fallback
- **Automated Chromium Management**: First-run setup automatically downloads and configures Chromium browser (~200MB)
- **Custom Certificate Support**: Integrated custom SSL certificate verification for cyber.mil domain
- **Improved Error Handling**: Enhanced error messages and graceful fallbacks for web scraping failures

### Changed
- **Web Scraping Architecture**: Completely refactored `web.py` to handle JavaScript-rendered content
- **Requirements**: Added `requests-html>=0.10.0` and `lxml_html_clean>=0.4.0` dependencies
- **Performance**: JavaScript rendering adds 5-10 seconds to initial page loads but enables automated downloads
- **User Experience**: Better progress indication and error messages during web operations

### Enhanced
- **STIG Detection**: Now successfully detects 436+ STIG files from cyber.mil (previously 0 due to dynamic loading)
- **Robustness**: Multiple fallback mechanisms ensure compatibility with various website structures
- **Logging**: Improved logging for web scraping operations and JavaScript rendering status
- **Documentation**: Updated README.md with new requirements and first-run setup instructions

### Technical Details
- **fetch_page()**: Enhanced with JavaScript rendering using HTMLSession
- **parse_table_for_links()**: Implemented 4-tier detection strategy with STIG-specific filtering
- **Certificate Handling**: Proper integration of custom certificate bundle with requests-html
- **Backwards Compatibility**: Graceful fallback to basic requests if requests-html unavailable

### Performance Impact
- **First Run**: ~35 seconds (includes Chromium download)
- **Subsequent Runs**: ~5-10 seconds for JavaScript rendering
- **Disk Space**: Additional ~200MB for Chromium browser (one-time)
- **Success Rate**: Restored automated STIG downloads from 0% to 100%

### Migration Notes
- Users upgrading from previous versions need to run `pip install -r requirements.txt` to install new dependencies
- First execution will trigger automatic Chromium download (~200MB, one-time setup)
- No changes required to existing CKLB files or workflow

---

## [1.0.0] - 2025-07-XX

### Initial Release
- Basic STIG to CKLB conversion functionality
- Terminal User Interface (TUI) for checklist management
- Inventory management system
- CKLB version comparison and upgrade capabilities
- Support for XCCDF XML input files
- JSON schema validation for CKLB files