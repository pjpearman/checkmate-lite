from pathlib import Path
from urllib.parse import urljoin

import sys


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from web import URL, parse_table_for_links


def load_fixture(name: str) -> str:
    fixture_path = Path(__file__).parent / "fixtures" / name
    return fixture_path.read_text(encoding="utf-8")


def test_parse_table_for_links_extracts_stig_checklists():
    html_content = load_fixture("cyber_mil_downloads.html")

    results = parse_table_for_links(html_content)

    expected = [
        ("Example_Product_1.ckl", urljoin(URL, "/stig/downloads/example_product_1.ckl")),
        ("Example_Product_3.ckl", "https://dl.dod.cyber.mil/downloads/example_product_3.ckl"),
        ("example_product_4.ckl", urljoin(URL, "/stig/downloads/example_product_4.ckl")),
        ("example_product_5.ckl", urljoin(URL, "/stig/downloads/example_product_5.ckl")),
    ]

    assert results == expected
    assert len(results) == len({(name, url) for name, url in results})
