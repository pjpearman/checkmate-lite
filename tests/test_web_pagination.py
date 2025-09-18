import unittest
from pathlib import Path
from unittest.mock import patch

from web import collect_all_file_links


class CollectAllFileLinksTests(unittest.TestCase):
    def load_fixture(self, name: str) -> str:
        fixture_path = Path(__file__).parent / "fixtures" / name
        return fixture_path.read_text(encoding="utf-8")

    def test_collect_all_file_links_follows_rel_next(self):
        pages = {
            "https://example.com/downloads?page=1": self.load_fixture("pagination_page1.html"),
            "https://example.com/downloads?page=2": self.load_fixture("pagination_page2.html"),
            "https://example.com/downloads?page=3": self.load_fixture("pagination_page3_empty.html"),
        }

        with patch("web.fetch_page", side_effect=lambda url: pages[url]):
            results = collect_all_file_links("https://example.com/downloads?page=1")

        self.assertEqual(
            results,
            [
                ("file1.zip", "https://example.com/files/file1.zip"),
                ("file2.zip", "https://example.com/files/file2.zip"),
                ("file3.zip", "https://example.com/files/file3.zip"),
            ],
        )

    def test_collect_all_file_links_increments_page_query_when_no_nav(self):
        pages = {
            "https://example.com/downloads?page=5": self.load_fixture("pagination_no_nav_page1.html"),
            "https://example.com/downloads?page=6": self.load_fixture("pagination_no_nav_page2.html"),
            "https://example.com/downloads?page=7": self.load_fixture("pagination_empty.html"),
        }

        with patch("web.fetch_page", side_effect=lambda url: pages[url]):
            results = collect_all_file_links("https://example.com/downloads?page=5")

        self.assertEqual(
            results,
            [
                ("file10.zip", "https://example.com/files/file10.zip"),
                ("file20.zip", "https://example.com/files/file20.zip"),
                ("file30.zip", "https://example.com/files/file30.zip"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
