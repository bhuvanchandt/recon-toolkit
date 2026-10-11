import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fingerprint import parse_ports  # noqa: E402


class TestParsePorts(unittest.TestCase):
    def test_single_ports(self):
        self.assertEqual(parse_ports("22,80,443"), [22, 80, 443])

    def test_range(self):
        self.assertEqual(parse_ports("1-5"), [1, 2, 3, 4, 5])

    def test_mixed(self):
        self.assertEqual(parse_ports("22,80-82,443"), [22, 80, 81, 82, 443])

    def test_whitespace_tolerated(self):
        self.assertEqual(parse_ports(" 22 , 80 , 443 "), [22, 80, 443])

    def test_empty_segments_ignored(self):
        self.assertEqual(parse_ports("22,,80,"), [22, 80])

    def test_deduplicates(self):
        self.assertEqual(parse_ports("22,22,80"), [22, 80])

    def test_out_of_range_dropped(self):
        self.assertEqual(parse_ports("0,22,65536,80"), [22, 80])

    def test_empty_string(self):
        self.assertEqual(parse_ports(""), [])


if __name__ == "__main__":
    unittest.main()
