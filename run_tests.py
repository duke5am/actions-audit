#!/usr/bin/env python3
"""Convenience runner: equivalent to `python3 -m unittest discover -s tests -v`.

Usage:
    python3 run_tests.py            # verbose unittest run
    python3 run_tests.py -q         # quiet unittest run
"""

from __future__ import annotations

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main() -> int:
    verbosity = 1 if "-q" in sys.argv[1:] or "--quiet" in sys.argv[1:] else 2
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=os.path.join(HERE, "tests"),
                            pattern="test_*.py", top_level_dir=HERE)
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
