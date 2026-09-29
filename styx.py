#!/usr/bin/env python3
"""Styx — run from a checkout without installing.

    python styx.py check proxies.txt --geo --speed
"""

from styx.cli import main

if __name__ == "__main__":
    main()
