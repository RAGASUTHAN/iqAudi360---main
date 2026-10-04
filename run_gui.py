#!/usr/bin/env python3
"""iqAudi360 Web GUI Launcher.

Run this script to launch the local web dashboard:
    python run_gui.py
"""

import sys
from strix.gui.server import run_gui_server

if __name__ == "__main__":
    run_gui_server(sys.argv[1:])
