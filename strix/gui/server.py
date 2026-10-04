"""HTTP Server runner for iqAudi360 Web GUI."""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time
import webbrowser
from typing import Sequence

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from strix.gui.app import create_app


def find_available_port(start_port: int = 5050, max_attempts: int = 50) -> int:
    """Find the first available TCP port starting from start_port."""
    for port in range(start_port, start_port + max_attempts):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", port))
            if result != 0:
                return port
    return start_port


def run_gui_server(argv: Sequence[str] | None = None) -> None:
    """Entry point for `iqaudi360 gui` / `python run_gui.py`."""
    parser = argparse.ArgumentParser(
        prog="iqaudi360 gui",
        description="Launch the iqAudi360 Web GUI Dashboard",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5050,
        help="Port to bind (default: 5050, auto-increments if in use).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Do not automatically open the web browser on launch.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Run Flask in debug mode.",
    )

    args = parser.parse_args(argv)

    port = args.port
    if not args.debug:
        port = find_available_port(args.port)

    url = f"http://{args.host}:{port}"

    console = Console()
    banner = Text()
    banner.append("iqAudi360 Web GUI\n", style="bold cyan")
    banner.append("Multi-Agent Security Testing Platform\n\n", style="dim")
    banner.append("Dashboard URL: ", style="white")
    banner.append(f"{url}\n", style="bold green underline")
    banner.append("Host: ", style="dim")
    banner.append(f"{args.host}  ", style="white")
    banner.append("Port: ", style="dim")
    banner.append(f"{port}\n", style="white")
    banner.append("\nPress Ctrl+C to stop the server.", style="dim italic")

    console.print(
        Panel(
            banner,
            title="[bold cyan]iqAudi360 Web Platform[/]",
            border_style="cyan",
            padding=(1, 2),
        )
    )

    if not args.no_browser:
        def _open_browser() -> None:
            time.sleep(1.2)
            try:
                webbrowser.open(url)
            except Exception:
                pass

        threading.Thread(target=_open_browser, daemon=True).start()

    app = create_app()

    # Disable Flask banner clutter
    import logging
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.ERROR)

    try:
        app.run(
            host=args.host,
            port=port,
            debug=args.debug,
            threaded=True,
            use_reloader=False,
        )
    except (KeyboardInterrupt, SystemExit):
        console.print("\n[yellow]iqAudi360 Web GUI stopped.[/yellow]")


if __name__ == "__main__":
    run_gui_server(sys.argv[1:])
