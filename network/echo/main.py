#!/usr/bin/env python3
"""
echo: IAG5 equivalent of the IAG4 echo.sh service.
Takes a comma-separated argument_list and echoes them back with metadata.
"""

import argparse
import json
from datetime import datetime, timezone


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--argument_list", default="", help="Comma-separated list of arguments to echo")
    args = parser.parse_args()

    raw = args.argument_list.strip() if args.argument_list else ""
    arguments = [a.strip() for a in raw.split(",") if a.strip()] if raw else []

    result = {
        "success": True,
        "arguments": arguments,
        "count": len(arguments),
        "stdout": " ".join(arguments),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
