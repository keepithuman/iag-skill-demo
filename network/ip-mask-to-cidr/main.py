#!/usr/bin/env python3
"""
ip-mask-to-cidr: IAG5 equivalent of the IAG4 ipMaskToCIDR.py service.
Takes an IP address and dotted-decimal netmask, returns CIDR notation and subnet details.
"""

import argparse
import ipaddress
import json
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ipAddress", required=True, help="IP address (e.g. 2.2.2.0)")
    parser.add_argument("--netmask", required=True, help="Dotted-decimal netmask (e.g. 255.255.255.0)")
    args = parser.parse_args()

    ip = args.ipAddress.strip()
    mask = args.netmask.strip()

    try:
        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
    except ValueError as e:
        print(json.dumps({"success": False, "error": str(e)}))
        sys.exit(0)

    hosts = list(network.hosts())
    result = {
        "success": True,
        "input": {
            "ipAddress": ip,
            "netmask": mask,
        },
        "cidr": str(network),
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "prefix_length": network.prefixlen,
        "first_host": str(hosts[0]) if hosts else str(network.network_address),
        "last_host": str(hosts[-1]) if hosts else str(network.broadcast_address),
        "num_usable_hosts": len(hosts),
        "wildcard_mask": str(network.hostmask),
        # The canonical CIDR string — matches what the old ipMaskToCIDR.py printed to stdout
        "stdout": str(network),
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
