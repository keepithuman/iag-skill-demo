#!/usr/bin/env python3
"""
subnet-calc: Full breakdown of any IPv4/IPv6 CIDR.
Inputs arrive as --argname CLI flags (IAG convention).
Always prints JSON to stdout and exits 0.
"""

import argparse
import ipaddress
import json
import sys


def ip_class(network):
    """Return the classical IP class for an IPv4 network (A/B/C/D/E or Private)."""
    addr = int(network.network_address)
    if network.version != 4:
        return "IPv6"
    if network.is_private:
        # Label private ranges by RFC
        ip_str = str(network.network_address)
        if ip_str.startswith("10."):
            return "Private (RFC1918 Class A)"
        if ip_str.startswith("172."):
            return "Private (RFC1918 Class B)"
        if ip_str.startswith("192.168."):
            return "Private (RFC1918 Class C)"
        return "Private"
    if addr >> 31 == 0b0:
        return "A (0.0.0.0/1)"
    if addr >> 30 == 0b10:
        return "B (128.0.0.0/2)"
    if addr >> 29 == 0b110:
        return "C (192.0.0.0/3)"
    if addr >> 28 == 0b1110:
        return "D — Multicast"
    return "E — Reserved"


def format_binary(addr):
    """Return dotted binary string for an IPv4 address."""
    octets = str(addr).split(".")
    return ".".join(f"{int(o):08b}" for o in octets)


def build_ipv4_report(network, split_prefix, include_hosts):
    hosts = list(network.hosts())
    num_hosts = len(hosts)

    report = {
        "input": str(network),
        "version": 4,
        "network_address": str(network.network_address),
        "broadcast_address": str(network.broadcast_address),
        "first_host": str(hosts[0]) if hosts else str(network.network_address),
        "last_host": str(hosts[-1]) if hosts else str(network.broadcast_address),
        "num_usable_hosts": num_hosts,
        "total_addresses": network.num_addresses,
        "prefix_length": network.prefixlen,
        "netmask": str(network.netmask),
        "netmask_hex": "0x" + "".join(f"{int(o):02x}" for o in str(network.netmask).split(".")),
        "wildcard_mask": str(network.hostmask),
        "ip_class": ip_class(network),
        "is_private": network.is_private,
        "is_loopback": network.is_loopback,
        "is_multicast": network.is_multicast,
        "binary": {
            "network_address": format_binary(network.network_address),
            "netmask": format_binary(network.netmask),
        },
        "supernet": str(network.supernet()),
    }

    if include_hosts and num_hosts <= 256:
        report["hosts"] = [str(h) for h in hosts]
    elif include_hosts:
        report["hosts_skipped"] = f"network too large ({num_hosts} hosts) — use /28 or smaller"

    if split_prefix:
        try:
            new_prefix = int(split_prefix)
            if new_prefix <= network.prefixlen:
                report["subnets"] = {"error": f"split_prefix /{new_prefix} must be larger than /{network.prefixlen}"}
            elif new_prefix > 32:
                report["subnets"] = {"error": "split_prefix must be ≤ 32 for IPv4"}
            else:
                subnets = list(network.subnets(new_prefix=new_prefix))
                subnet_hosts = list(subnets[0].hosts())
                report["subnets"] = {
                    "split_prefix": f"/{new_prefix}",
                    "count": len(subnets),
                    "hosts_per_subnet": len(subnet_hosts),
                    "list": [
                        {
                            "cidr": str(s),
                            "first_host": str(list(s.hosts())[0]) if list(s.hosts()) else str(s.network_address),
                            "last_host": str(list(s.hosts())[-1]) if list(s.hosts()) else str(s.broadcast_address),
                        }
                        for s in subnets[:64]  # cap at 64 to keep output readable
                    ],
                    "truncated": len(subnets) > 64,
                }
        except ValueError as e:
            report["subnets"] = {"error": str(e)}

    return report


def build_ipv6_report(network, split_prefix):
    report = {
        "input": str(network),
        "version": 6,
        "network_address": str(network.network_address),
        "first_host": str(network.network_address + 1),
        "last_host": str(network.broadcast_address - 1),
        "total_addresses": network.num_addresses,
        "prefix_length": network.prefixlen,
        "is_private": network.is_private,
        "is_loopback": network.is_loopback,
        "is_multicast": network.is_multicast,
        "is_link_local": network.is_link_local,
        "is_site_local": network.is_site_local,
        "supernet": str(network.supernet()),
    }

    if split_prefix:
        try:
            new_prefix = int(split_prefix)
            if new_prefix <= network.prefixlen:
                report["subnets"] = {"error": f"split_prefix /{new_prefix} must be larger than /{network.prefixlen}"}
            elif new_prefix > 128:
                report["subnets"] = {"error": "split_prefix must be ≤ 128 for IPv6"}
            else:
                subnets = list(network.subnets(new_prefix=new_prefix))
                report["subnets"] = {
                    "split_prefix": f"/{new_prefix}",
                    "count": len(subnets),
                    "list": [str(s) for s in subnets[:64]],
                    "truncated": len(subnets) > 64,
                }
        except ValueError as e:
            report["subnets"] = {"error": str(e)}

    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cidr", required=True, help="Network in CIDR notation")
    parser.add_argument("--split_prefix", default="", help="Split into subnets of this prefix length")
    parser.add_argument("--include_hosts", default="false", help="Include all host IPs (safe for /28 or smaller)")
    args = parser.parse_args()

    include_hosts = (args.include_hosts or "false").strip().lower() == "true"
    split_prefix = (args.split_prefix or "").strip() or None

    try:
        network = ipaddress.ip_network(args.cidr.strip(), strict=False)
    except ValueError as e:
        print(json.dumps({"success": False, "error": f"invalid CIDR: {e}"}))
        sys.exit(0)

    if network.version == 4:
        report = build_ipv4_report(network, split_prefix, include_hosts)
    else:
        report = build_ipv6_report(network, split_prefix)

    report["success"] = True
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
