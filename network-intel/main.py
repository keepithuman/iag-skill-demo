#!/usr/bin/env python3
"""
network-intel: DNS, ping, port scan, geolocation, and TLS check for any host or IP.
Inputs arrive as --argname CLI flags (IAG convention).
Always prints JSON to stdout and exits 0.
"""

import argparse
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    443: "HTTPS",
    445: "SMB",
    830: "NETCONF",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
    9200: "Elasticsearch",
    22222: "IAG",
}


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Hostname or IP address to inspect")
    parser.add_argument(
        "--checks",
        default="dns,ping,ports,geo,tls",
        help="Comma-separated checks to run: dns,ping,ports,geo,tls",
    )
    parser.add_argument("--timeout", default="5", help="Per-check timeout in seconds")
    return parser.parse_args()


def resolve_dns(target, timeout):
    result = {"forward": [], "reverse": None, "canonical": None, "errors": []}
    try:
        socket.setdefaulttimeout(timeout)
        infos = socket.getaddrinfo(target, None)
        ips = list({info[4][0] for info in infos})
        result["forward"] = sorted(ips)
        result["canonical"] = socket.getfqdn(target)
    except socket.gaierror as e:
        result["errors"].append(str(e))
        return result

    # Reverse lookup for the first resolved IP
    if result["forward"]:
        try:
            result["reverse"] = socket.gethostbyaddr(result["forward"][0])[0]
        except socket.herror:
            pass

    return result


def check_ping(ip, timeout):
    try:
        out = subprocess.run(
            ["ping", "-c", "3", "-W", str(int(timeout * 1000)), "-t", str(timeout), ip],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        if out.returncode == 0:
            # Extract avg RTT from "round-trip min/avg/max/stddev = X/X/X/X ms"
            rtt = None
            for line in out.stdout.splitlines():
                if "round-trip" in line or "rtt" in line:
                    parts = line.split("=")[-1].strip().split("/")
                    if len(parts) >= 2:
                        rtt = f"{parts[1]} ms"
            return {"reachable": True, "rtt_avg": rtt, "output": out.stdout.strip()}
        return {"reachable": False, "rtt_avg": None, "output": out.stderr.strip() or out.stdout.strip()}
    except subprocess.TimeoutExpired:
        return {"reachable": False, "rtt_avg": None, "output": "ping timed out"}
    except Exception as e:
        return {"reachable": False, "rtt_avg": None, "output": str(e)}


def scan_ports(ip, timeout):
    open_ports = []
    closed = 0
    for port, service in COMMON_PORTS.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "state": "open"})
            else:
                closed += 1
        except Exception:
            closed += 1
        finally:
            sock.close()
    return {"open": open_ports, "closed_or_filtered": closed, "scanned": len(COMMON_PORTS)}


def check_geo(ip, timeout):
    # Skip RFC1918 / loopback / link-local
    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return {"skipped": True, "reason": "private/loopback address — no geo data"}
    except ValueError:
        pass

    try:
        req = urllib.request.Request(
            f"https://ipinfo.io/{ip}/json",
            headers={"Accept": "application/json", "User-Agent": "network-intel/1.0"},
        )
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
        # Keep only relevant fields
        return {k: data.get(k) for k in ("ip", "city", "region", "country", "org", "timezone", "loc") if k in data}
    except Exception as e:
        return {"error": str(e)}


def check_tls(host, timeout):
    # Only meaningful for hostnames, not raw IPs (no SNI)
    try:
        ipaddress.ip_address(host)
        return {"skipped": True, "reason": "raw IP — no SNI hostname for TLS check"}
    except ValueError:
        pass

    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(
            socket.create_connection((host, 443), timeout=timeout),
            server_hostname=host,
            do_handshake_on_connect=True,
        ) as ssock:
            cert = ssock.getpeercert()
            return {
                "connected": True,
                "protocol": ssock.version(),
                "cipher": ssock.cipher()[0],
                "subject": dict(x[0] for x in cert.get("subject", [])),
                "issuer": dict(x[0] for x in cert.get("issuer", [])),
                "not_before": cert.get("notBefore"),
                "not_after": cert.get("notAfter"),
                "san": [v for _, v in cert.get("subjectAltName", [])],
            }
    except ssl.SSLCertVerificationError as e:
        return {"connected": False, "error": f"cert verification failed: {e}"}
    except ConnectionRefusedError:
        return {"connected": False, "error": "port 443 refused"}
    except socket.timeout:
        return {"connected": False, "error": "connection timed out"}
    except Exception as e:
        return {"connected": False, "error": str(e)}


def main():
    args = parse_args()
    target = args.target.strip()
    timeout = max(1, min(30, int(args.timeout)))
    checks = [c.strip().lower() for c in args.checks.split(",") if c.strip()]

    report = {
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "checks_requested": checks,
    }

    # Resolve target to IP first — everything else needs it
    if "dns" in checks or any(c in checks for c in ("ping", "ports", "geo")):
        dns = resolve_dns(target, timeout)
        if "dns" in checks:
            report["dns"] = dns
        primary_ip = dns["forward"][0] if dns["forward"] else None
    else:
        # Try to use target directly as IP
        try:
            ipaddress.ip_address(target)
            primary_ip = target
        except ValueError:
            primary_ip = None

    if "ping" in checks:
        if primary_ip:
            report["ping"] = check_ping(primary_ip, timeout)
        else:
            report["ping"] = {"error": "could not resolve target to IP"}

    if "ports" in checks:
        if primary_ip:
            report["ports"] = scan_ports(primary_ip, timeout)
        else:
            report["ports"] = {"error": "could not resolve target to IP"}

    if "geo" in checks:
        if primary_ip:
            report["geo"] = check_geo(primary_ip, timeout)
        else:
            report["geo"] = {"error": "could not resolve target to IP"}

    if "tls" in checks:
        report["tls"] = check_tls(target, timeout)

    # Summary
    open_count = len(report.get("ports", {}).get("open", []))
    reachable = report.get("ping", {}).get("reachable")
    report["summary"] = {
        "resolved": bool(primary_ip),
        "primary_ip": primary_ip,
        "reachable": reachable,
        "open_ports": open_count,
        "tls_ok": report.get("tls", {}).get("connected"),
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
