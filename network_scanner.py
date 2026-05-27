#!/usr/bin/env python3
"""Personal network security audit: discover hosts and check default credentials."""

import ipaddress
import platform
import re
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET


def run_command(cmd: list[str]) -> str:
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        print(f"Error running {' '.join(cmd)}:", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        raise


def get_default_gateway() -> str:
    system = platform.system()
    if system == "Darwin":
        output = run_command(["route", "-n", "get", "default"])
        for line in output.splitlines():
            if "gateway:" in line:
                return line.split("gateway:", 1)[1].strip()
    elif system == "Linux":
        output = run_command(["ip", "route", "show", "default"])
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
        if match:
            return match.group(1)
    raise RuntimeError(f"Could not determine default gateway on {system}")


def get_local_ipv4(gateway: str) -> str:
    """Use a UDP socket to determine the primary local IPv4 address."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((gateway, 1))
        return sock.getsockname()[0]
    finally:
        sock.close()


def get_network_cidr(local_ip: str) -> str:
    return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))


def parse_host_discovery_xml(xml_text: str) -> list[dict]:
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(f"Failed to parse nmap host discovery output: {exc}") from exc

    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ip = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
                break
        if not ip:
            continue

        hostname = None
        hostnames_el = host.find("hostnames")
        if hostnames_el is not None:
            hn = hostnames_el.find("hostname")
            if hn is not None:
                hostname = hn.get("name")

        hosts.append({"ip": ip, "hostname": hostname})

    return hosts


CREDENTIAL_SCAN_SCRIPTS = (
    "http-default-accounts,ftp-anon,snmp-brute,telnet-brute"
)
CREDENTIAL_SCRIPT_IDS = frozenset(
    script.strip() for script in CREDENTIAL_SCAN_SCRIPTS.split(",")
)


def classify_default_creds(script_outputs: list[str]) -> str:
    if not script_outputs:
        return "UNKNOWN"

    combined_lower = "\n".join(script_outputs).lower()

    failure_keywords = (
        "failed",
        "couldn't",
        "could not",
        "no valid",
        "not allowed",
        "denied",
        "authentication failed",
        "incorrect",
        "unable to",
        "not vulnerable",
    )
    if any(keyword in combined_lower for keyword in failure_keywords):
        return "NO"

    positive_keywords = ("valid", "login", "anonymous", "success")
    if any(keyword in combined_lower for keyword in positive_keywords):
        return "YES"

    return "NO"


def parse_service_scan_xml(xml_text: str) -> dict:
    root = ET.fromstring(xml_text)
    host = root.find("host")
    open_ports: list[str] = []
    script_outputs: list[str] = []

    if host is None:
        return {
            "open_ports": open_ports,
            "default_creds": "UNKNOWN",
            "script_outputs": script_outputs,
        }

    for port in host.findall(".//port"):
        state_el = port.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue

        port_id = port.get("portid", "?")
        proto = port.get("protocol", "tcp")
        service_el = port.find("service")

        if service_el is not None:
            name = service_el.get("name", "unknown")
            product = service_el.get("product") or ""
            version = service_el.get("version") or ""
            extra = service_el.get("extrainfo") or ""
            detail = " ".join(part for part in [product, version] if part).strip()
            if extra:
                detail = f"{detail} ({extra})".strip() if detail else extra
            service_desc = f"{name} {detail}".strip() if detail else name
        else:
            service_desc = "unknown"

        open_ports.append(f"{port_id}/{proto} — {service_desc}")

        for script in port.findall("script"):
            script_id = script.get("id")
            if script_id not in CREDENTIAL_SCRIPT_IDS:
                continue
            output = (script.get("output") or "").strip()
            if output:
                script_outputs.append(f"[{script_id}] {output}")

    for script in host.findall(".//script"):
        script_id = script.get("id")
        if script_id not in CREDENTIAL_SCRIPT_IDS:
            continue
        output = (script.get("output") or "").strip()
        labeled = f"[{script_id}] {output}"
        if output and labeled not in script_outputs:
            script_outputs.append(labeled)

    default_creds = classify_default_creds(script_outputs)

    return {
        "open_ports": open_ports,
        "default_creds": default_creds,
        "script_outputs": script_outputs,
    }


def discover_hosts(network_cidr: str) -> list[dict]:
    print(f"\n[Step 2] Discovering live hosts on {network_cidr} ...")
    xml_out = run_command(["nmap", "-sn", network_cidr, "-oX", "-"])
    hosts = parse_host_discovery_xml(xml_out)
    print(f"  Found {len(hosts)} live host(s).")
    return hosts


def scan_host(ip: str) -> dict:
    xml_out = run_command(
        ["nmap", "-sV", "--script", CREDENTIAL_SCAN_SCRIPTS, ip, "-oX", "-"]
    )
    return parse_service_scan_xml(xml_out)


def print_report(host_results: list[dict]) -> None:
    print("\n" + "=" * 72)
    print("NETWORK SECURITY AUDIT REPORT")
    print("=" * 72)

    creds_count = 0
    for index, entry in enumerate(host_results, 1):
        scan = entry["scan"]
        creds = scan["default_creds"]
        if creds == "YES":
            creds_count += 1

        print(f"\n--- Device {index} ---")
        print(f"  IP:       {entry['ip']}")
        print(f"  Hostname: {entry.get('hostname') or 'N/A'}")
        if scan["open_ports"]:
            print("  Open ports & services:")
            for port in scan["open_ports"]:
                print(f"    - {port}")
        else:
            print("  Open ports & services: none detected")
        print(f"  Default credentials: {creds}")
        for note in scan["script_outputs"]:
            for line in note.splitlines():
                if line.strip():
                    print(f"    > {line.strip()}")

    print("\n" + "=" * 72)
    print(
        f"Total devices found: {len(host_results)} — "
        f"Devices with potential default credentials: {creds_count}"
    )
    print("=" * 72 + "\n")


def main() -> int:
    print("Network Default-Password Scanner")
    print("-" * 40)

    print("\n[Step 1] Detecting local network range ...")
    try:
        gateway = get_default_gateway()
        local_ip = get_local_ipv4(gateway)
        network_cidr = get_network_cidr(local_ip)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"  Gateway:     {gateway}")
    print(f"  Local IP:    {local_ip}")
    print(f"  Scan target: {network_cidr}")

    try:
        hosts = discover_hosts(network_cidr)
    except Exception as exc:
        print(f"Error during host discovery: {exc}", file=sys.stderr)
        return 1

    if not hosts:
        print("\nNo live hosts found on the subnet.")
        print(
            "\nTotal devices found: 0 — Devices with potential default credentials: 0"
        )
        return 0

    print(
        f"\n[Step 3] Scanning {len(hosts)} host(s) for services and default credentials ..."
    )
    host_results = []
    for index, host in enumerate(hosts, 1):
        ip = host["ip"]
        print(f"  [{index}/{len(hosts)}] Scanning {ip} ...")
        try:
            scan = scan_host(ip)
        except subprocess.CalledProcessError:
            scan = {
                "open_ports": [],
                "default_creds": "UNKNOWN",
                "script_outputs": [],
            }
        host_results.append({**host, "scan": scan})

    print("\n[Step 4] Report")
    print_report(host_results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
