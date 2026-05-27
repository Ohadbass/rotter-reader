#!/usr/bin/env python3
"""Check specific local devices for default HTTP credentials."""

import sys
from typing import Optional

try:
    import requests
    import urllib3
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("The 'requests' library is required. Install it with:")
    print("  pip3 install requests")
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGETS = [
    {"ip": "192.168.10.7", "label": "Arris device"},
    {"ip": "192.168.10.13", "label": "unknown IoT device (hostname lwip0)"},
]

PORTS = [80, 8080, 443]
TIMEOUT = 3

FAILURE_WORDS = ("incorrect", "invalid", "failed", "error", "unauthorized", "wrong")

CREDENTIALS = [
    ("admin", ""),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("root", "root"),
    ("root", ""),
    ("user", "user"),
    ("technician", "technician"),
    ("", ""),
]

FORM_FIELD_PAIRS = [
    ("username", "password"),
    ("user", "pass"),
]


def base_url(ip: str, port: int) -> str:
    scheme = "https" if port == 443 else "http"
    if port in (80, 443):
        return f"{scheme}://{ip}/"
    return f"{scheme}://{ip}:{port}/"


def format_creds(username: str, password: str) -> str:
    user_display = username if username else "(empty)"
    pass_display = password if password else "(empty)"
    return f"{user_display}/{pass_display}"


def looks_like_success(response: requests.Response) -> bool:
    if response.status_code != 200:
        return False
    body = response.text.lower()
    return not any(word in body for word in FAILURE_WORDS)


def is_port_reachable(url: str) -> bool:
    try:
        requests.get(url, timeout=TIMEOUT, verify=False, allow_redirects=True)
        return True
    except requests.RequestException:
        return False


def try_basic_auth(url: str, username: str, password: str) -> Optional[requests.Response]:
    try:
        return requests.get(
            url,
            auth=HTTPBasicAuth(username, password),
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


def try_form_post(url: str, fields: dict[str, str]) -> Optional[requests.Response]:
    try:
        return requests.post(
            url,
            data=fields,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True,
        )
    except requests.RequestException:
        return None


def check_port(ip: str, port: int) -> tuple[list[str], str]:
    url = base_url(ip, port)

    if not is_port_reachable(url):
        return [], "unreachable"

    successes: list[str] = []
    seen: set[tuple[str, str]] = set()

    for username, password in CREDENTIALS:
        cred_label = format_creds(username, password)

        response = try_basic_auth(url, username, password)
        if response and looks_like_success(response):
            key = (cred_label, "basic")
            if key not in seen:
                seen.add(key)
                successes.append(
                    f"SUCCESS: {ip}:{port} — logged in with {cred_label}"
                )

        for field_user, field_pass in FORM_FIELD_PAIRS:
            response = try_form_post(
                url,
                {field_user: username, field_pass: password},
            )
            if response and looks_like_success(response):
                key = (cred_label, f"form:{field_user}/{field_pass}")
                if key not in seen:
                    seen.add(key)
                    successes.append(
                        f"SUCCESS: {ip}:{port} — logged in with {cred_label}"
                    )

    if successes:
        return successes, "success"
    return [], "failed"


def main() -> int:
    all_successes: list[str] = []

    for target in TARGETS:
        ip = target["ip"]
        print(f"\nChecking {ip} ({target['label']})...")

        for port in PORTS:
            successes, status = check_port(ip, port)

            if status == "unreachable":
                print(f"UNREACHABLE: {ip}:{port}")
            elif status == "failed":
                print(f"FAILED: {ip}:{port} — no default credentials worked")
            else:
                for line in successes:
                    print(line)
                all_successes.extend(successes)

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    if all_successes:
        print(f"Successful logins found: {len(all_successes)}")
        for line in all_successes:
            print(f"  {line}")
    else:
        print("No successful logins found.")
    print("=" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())
