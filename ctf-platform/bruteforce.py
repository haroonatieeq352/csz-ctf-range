#!/usr/bin/env python3
"""
CSZone CTF Range - Directory Brute Forcer
Usage: python bruteforce.py
       python bruteforce.py http://localhost:8000/ ../participant-tools/dir-wordlist.txt

Note: this scans from the site ROOT by default. That's intentional — H2
requires finding /backup/, which is not linked or disclosed anywhere in
the app, so the scan has to cover the whole site, not a subdirectory.
"""
import urllib.request
import sys
import time

TARGET   = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/"
WORDLIST = sys.argv[2] if len(sys.argv) > 2 else "../participant-tools/dir-wordlist.txt"

print(f"\n[*] CSZone Directory Brute-Forcer")
print(f"[*] Target   : {TARGET}")
print(f"[*] Wordlist : {WORDLIST}\n")

found = []

try:
    with open(WORDLIST, "r") as f:
        words = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    print(f"[!] Wordlist not found: {WORDLIST}")
    sys.exit(1)

for word in words:
    url = TARGET.rstrip("/") + "/" + word + "/"
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            code = resp.getcode()
            if code in (200, 301, 302, 403):
                print(f"  [{code}] FOUND --> {url}")
                found.append((code, url))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  [403] FOUND --> {url}  (forbidden - still exists!)")
            found.append((403, url))
    except Exception:
        pass

print(f"\n[+] Scan complete. {len(found)} path(s) found:")
for code, url in found:
    print(f"    [{code}] {url}")

if not found:
    print("    Nothing found. Try a bigger wordlist.")
print()
