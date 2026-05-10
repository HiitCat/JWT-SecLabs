#!/usr/bin/env python3
"""
JWT SecLabs - end-to-end test runner
Builds each lab's Docker image, runs the PoC, checks for a FLAG.

Usage:
    python test_all_labs.py              # all labs
    python test_all_labs.py 1 4 8        # specific labs by number
    python test_all_labs.py --no-build   # skip docker build (reuse existing images)
"""
import argparse, os, re, socket, subprocess, sys, time
from pwn import log

ROOT      = os.path.dirname(os.path.abspath(__file__))
PORT      = 3000
CONTAINER = "seclabs_runner"

LABS = [
    {"n": 1, "dir": "1-blind-trust",           "image": "lab1", "poc_args": []},
    {"n": 2, "dir": "2-voiding-the-rules",     "image": "lab2", "poc_args": []},
    {"n": 3, "dir": "3-secrets-under-the-rug", "image": "lab3", "poc_args": []},
    {"n": 4, "dir": "4-chameleon-hashes",      "image": "lab4", "poc_args": []},
    {"n": 5, "dir": "5-wrong-turn",            "image": "lab5", "poc_args": []},
    {"n": 6, "dir": "6-trojan-keys",           "image": "lab6", "poc_args": []},
    {"n": 7, "dir": "7-puppet-master",         "image": "lab7", "poc_args": ["--jwks-host", "host.docker.internal"]},
    {"n": 8, "dir": "8-shadow-key",            "image": "lab8", "poc_args": []},
]


def parse_args():
    p = argparse.ArgumentParser(description="JWT SecLabs - end-to-end test runner")
    p.add_argument("labs", nargs="*", type=int, metavar="N",
                   help="lab numbers to run (default: all)")
    p.add_argument("--no-build", action="store_true",
                   help="skip docker build and reuse existing images")
    return p.parse_args()


def sh(cmd, cwd=None, timeout=300):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def cleanup():
    subprocess.run(["docker", "rm", "-f", CONTAINER], capture_output=True)


def wait_for_port(timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            s = socket.create_connection(("localhost", PORT), timeout=1)
            s.close()
            return True
        except OSError:
            time.sleep(0.4)
    return False


def extract_flag(text):
    m = re.search(r"FLAG\{[^}]+\}", text)
    return m.group(0) if m else None


def run_lab(lab, build=True):
    name    = lab["dir"]
    image   = lab["image"]
    lab_dir = os.path.join(ROOT, name)

    log.info(f"Lab {lab['n']} - {name}")
    cleanup()

    if build:
        p = log.progress("building image")
        r = sh(["docker", "build", "-t", image, "."], cwd=lab_dir, timeout=300)
        if r.returncode != 0:
            p.failure("build failed")
            log.failure(r.stderr[-400:])
            return "BUILD FAILED", None
        p.success("done")

    p = log.progress("starting container")
    r = sh(["docker", "run", "-d", "--name", CONTAINER, "-p", f"{PORT}:{PORT}", image])
    if r.returncode != 0:
        p.failure("could not start")
        log.failure(r.stderr)
        return "START FAILED", None
    p.success("up")

    p = log.progress(f"waiting for :{PORT}")
    if not wait_for_port():
        p.failure("timeout")
        cleanup()
        return "SERVER TIMEOUT", None
    p.success("ready")

    p = log.progress("running poc")
    try:
        r = sh(["python", "poc.py"] + lab["poc_args"], cwd=lab_dir, timeout=120)
        output = r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        p.failure("poc timed out")
        cleanup()
        return "POC TIMEOUT", None

    flag = extract_flag(output)
    if flag:
        p.success(flag)
    else:
        p.failure("no flag found")
        for line in output.strip().splitlines()[-8:]:
            log.warning(line)

    cleanup()
    return ("PASS" if flag else "FAIL"), flag


def main():
    args   = parse_args()
    subset = args.labs or [lab["n"] for lab in LABS]
    to_run = [lab for lab in LABS if lab["n"] in subset]

    if not to_run:
        log.failure("no matching labs")
        sys.exit(1)

    log.info(f"running {len(to_run)} lab(s): {', '.join(str(l['n']) for l in to_run)}")
    if args.no_build:
        log.warning("--no-build: reusing existing Docker images")

    results = []
    for lab in to_run:
        status, flag = run_lab(lab, build=not args.no_build)
        results.append((lab["n"], lab["dir"], status, flag))

    passed = sum(1 for *_, s, _ in results if s == "PASS")
    total  = len(results)

    print()
    log.info("=" * 52)
    log.info("RESULTS")
    log.info("=" * 52)
    for n, name, status, flag in results:
        suffix = f"  {flag}" if flag else ""
        if status == "PASS":
            log.success(f"Lab {n}  {name:<35}{suffix}")
        else:
            log.failure(f"Lab {n}  {name:<35}  [{status}]")

    print()
    if passed == total:
        log.success(f"{passed}/{total} passed")
    else:
        log.failure(f"{passed}/{total} passed")

    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
