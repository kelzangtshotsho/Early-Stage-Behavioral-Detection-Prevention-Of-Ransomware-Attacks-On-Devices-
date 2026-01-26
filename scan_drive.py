#!/usr/bin/env python3
import os
import time
import math
import json
import shutil
import argparse
from pathlib import Path

# === Configurable paths ===
LOG_FILE = os.path.expanduser("~/filewatch_dashboard/logs/watcher_logs.json")
QUARANTINE_DIR = os.path.expanduser("~/filewatch_dashboard/quarantine")

# === Defaults ===
SAMPLE_SIZE = 4096
DEFAULT_ENTROPY_THRESHOLD = 7.0
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/run", "/tmp", "/var/lib"}  # skip noisy virtual dirs


def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    entropy = 0.0
    length = len(data)
    for c in counts:
        if c == 0:
            continue
        p = c / length
        entropy -= p * math.log2(p)
    return entropy


def approximate_entropy(path: str) -> float:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            if size <= SAMPLE_SIZE * 3:
                return shannon_entropy_bytes(f.read())
            start = f.read(SAMPLE_SIZE)
            midpos = max(SAMPLE_SIZE, size // 2 - SAMPLE_SIZE // 2)
            f.seek(midpos)
            middle = f.read(SAMPLE_SIZE)
            f.seek(max(0, size - SAMPLE_SIZE))
            end = f.read(SAMPLE_SIZE)
            return shannon_entropy_bytes(start + middle + end)
    except Exception:
        return 0.0


def log_event(entry: dict):
    try:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, "a") as lf:
            lf.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[ERROR] Logging failed: {e}")


def quarantine_file(path: str) -> str:
    try:
        os.makedirs(QUARANTINE_DIR, exist_ok=True)
        base = os.path.basename(path)
        dest = os.path.join(QUARANTINE_DIR, base + ".quarantine")
        if os.path.exists(dest):
            dest = os.path.join(QUARANTINE_DIR, f"{base}.{int(time.time())}.quarantine")
        shutil.move(path, dest)
        return dest
    except Exception as e:
        print(f"[WARN] Quarantine failed: {e}")
        return ""


def scan(start_dir: str, entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD, quarantine: bool = False):
    suspicious = []
    safe = []
    total = 0

    for root, dirs, files in os.walk(start_dir):
        dirs[:] = [d for d in dirs if os.path.join(root, d) not in EXCLUDE_DIRS]

        for fname in files:
            full = os.path.join(root, fname)
            if any(full.startswith(ex) for ex in EXCLUDE_DIRS):
                continue
            if not os.path.isfile(full):
                continue
            try:
                size = os.path.getsize(full)
                if size == 0:
                    continue
            except Exception:
                continue

            entropy = approximate_entropy(full)
            status = "SAFE FILE"
            action = "-"
            if entropy >= entropy_threshold:
                status = "SUSPICIOUS FILE"
                if quarantine:
                    q = quarantine_file(full)
                    action = f"Quarantined to {q}" if q else "Quarantine failed"
                suspicious.append((full, entropy))
            else:
                safe.append((full, entropy))

            log = {
                "event": "SCAN",
                "file": os.path.abspath(full),
                "entropy": round(entropy, 2),
                "status": status,
                "timestamp": int(time.time()),
                "action": action
            }
            log_event(log)
            total += 1

    # Print summary
    print("\n=== Scan Summary ===")
    print(f"Scanned: {total} files")
    print(f"Safe: {len(safe)} | Suspicious: {len(suspicious)}\n")

    if safe:
        print("Safe files:")
        for f, e in safe[:5]:
            print(f"  {f} (Entropy: {e:.2f})")
        if len(safe) > 5:
            print(f"  ... {len(safe)-5} more")

    if suspicious:
        print("\nSuspicious files:")
        for f, e in suspicious:
            print(f"  {f} (Entropy: {e:.2f})")

    print("\nResults also saved in:", LOG_FILE)


def parse_args():
    p = argparse.ArgumentParser(description="Scan a folder/drive and classify files by entropy.")
    p.add_argument("-p", "--path", required=True, help="Folder to scan")
    p.add_argument("-t", "--threshold", type=float, default=DEFAULT_ENTROPY_THRESHOLD, help="Entropy threshold (default 7.0)")
    p.add_argument("-q", "--quarantine", action="store_true", help="Quarantine suspicious files")
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    scan(args.path, entropy_threshold=args.threshold, quarantine=args.quarantine)
