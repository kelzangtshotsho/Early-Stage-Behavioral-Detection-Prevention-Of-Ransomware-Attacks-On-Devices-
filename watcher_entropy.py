import os
import math
import time
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------------------------
# Configuration
# -------------------------
WATCH_DIR = os.path.expanduser("~/testwatch")   # folder to monitor
LOG_FILE = os.path.expanduser("~/watcher_logs.json")  # log file
ENTROPY_THRESHOLD = 7.5

# -------------------------
# Helper functions
# -------------------------
def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string"""
    if not data:
        return 0
    entropy = 0
    length = len(data)
    for x in set(data):
        p_x = data.count(x) / length
        entropy -= p_x * math.log2(p_x)
    return entropy

def calculate_entropy(file_path: str) -> float:
    """Check average entropy of file in chunks"""
    try:
        total_entropy = 0
        total_bytes = 0
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                chunk_entropy = shannon_entropy(chunk)
                total_entropy += chunk_entropy * len(chunk)
                total_bytes += len(chunk)
        if total_bytes == 0:
            return 0.0
        return round(total_entropy / total_bytes, 2)
    except Exception:
        return -1  # could not read file

def log_event(event_type, path, entropy=None):
    """Print event and log to JSON file"""
    timestamp = time.time()

    if entropy is not None:
        if entropy > ENTROPY_THRESHOLD:
            alert = "SUSPICIOUS FILE"
            print(f"\033[91m[!] {event_type}: {path} (entropy={entropy:.2f}) → {alert}\033[0m")
        else:
            alert = "SAFE FILE"
            print(f"\033[92m[OK] {event_type}: {path} (entropy={entropy:.2f}) → {alert}\033[0m")
    else:
        alert = "INFO"
        print(f"[{event_type}] {path}")

    # Append to log file
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        json.dump({
            "timestamp": timestamp,
            "event": event_type,
            "path": path,
            "entropy": entropy,
            "status": alert
        }, f)
        f.write("\n")

# -------------------------
# Event Handler
# -------------------------
class MyHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            entropy = calculate_entropy(event.src_path)
            log_event("CREATE", event.src_path, entropy)

    def on_modified(self, event):
        if not event.is_directory:
            entropy = calculate_entropy(event.src_path)
            log_event("MODIFY", event.src_path, entropy)

    def on_deleted(self, event):
        if not event.is_directory:
            log_event("DELETE", event.src_path)

# -------------------------
# Main Watcher Setup
# -------------------------
if __name__ == "__main__":
    if not os.path.exists(WATCH_DIR):
        os.makedirs(WATCH_DIR)
        print(f"Created watch directory: {WATCH_DIR}")

    event_handler = MyHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_DIR, recursive=True)
    observer.start()

    print(f"👀 Watching {WATCH_DIR} for file changes...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

