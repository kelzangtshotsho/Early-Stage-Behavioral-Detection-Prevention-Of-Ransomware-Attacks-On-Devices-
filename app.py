from flask import Flask, jsonify, send_from_directory
from flask_cors import CORS
import os, json, socket, time

app = Flask(__name__)
CORS(app)

# === Paths ===
LOG_FILE = os.path.expanduser("~/filewatch_dashboard/logs/watcher_logs.json")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# === Favicon Route ===
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(STATIC_DIR, 'favicon.ico', mimetype='image/vnd.microsoft.icon')

# === Logs Route ===
@app.route("/logs")
def get_logs():
    logs = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    log = json.loads(line)

                    # Ensure all required fields exist
                    full_log = {
                        "event": log.get("event", "-"),
                        "file": log.get("file", log.get("path", "-")),
                        "entropy": log.get("entropy") if isinstance(log.get("entropy"), (int, float)) else None,
                        "status": log.get("status", "-"),
                        "timestamp": log.get("timestamp", int(time.time())),
                        "action": log.get("action", "-"),
                        "message": log.get("message", "-")
                    }
                    logs.append(full_log)
                except json.JSONDecodeError:
                    continue
    return jsonify(logs)

# === Helper: Get LAN IP ===
def get_lan_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "127.0.0.1"

# === Run Flask App ===
if __name__ == "__main__":
    host = "0.0.0.0"
    port = 5000
    lan_ip = get_lan_ip()

    print(f"\n🚀 Backend running! Access logs at:")
    print(f"   ➜ http://127.0.0.1:{port}/logs")
    print(f"   ➜ http://{lan_ip}:{port}/logs\n")

    app.run(host=host, port=port, debug=True)
