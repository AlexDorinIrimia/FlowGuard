# ui_server.py
import supabase
from flask import Flask, render_template, jsonify, request, redirect, url_for
from flask_socketio import SocketIO
from datetime import datetime
import logging
from dateutil.parser import isoparse
import platform
import psutil

from backend.DataBase.DBAgent import AgentManager
from backend.logging.logger import IDSLogger
from backend.ui_bridge import get_recent_traffic
from backend.integrated_detection import IntegratedDetectionSystem

# --- Flask setup ---
app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

# --- Logging setup ---
class AlertOnlyFilter(logging.Filter):
    def filter(self, record):
        return '[ALERT]' in record.getMessage()

# --- Agent & Logger ---
agent_mgr = AgentManager()
agent = agent_mgr.register_agent()
logger = IDSLogger(agent)

ids = IntegratedDetectionSystem()

# --- Helper functions ---
def parse_timestamp(timestamp_str):
    try:
        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        try:
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            return datetime.utcnow()

def get_interfaces():
    ifaces = []
    system = platform.system()
    addrs = psutil.net_if_addrs()
    if system == "Windows":
        for name, addr_list in addrs.items():
            if any(addr.family == psutil.AF_LINK for addr in addr_list):
                ifaces.append(name)
    else:
        for name in addrs:
            if name != "lo":
                ifaces.append(name)
    return ifaces

selected_interface = {"name": None}

@app.route("/select_interface", methods=["GET", "POST"])
def select_interface():
    interfaces = get_interfaces()
    if request.method == "POST":
        iface = request.form.get("iface")
        if iface:
            selected_interface["name"] = iface
            return redirect(url_for("dashboard"))
    return render_template("select_interface.html", interfaces=interfaces)

@app.route("/")
def dashboard():
    if selected_interface["name"] is None:
        return redirect(url_for("select_interface"))
    return render_template("index.html")

@app.route("/logs")
def logs_page():
    return render_template("Logs.html")

# --- API endpoints ---
@app.route("/api/logs")
def api_logs():
    try:
        page = int(request.args.get("page", 1))
        limit = int(request.args.get("limit", 100))
        offset = (page - 1) * limit

        # Fetch logs din IDSLogger pentru pagina curentă
        logs = logger.fetch_logs(limit=limit, offset=offset)

        # Total alerts pentru pagination (fără limită 1000)
        total_result = logger.db.from_("alerts").select("id", count="exact").execute()
        total_alerts = total_result.count or 0

        total_pages = (total_alerts + limit - 1) // limit

        return jsonify({
            "success": True,
            "data": logs,
            "pagination": {
                "current_page": page,
                "total_pages": total_pages,
                "total_alerts": total_alerts
            }
        })

    except Exception as e:
        print("ERROR /api/logs:", e)
        return jsonify({"success": False, "error": str(e)}), 500



@app.route("/api/recent_alerts")
def recent_alerts():
    try:
        # Ia ultimele 5 alerte pentru acest agent
        logs = logger.fetch_logs(limit=5, offset=0)
        # Elimină câmpurile nedorite
        for log in logs:
            log.pop("id", None)
            log.pop("agent_id", None)

        return jsonify({"success": True, "data": logs})
    except Exception as e:
        print("ERROR /api/recent_alerts:", e)
        return jsonify({"success": False, "error": str(e)}), 500


from datetime import datetime, timezone

@app.route("/api/stats")
def get_stats():
    try:
        logs = logger.fetch_logs(limit=500)
        total_alerts = len(logs)
        alerts_by_type = {}
        one_hour_ago_ts = datetime.utcnow().timestamp() - 3600
        recent_alerts_count = 0

        for log in logs:
            alert_type = log.get("alert_type", "Unknown")
            alerts_by_type[alert_type] = alerts_by_type.get(alert_type, 0) + 1
            ts = log.get("timestamp")
            if ts:
                ts_obj = isoparse(ts)
                if ts_obj.timestamp() > one_hour_ago_ts:
                    recent_alerts_count += 1

        return jsonify({
            "success": True,
            "data": {
                "total_alerts": total_alerts,
                "alerts_by_type": alerts_by_type,
                "recent_alerts_count": recent_alerts_count,
                "last_update": datetime.now(timezone.utc).isoformat()  # ISO 8601 cu UTC
            }
        })
    except Exception as e:
        print("ERROR", f"Error in get_stats: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/traffic")
def traffic_api():
    return jsonify({"success": True, "data": get_recent_traffic()})

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

