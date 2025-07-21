from flask import Flask, render_template, jsonify, request
import os
import glob
from datetime import datetime
import re
import sys
import logging
from backend.logging.logger import IDSLogger
from backend.ui_bridge import get_recent_traffic
from backend.integrated_detection import IntegratedDetectionSystem


current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(current_dir)
sys.path.insert(0, project_root)

from flask_socketio import SocketIO, emit

class AlertOnlyFilter(logging.Filter):
    def filter(self, record):
        return '[ALERT]' in record.getMessage()

app = Flask(__name__)
socketio = SocketIO(app, async_mode='threading')

# Configuration - adjust these paths to match your project structure
LOG_DIRECTORY = os.path.join(project_root,'logs')
LOG_FILE_PATTERN = '*.log'
os.makedirs(LOG_DIRECTORY, exist_ok=True)
print(LOG_DIRECTORY)
# Set up logging
logger = IDSLogger().get_logger()

ids = IntegratedDetectionSystem()

def parse_timestamp(timestamp_str):
    """Parse timestamp string into datetime object."""
    try:
        return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    except ValueError:
        try:
            return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
        except ValueError:
            return datetime.now()

def parse_log_line(line):
    """Parse a single log line into a structured format."""
    line = line.strip()
    if not line:
        return None

    try:
        # Pattern for IDS log format
        pattern = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \[WARNING\] \[ALERT\] Threat Detected: (\w+) \| Src: ([\d\.]+):(\d+) -> Dst: ([\d\.]+):(\d+) \| Protocol: (\d+) \| Packets: (\d+) \| Confidence: ([\d\.]+)'
        match = re.search(pattern, line)

        if match:
            timestamp, threat_type, source_ip, source_port, dest_ip, dest_port, protocol, packets, confidence = match.groups()
            return {
                'timestamp': timestamp,
                'source_ip': source_ip,
                'destination_ip': dest_ip,
                'source_port': source_port,
                'destination_port': dest_port,
                'threat_type': threat_type,
                'protocol': protocol,
                'packets': packets,
                'confidence': confidence,
                'raw_log': line
            }

        return None  # Only return parsed lines

    except Exception as e:
        logger.error(f"Error parsing log line: {line[:100]}... - {str(e)}")
        return None

def read_log_files():
    """Read all log files from the specified directory and parse them into structured entries."""
    logs = []

    if not os.path.exists(LOG_DIRECTORY):
        logger.error(f"Log directory '{LOG_DIRECTORY}' does not exist")
        return logs

    log_files = glob.glob(os.path.join(LOG_DIRECTORY, LOG_FILE_PATTERN))
    if not log_files:
        logger.warning(f"No log files found in '{LOG_DIRECTORY}' matching pattern '{LOG_FILE_PATTERN}'")
        return logs

    logger.info(f"Found {len(log_files)} log files: {[os.path.basename(f) for f in log_files]}")

    for file_path in sorted(log_files, key=os.path.getmtime, reverse=True):
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                logger.info(f"Reading file: {file_path}")
                file_logs = []
                total_lines = 0
                parsed_lines = 0

                for line_num, line in enumerate(file, 1):
                    total_lines += 1
                    parsed_log = parse_log_line(line)
                    if parsed_log:
                        parsed_lines += 1
                        parsed_log['file_source'] = os.path.basename(file_path)
                        parsed_log['line_number'] = line_num
                        file_logs.append(parsed_log)

                logs.extend(file_logs)
                logger.info(f"Parsed {parsed_lines}/{total_lines} entries from {file_path}")

        except Exception as e:
            logger.error(f"Error reading file {file_path}: {str(e)}")
            continue

    # Sort logs by timestamp (newest first)
    logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    logger.info(f"Total log entries: {len(logs)}")
    return logs

@app.route('/')
def dashboard():
    return render_template('index.html')

@app.route('/logs')
def logs_page():
    return render_template('Logs.html')

@app.route('/api/logs')
def get_logs():
    try:
        # Get pagination parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 100, type=int)  # Default 100 logs per page

        # Read logs from files
        all_logs = read_log_files()

        # Calculate pagination
        total_logs = len(all_logs)
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_logs = all_logs[start_idx:end_idx]

        return jsonify({
            'success': True,
            'data': paginated_logs,
            'pagination': {
                'current_page': page,
                'total_pages': (total_logs + limit - 1) // limit,
                'total_logs': total_logs,
                'logs_per_page': limit
            }
        })

    except Exception as e:
        logger.error(f"Error in get_logs: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/recent-alerts')
def get_recent_alerts():
    try:
        all_logs = read_log_files()
        recent_alerts = all_logs[:5]  # Get 5 most recent instead of 10

        return jsonify({
            'success': True,
            'data': recent_alerts,
            'total': len(recent_alerts)
        })

    except Exception as e:
        print(f"Error in get_recent_alerts: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/stats')
def get_stats():
    """Get current IDS statistics"""
    try:
        all_logs = read_log_files()
        
        # Calculate statistics
        total_alerts = len(all_logs)
        alerts_by_type = {}
        for log in all_logs:
            alert_type = log.get('threat_type', 'Unknown')
            alerts_by_type[alert_type] = alerts_by_type.get(alert_type, 0) + 1
        
        # Get recent activity (last hour)
        one_hour_ago = datetime.now().timestamp() - 3600
        recent_alerts = [log for log in all_logs if parse_timestamp(log['timestamp']).timestamp() > one_hour_ago]
        
        return jsonify({
            'success': True,
            'data': {
                'total_alerts': total_alerts,
                'alerts_by_type': alerts_by_type,
                'recent_alerts_count': len(recent_alerts),
                'last_update': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
        })
    except Exception as e:
        logger.error(f"Error getting stats: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
@app.route("/api/interfaces")
def list_ifaces():
    from backend.packet_capture.packet_sniffer import PacketSniffer
    return jsonify({"interfaces": PacketSniffer.list_friendly_interfaces()})

@socketio.on("select_interface")
def select_iface(data):
    iface = data.get("interface")
    ids.packet_sniffer.update_interface(iface)
    emit("interface_selected", {"success": True, "interface": iface})

@app.route("/api/traffic")
def traffic_api():
    return jsonify({
        "success": True,
        "data": get_recent_traffic()
    })
