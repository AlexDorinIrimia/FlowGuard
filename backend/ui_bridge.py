# backend/ui_bridge.py
from collections import deque

# Holds packet count info to be consumed by the UI
traffic_log = deque(maxlen=12)

def get_recent_traffic(seconds=60):
    from datetime import datetime, timedelta

    now = datetime.utcnow()
    window = now - timedelta(seconds=seconds)

    return [
        {
            "timestamp": entry["timestamp"].isoformat(),
            "packet_count": entry["packet_count"]
        }
        for entry in traffic_log
        if entry["timestamp"] >= window
    ]
