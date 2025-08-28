from datetime import datetime
from backend.DataBase.DataBase import Database

class IDSLogger:
    def __init__(self, agent_id):
        self.db = Database().get_client()
        self.agent_id = agent_id

    def log(self, level: str, message: str, src_ip=None, dst_ip=None, confidence=None):
        # Inserare log în Supabase
        self.db.from_("alerts").insert({
            "agent_id": self.agent_id,
            "alert_type": level,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat(),
            "message": message
        }).execute()

    def fetch_logs(self, limit=100, offset=0):
        """
        Returnează lista de loguri pentru JS.
        Nu include 'id' și 'agent_id'.
        """
        try:
            result = (
                self.db.from_("alerts")
                .select("timestamp, source_ip, destination_ip, alert_type, confidence, message")
                .order("timestamp", desc=True)
                .range(offset, offset + limit - 1)
                .execute()
            )

            logs = result.data if result.data else []
            return logs

        except Exception as e:
            print("[fetch_logs] ERROR:", e)
            return []
