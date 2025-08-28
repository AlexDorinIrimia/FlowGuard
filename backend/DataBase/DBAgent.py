from backend.DataBase.DataBase import Database
import socket
import uuid

class AgentManager:
    def __init__(self):
        self.db = Database().get_client()

    def register_agent(self):
        hostname = socket.gethostname()
        try:
            # IP local (LAN)
            ip_address = socket.gethostbyname(hostname)
        except Exception:
            ip_address = "unknown"

        existing = ( self.db.table("agents")
                     .select("id")
                     .eq("hostname", hostname)
                     .eq("ip_address", ip_address)
                     .execute() )
        if existing.data:
        # Agent deja există -> update last_seen și returnează id-ul
            agent_id = existing.data[0]["id"]
            self.db.table("agents").update({ "last_seen": "NOW()" }).eq("id", agent_id).execute()
            return agent_id
        else: # Creează agent nou
            agent_id = str(uuid.uuid4())
            self.db.table("agents").insert(
                { "id": agent_id,
                  "hostname": hostname,
                  "ip_address": ip_address,
                  "last_seen": "NOW()" }).execute()
            return agent_id